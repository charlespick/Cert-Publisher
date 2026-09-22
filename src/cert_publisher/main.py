"""Operator entrypoint: run the controller, shut down cleanly.

The process is long-lived now, so the entrypoint's job is different from the
CronJob's. It no longer decides success or failure for a batch of publications
-- that lives on each publication's ``.status`` -- and instead owns two things
a controller has to get right:

* **Shutdown.** SIGTERM stops the queue and lets an in-flight publish finish,
  up to ``SHUTDOWN_TIMEOUT``. There is only ever one of these processes -- the
  chart runs a single-replica StatefulSet, which does not start a replacement
  until this pod is gone -- so nothing else can start on the same host while
  it drains.
* **Exit codes that mean something.** A shutdown that timed out with a
  reconcile still writing to a host exits non-zero, so the interruption is on
  the pod's termination state, not only in its logs.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from dataclasses import dataclass

from .controller import Controller, ControllerConfig
from .health import HealthServer
from .kube import Kube

log = logging.getLogger("cert-publisher")


def _setup_logging() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


@dataclass(frozen=True)
class OperatorConfig:
    controller: ControllerConfig
    health_port: int

    @classmethod
    def from_env(cls) -> OperatorConfig:
        controller = ControllerConfig(
            # Empty/unset WATCH_NAMESPACE reconciles across the whole cluster.
            namespace=os.environ.get("WATCH_NAMESPACE") or None,
            workers=max(1, _env_int("WORKER_COUNT", 4)),
            resync_seconds=_env_float("RESYNC_INTERVAL", 1800.0),
            resync_jitter=_env_float("RESYNC_JITTER", 0.2),
            backoff_base_seconds=_env_float("BACKOFF_BASE", 5.0),
            backoff_max_seconds=_env_float("BACKOFF_MAX", 900.0),
            watch_timeout_seconds=_env_int("WATCH_TIMEOUT", 300),
            startup_spread_seconds=_env_float("STARTUP_SPREAD", 60.0),
            shutdown_timeout_seconds=_env_float("SHUTDOWN_TIMEOUT", 30.0),
            reconcile_timeout_seconds=_env_float("RECONCILE_TIMEOUT", 900.0),
        )
        return cls(
            controller=controller,
            health_port=_env_int("HEALTH_PORT", 8080),
        )


def _shutdown_code(drained: bool) -> int:
    """Exit status for a shutdown we asked for: non-zero if it cut a write off.

    The pod is going away either way, so nothing restarts on this; it is there
    so the interruption shows in the pod's last termination state rather than
    only in its logs.
    """
    if drained:
        return 0
    log.error("exiting with a reconcile interrupted mid-write")
    return 1


def main() -> int:
    _setup_logging()
    config = OperatorConfig.from_env()

    kube = Kube()
    controller = Controller(kube, config.controller)

    health = HealthServer(config.health_port)
    health.add_liveness_check(controller.healthy)
    health.add_readiness_check(controller.ready)
    health.start()

    stop_event = threading.Event()

    def _handle_signal(signum, _frame) -> None:
        log.info("received %s; shutting down", signal.Signals(signum).name)
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    try:
        controller.start()
        stop_event.wait()
        return _shutdown_code(controller.stop())
    finally:
        health.stop()
        logging.shutdown()


if __name__ == "__main__":
    sys.exit(main())
