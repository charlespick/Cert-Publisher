"""Operator entrypoint: elect a leader, run the controller, shut down cleanly.

The process is long-lived now, so the entrypoint's job is different from the
CronJob's. It no longer decides success or failure for a batch of publications
-- that lives on each publication's ``.status`` -- and instead owns three
things a controller has to get right:

* **Leader election.** Every replica starts and campaigns; only the one holding
  the lease reconciles, because publishing a certificate writes to a host and
  must not happen twice.
* **Shutdown.** SIGTERM stops the queue and lets an in-flight publish finish,
  renewing the lease the whole time so no standby can start on the same host
  meanwhile; then it releases the lease so a standby takes over immediately.
  If a publish is still running when the timeout runs out, the lease is kept
  and the process exits at once, so the write dies well before the lease
  can expire.
* **Exit codes that mean something to a Deployment.** A lost lease exits
  non-zero, immediately and without draining: once a standby may take over,
  a worker still writing to a host would be racing it. A shutdown that timed
  out with a reconcile still writing to a host also exits non-zero, so the
  interruption is on the pod's termination state, not only in its logs.
"""

from __future__ import annotations

import logging
import os
import signal
import socket
import sys
import threading
import uuid
from dataclasses import dataclass

from .controller import Controller, ControllerConfig
from .health import HealthServer
from .kube import Kube
from .leader import LeaderElector, LeadershipLost

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


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class OperatorConfig:
    controller: ControllerConfig
    health_port: int
    leader_election: bool
    lease_name: str
    lease_namespace: str
    lease_duration: float
    renew_deadline: float
    retry_period: float

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
            leader_election=_env_bool("LEADER_ELECTION", True),
            lease_name=os.environ.get("LEADER_ELECTION_ID", "cert-publisher"),
            lease_namespace=(
                os.environ.get("LEADER_ELECTION_NAMESPACE")
                or os.environ.get("POD_NAMESPACE")
                or _service_account_namespace()
                or "default"
            ),
            lease_duration=_env_float("LEADER_LEASE_DURATION", 15.0),
            renew_deadline=_env_float("LEADER_RENEW_DEADLINE", 10.0),
            retry_period=_env_float("LEADER_RETRY_PERIOD", 2.0),
        )


def _service_account_namespace() -> str | None:
    """The namespace this pod runs in, from its service-account token mount."""
    path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    try:
        with open(path) as handle:
            return handle.read().strip() or None
    except OSError:
        return None


def _identity() -> str:
    """A lease holder identity unique to this process, not just this host.

    A restarted pod that reused its name would otherwise look to itself like
    the still-valid holder of a lease its predecessor took to the grave.
    """
    return f"{os.environ.get('POD_NAME') or socket.gethostname()}_{uuid.uuid4()}"


def _hard_exit(code: int) -> None:
    """End the process now, taking every worker thread down with it.

    ``sys.exit`` would unwind this thread and then wait out interpreter
    shutdown -- atexit hooks, the client's connection pools -- while a worker
    thread is still writing to a host. When the lease is gone, or about to
    be, those writes have to stop before a standby's can start, so the logs
    are flushed and the process ends without ceremony.
    """
    logging.shutdown()
    os._exit(code)


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
    health.start()

    stop_event = threading.Event()

    def _handle_signal(signum, _frame) -> None:
        log.info("received %s; shutting down", signal.Signals(signum).name)
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    def _start_leading() -> None:
        controller.start()
        health.set_leading(True)

    # Whether every reconcile finished before shutdown. One that did not is
    # cut off when the process exits, so the exit code says so.
    clean = [True]

    def _stop_leading() -> bool:
        # Stop first, then stand down: until the last worker is done this pod
        # is still the one reconciling, and /leader is what an operator reads
        # to find out which pod that is.
        drained = controller.stop()
        health.set_leading(False)
        clean[0] = clean[0] and drained
        return drained

    def _lost_leading(exc: LeadershipLost) -> None:
        # No drain: a standby may take over within leaseDuration of our last
        # renewal, and a worker still writing to a host then would be racing
        # it. Killing the write is the lesser harm; the next leader redoes it.
        # Exiting non-zero also sends this pod back to being a standby in a
        # fresh process rather than one that might still be half-reconciling.
        log.error("%s; exiting now without waiting for in-flight reconciles", exc)
        _hard_exit(1)

    # Ready means "reached the apiserver and campaigning", not "leading" --
    # see health.py for why a readiness gate only the leader can pass
    # deadlocks a rollout. It waits for the first Lease read, though, so a pod
    # with broken credentials or RBAC does not pass readiness and let a
    # rolling update replace a working pod with it.
    try:
        if not config.leader_election:
            health.set_ready(True)
            log.warning(
                "leader election is disabled; run exactly one replica, or two "
                "will publish to the same hosts at the same time"
            )
            _start_leading()
            stop_event.wait()
            _stop_leading()
            return _shutdown_code(clean[0])

        elector = LeaderElector(
            kube.coordination,
            name=config.lease_name,
            namespace=config.lease_namespace,
            identity=_identity(),
            lease_duration=config.lease_duration,
            renew_deadline=config.renew_deadline,
            retry_period=config.retry_period,
            labels={"app.kubernetes.io/name": "cert-publisher"},
        )
        elector.run(
            on_started_leading=_start_leading,
            on_stopped_leading=_stop_leading,
            stop_event=stop_event,
            on_reachable=lambda: health.set_ready(True),
            on_lost_leading=_lost_leading,
        )
        if not clean[0]:
            # The drain gave up on a worker and the lease was kept, not
            # released. It stops being renewed now, so the worker has to die
            # before the lease can expire -- not whenever interpreter shutdown
            # gets round to it.
            health.stop()
            _hard_exit(_shutdown_code(False))
        return 0
    except LeadershipLost as exc:
        # Only reached if _lost_leading returned, which it does not outside
        # tests; kept so a lost lease can never look like a clean exit.
        log.error("%s", exc)
        return 1
    finally:
        health.stop()
        logging.shutdown()


if __name__ == "__main__":
    sys.exit(main())
