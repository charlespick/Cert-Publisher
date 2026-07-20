"""Retry transient network failures with exponential backoff and logging.

Provisioners talk to external hosts over the network, where brief timeouts and
refused/unreachable conditions are routine and usually clear on their own. This
helper wraps a single connection-establishment step so a transient blip is
retried instead of failing the whole reconcile, and turns an exhausted retry
into a clear, host-qualified error rather than a bare ``timed out`` traceback.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Callable, TypeVar

log = logging.getLogger("cert-publisher.retry")

T = TypeVar("T")

# Connection-level failures worth retrying. ``OSError`` covers socket timeouts
# (``TimeoutError``), refused/unreachable hosts, DNS resolution errors, TLS
# handshake failures (``ssl.SSLError``), and paramiko's
# ``NoValidConnectionsError`` -- but not authentication failures or host-key /
# thumbprint mismatches, which are plain ``Exception`` subclasses and will never
# fix themselves on retry.
DEFAULT_RETRYABLE: tuple[type[BaseException], ...] = (OSError,)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


def with_retries(
    func: Callable[[], T],
    *,
    description: str,
    attempts: int | None = None,
    base_delay: float | None = None,
    retryable: tuple[type[BaseException], ...] = DEFAULT_RETRYABLE,
) -> T:
    """Call ``func`` up to ``attempts`` times, backing off between tries.

    ``description`` names the operation (e.g. ``"WinRM endpoint check for
    host:5986"``) and is used both in log messages and in the error raised when
    every attempt fails. Only exceptions in ``retryable`` trigger a retry;
    anything else propagates immediately so genuine, non-transient failures are
    not masked. Attempt count and backoff default to ``RETRY_ATTEMPTS`` (3) and
    ``RETRY_BASE_DELAY`` (2.0s), overridable via the environment.

    On exhaustion a ``ConnectionError`` is raised whose message names the
    operation and attempt count and chains the underlying error, so callers --
    and the CertPublication status -- get a clear reason instead of a raw socket
    traceback.
    """
    if attempts is None:
        attempts = _int_env("RETRY_ATTEMPTS", 3)
    if base_delay is None:
        base_delay = _float_env("RETRY_BASE_DELAY", 2.0)
    attempts = max(1, attempts)

    last_exc: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            if attempt > 1:
                log.info("%s: retry %d/%d", description, attempt, attempts)
            return func()
        except retryable as exc:
            last_exc = exc
            if attempt < attempts:
                delay = base_delay * (2 ** (attempt - 1))
                log.warning(
                    "%s failed (attempt %d/%d): %s; retrying in %.1fs",
                    description, attempt, attempts, exc, delay,
                )
                time.sleep(delay)
            else:
                log.error(
                    "%s failed after %d attempt(s): %s",
                    description, attempts, exc,
                )

    raise ConnectionError(
        f"{description} failed after {attempts} attempt(s): {last_exc}"
    ) from last_exc
