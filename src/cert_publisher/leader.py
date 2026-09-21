"""Lease-based leader election, so only one replica reconciles at a time.

Publishing a certificate is not an idempotent read: it writes files on a Linux
box, imports a PFX on a Windows one, and reboots an iDRAC. Two replicas racing
the same CertPublication would do that twice, and on the host-keyed path they
would each rotate the host's private key out from under the other's pending
CertificateRequest. So the operator runs active/passive: every replica starts,
but only the one holding the lease runs the controller.

The lock is a ``coordination.k8s.io/v1`` Lease -- the same mechanism kubelet
and the Kubernetes control plane use -- rather than the annotated ConfigMap
the Python client's bundled helper still writes, and the acquire/renew rules
follow client-go's:

* a candidate only steals a lease after it has watched it go ``leaseDuration``
  without being renewed, timed against *its own* clock so a skewed peer or
  apiserver cannot make an expired lease look fresh;
* the holder gives up leadership if it cannot renew within ``renewDeadline``,
  which is shorter than ``leaseDuration``, so it stops reconciling before its
  successor is allowed to start;
* a clean shutdown releases the lease instead of letting it expire, so a
  rolling update hands over in about a second rather than a full lease.
"""

from __future__ import annotations

import datetime
import logging
import threading
import time
from collections.abc import Callable

from kubernetes.client.rest import ApiException

log = logging.getLogger("cert-publisher.leader")

_API_VERSION = "coordination.k8s.io/v1"


class LeadershipLost(RuntimeError):
    """Raised when the lease could not be renewed within the renew deadline."""


class _OutOfTime(Exception):
    """An attempt ran out of renew deadline before its next Lease call."""


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _micro_time(when: datetime.datetime | None) -> str | None:
    """Format a datetime the way the apiserver parses ``MicroTime``.

    Kubernetes parses these fields with Go's ``RFC3339Micro`` layout, which
    demands exactly six fractional digits. ``datetime.isoformat()`` -- what the
    Python client emits for a ``datetime`` attribute -- drops the fraction
    entirely when it happens to be zero, which the apiserver then rejects. One
    renewal in a million failing is one too many for a lease, so the timestamps
    go on the wire as strings we format ourselves.
    """
    if when is None:
        return None
    return when.astimezone(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


class LeaderElector:
    """Acquire and hold a Lease, running a callback for as long as it is held."""

    def __init__(
        self,
        api,
        *,
        name: str,
        namespace: str,
        identity: str,
        lease_duration: float = 15.0,
        renew_deadline: float = 10.0,
        retry_period: float = 2.0,
        labels: dict[str, str] | None = None,
        release_on_stop: bool = True,
    ) -> None:
        if not lease_duration > renew_deadline:
            raise ValueError("leaseDuration must be greater than renewDeadline")
        if not renew_deadline > retry_period:
            raise ValueError("renewDeadline must be greater than retryPeriod")
        self._api = api
        self._name = name
        self._namespace = namespace
        self._identity = identity
        self._lease_duration = lease_duration
        self._renew_deadline = renew_deadline
        self._retry_period = retry_period
        self._labels = labels or {}
        self._release_on_stop = release_on_stop
        # Every Lease call is bounded by the renew deadline. _hold only checks
        # that deadline between attempts, so a call that blocks forever -- a
        # partitioned apiserver, a black-holed connection -- would otherwise
        # keep this replica believing it leads while a standby takes over.
        # While holding, each call is further cut to whatever is left of the
        # deadline, so a read and a write that each block for a full timeout
        # cannot add up to twice it.
        self._request_timeout = renew_deadline
        # When the last successful acquire-or-renew *started*, on our own
        # monotonic clock. The apiserver may have stamped renewTime at any
        # point after that, so the renew deadline is counted from here.
        self._renewed_at = time.monotonic()

        # The lease record as we last saw it, and when we saw it -- on our own
        # monotonic clock. Expiry is judged from that observation, never from
        # the timestamp in the record, which was written by another process.
        self._observed_record: tuple[str | None, datetime.datetime | None] | None = None
        self._observed_at = time.monotonic()
        self._on_reachable: Callable[[], None] | None = None

    # -- public API --------------------------------------------------------

    def run(
        self,
        *,
        on_started_leading: Callable[[], None],
        on_stopped_leading: Callable[[], bool | None],
        stop_event: threading.Event,
        on_reachable: Callable[[], None] | None = None,
    ) -> None:
        """Campaign for the lease, then hold it until stopped or lost.

        Returns normally when ``stop_event`` is set (a graceful shutdown, at
        any point in the campaign). Raises :class:`LeadershipLost` if the lease
        was held and could not be renewed -- the caller should exit non-zero so
        the pod is restarted rather than linger as a leader that is not one.

        ``on_stopped_leading`` returns False if it could not stop everything it
        started -- a publish still mid-conversation with a host. The lease is
        then left to expire rather than released, because handing it to a
        standby while this process is still writing to a host is the one thing
        leader election exists to prevent.

        ``on_reachable`` is called once, the first time the Lease is read (or
        found missing): the earliest point at which this replica has shown it
        can reach the apiserver with working credentials and RBAC, and so can
        take over if it wins.
        """
        self._on_reachable = on_reachable
        log.info(
            "campaigning for lease %s/%s as %s",
            self._namespace, self._name, self._identity,
        )
        if not self._campaign(stop_event):
            log.info("stopped before acquiring the lease")
            return

        log.info("acquired lease %s/%s; now the active replica",
                 self._namespace, self._name)
        on_started_leading()
        try:
            self._hold(stop_event)
        finally:
            drained = on_stopped_leading()
            if drained is False:
                log.warning(
                    "not releasing lease %s/%s: a reconcile was still in "
                    "flight, so the lease is left to expire in about %.0fs "
                    "rather than handing over while a host is being written to",
                    self._namespace, self._name, self._lease_duration,
                )
            elif self._release_on_stop:
                self.release()

    # -- campaign / renewal ------------------------------------------------

    def _campaign(self, stop_event: threading.Event) -> bool:
        """Poll until the lease is ours, or ``stop_event`` is set."""
        while not stop_event.is_set():
            if self.try_acquire_or_renew():
                return True
            stop_event.wait(self._retry_period)
        return False

    def _hold(self, stop_event: threading.Event) -> None:
        """Renew the lease until it is given up or lost.

        The deadline runs from the start of the last renewal that succeeded,
        not from the start of this round of retries, and it bounds every call
        made inside it. A standby starts counting ``leaseDuration`` from the
        last record it saw, so this replica has to know it has lost the lease
        within ``renewDeadline`` of that record -- not ``renewDeadline`` after
        it next got round to trying.
        """
        while not stop_event.is_set():
            deadline = self._renewed_at + self._renew_deadline
            while not self.try_acquire_or_renew(deadline=deadline):
                if stop_event.is_set():
                    return
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise LeadershipLost(
                        f"failed to renew lease {self._namespace}/{self._name} "
                        f"within {self._renew_deadline}s"
                    )
                stop_event.wait(min(self._retry_period, remaining))
            if stop_event.wait(self._retry_period):
                return

    def try_acquire_or_renew(self, *, deadline: float | None = None) -> bool:
        """One acquire-or-renew attempt. Never raises; returns whether we hold it.

        ``deadline`` (on the monotonic clock) bounds the whole attempt, read
        and write together; an attempt with no time left fails without calling
        the apiserver at all.
        """
        started = time.monotonic()
        try:
            lease = self._read(self._timeout(deadline))
        except _OutOfTime:
            return False
        except ApiException as exc:
            log.warning("could not read lease %s/%s: %s",
                        self._namespace, self._name, exc.reason)
            return False
        except Exception:
            log.exception("could not read lease %s/%s", self._namespace, self._name)
            return False

        if self._on_reachable is not None:
            callback, self._on_reachable = self._on_reachable, None
            try:
                callback()
            except Exception:
                log.exception("on_reachable callback raised")

        if lease is None:
            return self._create(deadline)

        spec = lease.spec
        holder = spec.holder_identity if spec else None
        renewed = spec.renew_time if spec else None

        record = (holder, renewed)
        if record != self._observed_record:
            self._observed_record = record
            self._observed_at = time.monotonic()

        held_by_other = bool(holder) and holder != self._identity
        if held_by_other and time.monotonic() - self._observed_at < self._lease_duration:
            log.debug("lease %s/%s is held by %s", self._namespace, self._name, holder)
            return False

        now = _now()
        transitions = (spec.lease_transitions if spec else None) or 0
        acquired = _micro_time(spec.acquire_time if spec else None)
        if holder != self._identity:
            if held_by_other:
                log.info("lease %s/%s held by %s has expired; taking over",
                         self._namespace, self._name, holder)
            transitions += 1
            acquired = _micro_time(now)

        body = {
            "apiVersion": _API_VERSION,
            "kind": "Lease",
            "metadata": {
                "name": self._name,
                "namespace": self._namespace,
                # Optimistic concurrency: if another candidate wrote the lease
                # between our read and this update, the apiserver rejects us
                # with a 409 rather than letting both of us believe we won.
                "resourceVersion": lease.metadata.resource_version,
                "labels": self._labels,
            },
            "spec": {
                "holderIdentity": self._identity,
                "leaseDurationSeconds": int(self._lease_duration),
                "acquireTime": acquired or _micro_time(now),
                "renewTime": _micro_time(now),
                "leaseTransitions": transitions,
            },
        }
        try:
            self._api.replace_namespaced_lease(
                self._name, self._namespace, body,
                _request_timeout=self._timeout(deadline),
            )
        except _OutOfTime:
            return False
        except ApiException as exc:
            if exc.status == 409:
                log.debug("lost the race to update lease %s/%s",
                          self._namespace, self._name)
            else:
                log.warning("could not update lease %s/%s: %s",
                            self._namespace, self._name, exc.reason)
            return False
        except Exception:
            log.exception("could not update lease %s/%s", self._namespace, self._name)
            return False

        self._observed_record = (self._identity, now)
        self._observed_at = time.monotonic()
        self._renewed_at = started
        return True

    # -- API helpers -------------------------------------------------------

    def _timeout(self, deadline: float | None) -> float:
        """The timeout for one Lease call: the full one, or what is left.

        Raises :class:`_OutOfTime` rather than returning zero or less, which
        the client would take to mean "no timeout at all".
        """
        if deadline is None:
            return self._request_timeout
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _OutOfTime
        return min(self._request_timeout, remaining)

    def _read(self, timeout: float | None = None):
        try:
            return self._api.read_namespaced_lease(
                self._name, self._namespace,
                _request_timeout=timeout or self._request_timeout,
            )
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise

    def _create(self, deadline: float | None = None) -> bool:
        started = time.monotonic()
        now = _now()
        body = {
            "apiVersion": _API_VERSION,
            "kind": "Lease",
            "metadata": {
                "name": self._name,
                "namespace": self._namespace,
                "labels": self._labels,
            },
            "spec": {
                "holderIdentity": self._identity,
                "leaseDurationSeconds": int(self._lease_duration),
                "acquireTime": _micro_time(now),
                "renewTime": _micro_time(now),
                "leaseTransitions": 0,
            },
        }
        try:
            self._api.create_namespaced_lease(
                self._namespace, body, _request_timeout=self._timeout(deadline)
            )
        except _OutOfTime:
            return False
        except ApiException as exc:
            # 409 means another candidate created it first; we campaign again.
            if exc.status != 409:
                log.warning("could not create lease %s/%s: %s",
                            self._namespace, self._name, exc.reason)
            return False
        except Exception:
            log.exception("could not create lease %s/%s", self._namespace, self._name)
            return False
        self._observed_record = (self._identity, now)
        self._observed_at = time.monotonic()
        self._renewed_at = started
        return True

    def release(self) -> None:
        """Clear our hold so a standby takes over now rather than in a lease.

        Best-effort: if it does not land, the lease simply expires as it would
        have anyway.
        """
        try:
            lease = self._read()
            if lease is None or not lease.spec:
                return
            if lease.spec.holder_identity != self._identity:
                return  # already taken over; nothing of ours to release
            now = _now()
            body = {
                "apiVersion": _API_VERSION,
                "kind": "Lease",
                "metadata": {
                    "name": self._name,
                    "namespace": self._namespace,
                    "resourceVersion": lease.metadata.resource_version,
                    "labels": self._labels,
                },
                "spec": {
                    "holderIdentity": None,
                    # One second, not zero: a standby must still observe the
                    # record change before it may claim the lease.
                    "leaseDurationSeconds": 1,
                    "acquireTime": _micro_time(lease.spec.acquire_time) or _micro_time(now),
                    "renewTime": _micro_time(now),
                    "leaseTransitions": lease.spec.lease_transitions or 0,
                },
            }
            self._api.replace_namespaced_lease(
                self._name, self._namespace, body,
                _request_timeout=self._request_timeout,
            )
            log.info("released lease %s/%s", self._namespace, self._name)
        except Exception:
            log.warning("could not release lease %s/%s; it will expire instead",
                        self._namespace, self._name, exc_info=True)
