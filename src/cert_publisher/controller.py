"""The operator's event loop: watch, queue, reconcile, back off, resync.

Where the CronJob listed every CertPublication, reconciled each one in turn and
exited non-zero if any of them raised, this is the standard controller shape:

**Watchers turn API events into keys.** One thread per resource type streams
changes and enqueues the ``namespace/name`` of the affected publication --
never the event's object, which is stale the moment it is delivered. A
publication maps to itself; a cert-manager Certificate or CertificateRequest
maps through its ``ownerReferences`` to the publication that created it, so
material arriving from cert-manager wakes exactly the publication waiting on
it and nothing else. That is what makes a new CertPublication, and an
issuance, act in seconds rather than on the next half-hour tick.

**A work queue decides who runs what.** Keys are deduplicated, and a key in
flight is never handed to a second worker, so a storm of events for one
publication is one reconcile and two workers never talk to the same target
host at the same time.

**Failure is per-publication, not per-process.** A reconcile that raises marks
that publication's status and requeues it with exponential backoff. One
unreachable host no longer fails a Job, and no longer stops the publications
behind it in the list from being reconciled at all.

**A resync catches what no event can.** The interesting state for this
operator lives on hosts outside the cluster -- a certificate replaced by hand,
an iDRAC that quietly reverted, a certificate ageing into its renewal window --
and none of that produces an API event. Every publication is therefore looked
at again on a resync interval, spread out so a hundred publications do not
reach for a hundred hosts at the same instant.
"""

from __future__ import annotations

import datetime
import logging
import random
import threading
import time
from dataclasses import dataclass

from kubernetes import watch
from kubernetes.client.rest import ApiException

from .kube import (
    CM_CR_PLURAL,
    CM_GROUP,
    CM_PLURAL,
    CM_VERSION,
    GROUP,
    KIND,
    PLURAL,
    VERSION,
    Kube,
)
from .reconcile import Result, reconcile_publication
from .status import ERROR, set_status
from .utils import now_utc, rfc3339
from .workqueue import ExponentialBackoff, RateLimitingQueue

log = logging.getLogger("cert-publisher.controller")


@dataclass(frozen=True)
class WatchedResource:
    """A custom resource to watch, and how its events map to a publication."""

    group: str
    version: str
    plural: str
    #: True when the object *is* a publication; False when it is one we own and
    #: whose owning publication has to be read off its ownerReferences.
    is_publication: bool = False

    @property
    def label(self) -> str:
        return f"{self.plural}.{self.group}"


PUBLICATIONS = WatchedResource(GROUP, VERSION, PLURAL, is_publication=True)
CERTIFICATES = WatchedResource(CM_GROUP, CM_VERSION, CM_PLURAL)
CERTIFICATE_REQUESTS = WatchedResource(CM_GROUP, CM_VERSION, CM_CR_PLURAL)


@dataclass(frozen=True)
class ControllerConfig:
    """Tunables, all surfaced as Helm values on the Deployment."""

    namespace: str | None = None
    workers: int = 4
    resync_seconds: float = 1800.0
    #: Fraction of the resync interval to scatter resyncs over. Publications
    #: renewed together (a fleet installed on the same day) would otherwise
    #: keep reconciling together forever.
    resync_jitter: float = 0.2
    backoff_base_seconds: float = 5.0
    backoff_max_seconds: float = 900.0
    #: Window to spread the initial reconcile of every publication over, after
    #: a start or a relist. Converging on a fleet must not mean opening a
    #: connection to all of it at once.
    startup_spread_seconds: float = 60.0
    #: How long each watch connection lives before the apiserver closes it. A
    #: bounded watch is how a silently dead connection gets noticed.
    watch_timeout_seconds: int = 300
    #: Floor on how often a watch may be re-established. A watch the apiserver
    #: closes the instant it opens would otherwise be a hot loop against it.
    watch_min_interval_seconds: float = 1.0
    shutdown_timeout_seconds: float = 30.0
    #: How long one reconcile may run before this process is treated as wedged.
    #: A provisioner call that hangs with no timeout of its own holds its worker
    #: forever and starves every publication behind it; the CronJob's
    #: activeDeadlineSeconds used to bound exactly that, and liveness does now.
    reconcile_timeout_seconds: float = 900.0


class _Watcher:
    """One list/watch loop, on its own thread, feeding keys into the queue."""

    def __init__(
        self,
        kube: Kube,
        resource: WatchedResource,
        config: ControllerConfig,
        on_key,
        on_sync_key=None,
    ) -> None:
        self._kube = kube
        self._resource = resource
        self._config = config
        self._on_key = on_key
        self._on_sync_key = on_sync_key or on_key
        self._watch: watch.Watch | None = None
        self._lock = threading.Lock()
        # Liveness: when this loop last knew it was connected and current.
        self._last_healthy = time.monotonic()
        self.thread: threading.Thread | None = None
        # One loop, so one key -- but the jitter and the ceiling are the same
        # problem the queue's retries have, and the same implementation.
        self._backoff = ExponentialBackoff(
            config.backoff_base_seconds, config.backoff_max_seconds
        )

    # -- lifecycle ---------------------------------------------------------

    def start(self, stop_event: threading.Event) -> None:
        self.thread = threading.Thread(
            target=self._run, args=(stop_event,),
            name=f"watch-{self._resource.plural}", daemon=True,
        )
        self.thread.start()

    def stop(self) -> None:
        with self._lock:
            if self._watch is not None:
                # Ends the generator after the next event or timeout; the
                # underlying read is blocking, so this is a request, not a
                # guarantee, which is why the thread is a daemon.
                self._watch.stop()

    @property
    def last_healthy(self) -> float:
        return self._last_healthy

    @property
    def label(self) -> str:
        return self._resource.label

    # -- the loop ----------------------------------------------------------

    def _run(self, stop_event: threading.Event) -> None:
        resource_version: str | None = None
        while not stop_event.is_set():
            started = time.monotonic()
            try:
                if resource_version is None:
                    resource_version = self._sync()
                resource_version = self._watch_from(resource_version, stop_event)
                self._last_healthy = time.monotonic()
                self._backoff.forget(self._resource.label)
            except ApiException as exc:
                if exc.status == 410:
                    # The apiserver has compacted past our position. This is
                    # routine, not an error: relist and carry on without
                    # backing off, so the gap stays as short as possible.
                    log.info("[%s] watch expired; relisting", self._resource.label)
                    resource_version = None
                    continue
                # Any other failure keeps the position: the apiserver says 410
                # when it is genuinely gone, so a blip is no reason to pay for
                # a relist -- which, for publications, requeues the whole fleet.
                log.warning("[%s] watch failed: %s", self._resource.label, exc.reason)
            except Exception:
                if stop_event.is_set():
                    break
                log.exception("[%s] watch failed", self._resource.label)
            else:
                # A watch that came back instantly -- rather than after the
                # server-side timeout -- must not be reopened instantly too.
                idle = self._config.watch_min_interval_seconds - (
                    time.monotonic() - started
                )
                if idle > 0 and stop_event.wait(idle):
                    break
                continue
            # Only reached after a failure: wait before reconnecting so a
            # rejected watch (RBAC, a missing CRD) does not hammer the
            # apiserver.
            if stop_event.wait(self._backoff.next_backoff(self._resource.label)):
                break
        log.debug("[%s] watcher stopped", self._resource.label)

    def _sync(self) -> str:
        """List the resource and return the version to start watching from.

        For publications this is also the seeding pass: every existing one is
        queued, which is what makes a fresh pod (or one that has just won the
        lease) converge on the whole cluster rather than only on what changes
        from now on. It runs again after a relist, because a watch that lost
        its position may have lost changes with it. For the resources we
        merely own, only the version is wanted -- the publications they belong
        to are already queued by the pass above -- so the list is capped at one
        item.
        """
        if self._resource.is_publication:
            items, version = self._list(limit=None)
            for item in items:
                key = _publication_key(item)
                if key:
                    self._on_sync_key(key)
            log.info("[%s] synced %d object(s)", self._resource.label, len(items))
        else:
            _, version = self._list(limit=1)
            log.info("[%s] watching from version %s", self._resource.label, version)
        self._last_healthy = time.monotonic()
        return version

    def _list(self, *, limit: int | None) -> tuple[list[dict], str]:
        kwargs: dict = {}
        if limit is not None:
            kwargs["limit"] = limit
        resp = self._call(self._kube.custom.list_namespaced_custom_object,
                          self._kube.custom.list_cluster_custom_object, **kwargs)
        version = (resp.get("metadata") or {}).get("resourceVersion")
        if not version:
            raise RuntimeError(f"{self._resource.label} list carried no resourceVersion")
        return resp.get("items") or [], version

    def _watch_from(self, resource_version: str, stop_event: threading.Event) -> str:
        stream = watch.Watch()
        with self._lock:
            self._watch = stream
        try:
            events = stream.stream(
                self._watch_func(),
                *self._watch_args(),
                resource_version=resource_version,
                # Bounds the connection. Note this also disables the client's
                # own retry-once-on-410, which is what lets the loop above see
                # the 410 and relist deliberately.
                timeout_seconds=self._config.watch_timeout_seconds,
                # Give the read a ceiling above the server-side timeout so a
                # connection the network dropped is not held open forever.
                _request_timeout=self._config.watch_timeout_seconds + 30,
            )
            try:
                for event in events:
                    self._last_healthy = time.monotonic()
                    if stop_event.is_set():
                        stream.stop()
                        break
                    self._handle(event)
            finally:
                # Run the generator's own cleanup now rather than whenever it
                # is collected, so the HTTP connection is released on the way
                # out of a shutdown.
                events.close()
            # The apiserver closed the watch at its timeout. Resume from where
            # we got to rather than paying for another list.
            return stream.resource_version or resource_version
        finally:
            with self._lock:
                self._watch = None

    def _handle(self, event: dict) -> None:
        obj = event.get("object")
        if not isinstance(obj, dict):
            return  # BOOKMARK and other event shapes carry nothing to map
        if self._resource.is_publication:
            key = _publication_key(obj)
        else:
            key = _owning_publication_key(obj)
        if key:
            log.debug("[%s] %s -> %s", self._resource.label, event.get("type"), key)
            self._on_key(key)

    # -- namespaced vs cluster-wide ---------------------------------------

    def _watch_func(self):
        return self._kube.custom.list_namespaced_custom_object if self._config.namespace \
            else self._kube.custom.list_cluster_custom_object

    def _watch_args(self) -> tuple:
        resource = self._resource
        if self._config.namespace:
            return (resource.group, resource.version, self._config.namespace,
                    resource.plural)
        return (resource.group, resource.version, resource.plural)

    def _call(self, namespaced, cluster_wide, **kwargs):
        # The bound method is passed to Watch.stream elsewhere rather than a
        # partial, because the client reads the method's docstring to decide
        # how to deserialise; keep the two call sites shaped the same.
        return (namespaced if self._config.namespace else cluster_wide)(
            *self._watch_args(), **kwargs
        )


def _publication_key(obj: dict) -> str | None:
    meta = obj.get("metadata") or {}
    namespace, name = meta.get("namespace"), meta.get("name")
    if not namespace or not name:
        return None
    return f"{namespace}/{name}"


def _owning_publication_key(obj: dict) -> str | None:
    """The publication that owns this object, if any.

    Everything this operator creates carries a controller ownerReference back
    to its publication, so this is both the mapping and the filter: a
    Certificate somebody else manages simply has no owner of our kind and is
    ignored.
    """
    meta = obj.get("metadata") or {}
    namespace = meta.get("namespace")
    if not namespace:
        return None
    for owner in meta.get("ownerReferences") or []:
        if owner.get("kind") != KIND:
            continue
        api_version = owner.get("apiVersion") or ""
        if api_version.split("/", 1)[0] != GROUP:
            continue
        return f"{namespace}/{owner['name']}"
    return None


class Controller:
    """Runs watchers and workers until stopped, reconciling as events arrive."""

    def __init__(self, kube: Kube, config: ControllerConfig | None = None) -> None:
        self._kube = kube
        self._config = config or ControllerConfig()
        self._queue = RateLimitingQueue(
            ExponentialBackoff(
                self._config.backoff_base_seconds,
                self._config.backoff_max_seconds,
            )
        )
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []
        # What each worker is reconciling and since when, so liveness can tell
        # a busy worker from one wedged inside a call that never returns.
        self._in_flight: dict[str, tuple[str, float]] = {}
        self._in_flight_lock = threading.Lock()
        self._watchers = [
            _Watcher(kube, resource, self._config,
                     on_key=self._queue.add,
                     on_sync_key=self._enqueue_startup)
            for resource in (PUBLICATIONS, CERTIFICATES, CERTIFICATE_REQUESTS)
        ]
        self._started = False

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Start watchers and workers. Returns as soon as they are running."""
        if self._started:
            return
        self._started = True
        self._stop_event.clear()
        log.info(
            "starting controller: %d worker(s), resync every %.0fs, scope %s",
            self._config.workers, self._config.resync_seconds,
            self._config.namespace or "all namespaces",
        )
        for watcher in self._watchers:
            watcher.start(self._stop_event)
        for index in range(self._config.workers):
            thread = threading.Thread(
                target=self._work, name=f"worker-{index}", daemon=True
            )
            thread.start()
            self._threads.append(thread)

    def stop(self) -> bool:
        """Stop accepting work and let in-flight reconciles finish.

        Called on SIGTERM and on losing the lease. A reconcile mid-flight is
        talking to a host over SSH or WS-Man and cannot be interrupted safely,
        so it is given until ``shutdown_timeout_seconds`` -- which is why the
        Deployment's termination grace period is set above that.

        Returns whether every worker finished. A Python thread cannot be
        forced to stop, so a False here means one is still writing to a host:
        the caller must not hand leadership on until the lease expires.
        """
        if not self._started:
            return True
        log.info("stopping controller")
        self._stop_event.set()
        self._queue.shutdown()
        for watcher in self._watchers:
            watcher.stop()
        deadline = time.monotonic() + self._config.shutdown_timeout_seconds
        for thread in self._threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        still_running = [t.name for t in self._threads if t.is_alive()]
        if still_running:
            log.warning("worker(s) still reconciling at shutdown: %s",
                        ", ".join(still_running))
        self._threads.clear()
        self._started = False
        return not still_running

    def healthy(self) -> bool:
        """Whether this process is still doing its job, for the liveness probe.

        Two things stop it without stopping the process, and neither is fixed
        by waiting: a watch that has produced nothing -- not an event, not a
        timeout, not an error -- for several of its own timeouts, and a
        reconcile wedged inside a provisioner call that has no timeout of its
        own. Both starve every publication behind them, so both fail liveness
        and the kubelet restarts the pod.
        """
        if not self._started:
            return True
        now = time.monotonic()
        threshold = self._config.watch_timeout_seconds * 3 + 60
        for watcher in self._watchers:
            if now - watcher.last_healthy > threshold:
                log.error("[%s] watch has been silent for %.0fs",
                          watcher.label, now - watcher.last_healthy)
                return False
        with self._in_flight_lock:
            wedged = [
                (worker, key, now - since)
                for worker, (key, since) in self._in_flight.items()
                if now - since > self._config.reconcile_timeout_seconds
            ]
        for worker, key, elapsed in wedged:
            log.error("[%s] has been reconciling %s for %.0fs", worker, key, elapsed)
        return not wedged

    # -- the worker --------------------------------------------------------

    def _work(self) -> None:
        worker = threading.current_thread().name
        while not self._stop_event.is_set():
            key = self._queue.get(timeout=1.0)
            if key is None:
                continue
            with self._in_flight_lock:
                self._in_flight[worker] = (key, time.monotonic())
            try:
                self._reconcile(key)
            except Exception:
                # _reconcile handles its own failures; anything reaching here
                # is a bug in the controller, and must still not kill the
                # worker and with it the publications behind this one.
                log.exception("[%s] unhandled controller error", key)
            finally:
                with self._in_flight_lock:
                    self._in_flight.pop(worker, None)
                self._queue.done(key)

    def _reconcile(self, key: str) -> None:
        namespace, _, name = key.partition("/")
        try:
            pub = self._kube.get_publication(namespace, name)
        except Exception:
            log.exception("[%s] could not read publication", key)
            delay = self._queue.add_rate_limited(key)
            log.info("[%s] retrying in %.0fs", key, delay)
            return

        if pub is None:
            # Deleted. The Certificate and any CertificateRequest are owned by
            # it and collected by the apiserver, so there is nothing to undo.
            log.info("[%s] publication is gone; dropping it", key)
            self._queue.forget(key)
            return

        try:
            result = reconcile_publication(self._kube, pub)
        except Exception as exc:
            log.exception("[%s] reconcile failed", key)
            self._fail(key, pub, exc)
            return

        self._queue.forget(key)
        self._requeue(key, result)

    def _fail(self, key: str, pub: dict, exc: Exception) -> None:
        """Record a failed reconcile and schedule a retry.

        This is the whole point of the refactor: one host that is down is one
        publication in ``Error`` with a retry time on it, not a failed Job that
        says nothing about the other ninety-nine.
        """
        delay = self._queue.add_rate_limited(key)
        attempt = self._queue.failures(key)
        log.info("[%s] attempt %d failed; retrying in %.0fs", key, attempt, delay)
        set_status(
            self._kube, pub, ERROR,
            f"{exc} (attempt {attempt}; retrying in {_pretty(delay)})",
            next_retry=rfc3339(now_utc() + datetime.timedelta(seconds=delay)),
        )

    def _requeue(self, key: str, result: Result | None) -> None:
        if result is not None and result.requeue_after is not None:
            self._queue.add_after(key, result.requeue_after.total_seconds())
            return
        self._enqueue_resync(key)

    def _enqueue_resync(self, key: str) -> None:
        """Queue ``key`` one resync interval out, scattered.

        The scatter matters more than it looks: publications issued together
        renew together, so without it a fleet installed on the same afternoon
        would reconcile in lockstep for the rest of its life.
        """
        interval = self._config.resync_seconds
        jitter = interval * self._config.resync_jitter
        self._queue.add_after(key, max(0.0, interval + random.uniform(-jitter, jitter)))

    def _enqueue_startup(self, key: str) -> None:
        """Queue ``key`` soon, but spread across the startup window.

        A pod that has just won the lease has to look at every publication --
        it has no idea what happened while nobody was leading -- but it must
        not reach for every host in the fleet in the same second to do it.
        """
        self._queue.add_after(
            key, random.uniform(0.0, max(0.0, self._config.startup_spread_seconds))
        )

    # -- for tests and callers --------------------------------------------

    @property
    def queue(self) -> RateLimitingQueue:
        return self._queue


def _pretty(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    return f"{seconds / 3600:.1f}h"
