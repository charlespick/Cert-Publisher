"""A deduplicating, rate-limited work queue in the shape of client-go's.

The controller turns every interesting API event into a *key* (``ns/name`` of a
CertPublication) rather than acting on the event itself, and hands that key to
this queue. Three properties follow, and all three matter for an operator that
drives slow, external hosts:

* **Deduplication.** A burst of events for one publication -- the Certificate
  going Ready, its Secret being written, the publication itself being edited --
  collapses into a single reconcile.
* **Per-key serialisation.** A key handed out by :meth:`WorkQueue.get` is not
  handed out again until :meth:`WorkQueue.done`, so two workers never reconcile
  the same publication (and never talk to the same target host) at once. A key
  re-added while it is being processed is remembered and requeued on ``done``,
  so an event that races a reconcile is neither lost nor run concurrently.
* **Delayed adds.** :meth:`WorkQueue.add_after` schedules a key for later
  without parking a worker on it, which is what makes both retry backoff and
  the periodic resync free of dedicated threads.
"""

from __future__ import annotations

import heapq
import itertools
import random
import threading
import time
from collections import deque


class WorkQueue:
    """Thread-safe key queue: deduplicating, delaying, per-key serialising."""

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._queue: deque[str] = deque()
        # Keys that ought to be processed: queued now, or queued again as soon
        # as the in-flight reconcile for them finishes.
        self._dirty: set[str] = set()
        self._processing: set[str] = set()
        # Delayed adds, as a heap of (due, sequence, key) plus the authoritative
        # deadline per key. A key rescheduled sooner leaves a stale heap entry
        # behind, which is dropped when it pops rather than searched for.
        self._waiting: list[tuple[float, int, str]] = []
        self._deadlines: dict[str, float] = {}
        self._sequence = itertools.count()
        self._shutdown = False

    # -- producing ---------------------------------------------------------

    def add(self, key: str) -> None:
        """Queue ``key`` for processing as soon as a worker is free."""
        with self._cond:
            self._add_locked(key)
            self._cond.notify()

    def add_after(self, key: str, delay: float) -> None:
        """Queue ``key`` after ``delay`` seconds.

        The earliest pending deadline for a key wins: an immediate requeue is
        never pushed back by a resync scheduled half an hour out.
        """
        if delay <= 0:
            self.add(key)
            return
        with self._cond:
            if self._shutdown:
                return
            due = time.monotonic() + delay
            existing = self._deadlines.get(key)
            if existing is not None and existing <= due:
                return
            self._deadlines[key] = due
            heapq.heappush(self._waiting, (due, next(self._sequence), key))
            self._cond.notify()

    # -- consuming ---------------------------------------------------------

    def get(self, timeout: float) -> str | None:
        """Take the next key, or ``None`` if none came up within ``timeout``.

        The caller owns the key until it calls :meth:`done` with it.
        """
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                self._promote_due_locked(time.monotonic())
                if self._queue:
                    key = self._queue.popleft()
                    self._dirty.discard(key)
                    self._processing.add(key)
                    return key
                if self._shutdown:
                    return None
                now = time.monotonic()
                wait = deadline - now
                if wait <= 0:
                    return None
                if self._waiting:
                    wait = min(wait, self._waiting[0][0] - now)
                self._cond.wait(max(wait, 0.0))

    def done(self, key: str) -> None:
        """Release ``key``, requeueing it if it was re-added while in flight."""
        with self._cond:
            self._processing.discard(key)
            if key in self._dirty:
                self._queue.append(key)
                self._cond.notify()

    # -- lifecycle ---------------------------------------------------------

    def shutdown(self) -> None:
        """Stop accepting work and wake every waiting consumer."""
        with self._cond:
            self._shutdown = True
            self._cond.notify_all()

    @property
    def shutting_down(self) -> bool:
        with self._cond:
            return self._shutdown

    def __len__(self) -> int:
        with self._cond:
            return len(self._queue) + len(self._waiting)

    # -- internals ---------------------------------------------------------

    def _add_locked(self, key: str) -> None:
        if self._shutdown or key in self._dirty:
            return
        # An immediate add supersedes any delayed one for the same key.
        self._deadlines.pop(key, None)
        self._dirty.add(key)
        if key in self._processing:
            # done() will requeue it; queueing now would let two workers hold
            # the same key, and with it the same target host.
            return
        self._queue.append(key)

    def _promote_due_locked(self, now: float) -> None:
        while self._waiting and self._waiting[0][0] <= now:
            due, _, key = heapq.heappop(self._waiting)
            if self._deadlines.get(key) != due:
                continue  # superseded by a nearer deadline, or already added
            del self._deadlines[key]
            self._add_locked(key)


class ExponentialBackoff:
    """Per-key exponential backoff, in the style of client-go's rate limiters.

    Failures for one key double its delay up to a ceiling; a success forgets
    the key so the next failure starts from the base delay again. Jitter keeps
    a fleet of hosts that failed together (a flapping router, an issuer
    outage) from retrying in lockstep afterwards.
    """

    def __init__(self, base: float, maximum: float, jitter: float = 0.1) -> None:
        self._base = base
        self._maximum = maximum
        self._jitter = jitter
        self._failures: dict[str, int] = {}
        self._lock = threading.Lock()

    def next_backoff(self, key: str) -> float:
        with self._lock:
            failures = self._failures.get(key, 0)
            self._failures[key] = failures + 1
        # Shift rather than pow() so a long-broken host cannot overflow into inf.
        delay = min(self._base * (2 ** min(failures, 32)), self._maximum)
        if self._jitter:
            delay *= 1 + random.uniform(-self._jitter, self._jitter)
        return delay

    def failures(self, key: str) -> int:
        with self._lock:
            return self._failures.get(key, 0)

    def forget(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


class RateLimitingQueue(WorkQueue):
    """A :class:`WorkQueue` that knows how long to wait before a retry."""

    def __init__(self, backoff: ExponentialBackoff) -> None:
        super().__init__()
        self._backoff = backoff

    def add_rate_limited(self, key: str) -> float:
        """Requeue ``key`` after its next backoff, and return that delay."""
        delay = self._backoff.next_backoff(key)
        self.add_after(key, delay)
        return delay

    def failures(self, key: str) -> int:
        """How many times ``key`` has been requeued without succeeding."""
        return self._backoff.failures(key)

    def forget(self, key: str) -> None:
        """Reset ``key``'s backoff, after a reconcile that did not fail."""
        self._backoff.forget(key)
