"""The queue's guarantees are what keep two workers off the same host."""

import time

from cert_publisher.workqueue import (
    ExponentialBackoff,
    RateLimitingQueue,
    WorkQueue,
)


def test_adding_a_key_twice_yields_one_unit_of_work():
    """A burst of watch events for one publication is a single reconcile."""
    queue = WorkQueue()
    queue.add("ns/a")
    queue.add("ns/a")

    assert queue.get(timeout=0.1) == "ns/a"
    assert queue.get(timeout=0.05) is None


def test_a_key_in_flight_is_never_handed_to_a_second_worker():
    """Two workers must never talk to the same target host at once."""
    queue = WorkQueue()
    queue.add("ns/a")
    first = queue.get(timeout=0.1)

    # An event arrives while the reconcile is still running.
    queue.add("ns/a")
    assert queue.get(timeout=0.05) is None, "handed out while still processing"

    queue.done(first)
    assert queue.get(timeout=0.1) == "ns/a", "the mid-reconcile event was lost"


def test_a_key_not_re_added_while_in_flight_is_not_requeued():
    queue = WorkQueue()
    queue.add("ns/a")
    queue.done(queue.get(timeout=0.1))
    assert queue.get(timeout=0.05) is None


def test_a_delayed_key_is_not_available_until_it_is_due():
    queue = WorkQueue()
    queue.add_after("ns/a", 0.15)

    assert queue.get(timeout=0.02) is None
    assert queue.get(timeout=0.5) == "ns/a"


def test_the_nearest_deadline_wins():
    """A retry in five seconds must not be pushed out by a resync in an hour."""
    queue = WorkQueue()
    queue.add_after("ns/a", 0.1)
    queue.add_after("ns/a", 3600)

    started = time.monotonic()
    assert queue.get(timeout=1.0) == "ns/a"
    assert time.monotonic() - started < 1.0


def test_an_immediate_add_supersedes_a_pending_delay():
    """An edit to a publication is acted on now, not at its next resync."""
    queue = WorkQueue()
    queue.add_after("ns/a", 3600)
    queue.add("ns/a")

    assert queue.get(timeout=0.1) == "ns/a"
    # And the superseded delayed entry does not resurface later.
    queue.done("ns/a")
    assert queue.get(timeout=0.05) is None


def test_shutdown_releases_waiting_consumers():
    queue = WorkQueue()
    queue.shutdown()
    assert queue.get(timeout=5.0) is None  # returns immediately, not after 5s
    queue.add("ns/a")
    assert queue.get(timeout=0.05) is None


def test_no_new_work_is_handed_out_after_shutdown():
    """A shutdown waits for the publishes in flight; it must not start more.
    On the iDRAC path a new one rotates the host's key."""
    queue = WorkQueue()
    queue.add("ns/a")
    queue.add("ns/b")
    queue.shutdown()

    assert queue.get(timeout=0.05) is None


def test_backoff_doubles_and_is_capped():
    backoff = ExponentialBackoff(base=1.0, maximum=8.0, jitter=0.0)
    assert [backoff.next_backoff("ns/a") for _ in range(6)] == [
        1.0, 2.0, 4.0, 8.0, 8.0, 8.0
    ]


def test_backoff_is_per_key():
    backoff = ExponentialBackoff(base=1.0, maximum=64.0, jitter=0.0)
    backoff.next_backoff("ns/a")
    backoff.next_backoff("ns/a")
    assert backoff.next_backoff("ns/b") == 1.0, "one bad host slowed another down"


def test_a_success_resets_the_backoff():
    backoff = ExponentialBackoff(base=1.0, maximum=64.0, jitter=0.0)
    backoff.next_backoff("ns/a")
    backoff.next_backoff("ns/a")
    backoff.forget("ns/a")
    assert backoff.next_backoff("ns/a") == 1.0


def test_a_long_broken_key_does_not_overflow_the_delay():
    """2 ** failures would reach inf; the shift is clamped instead."""
    backoff = ExponentialBackoff(base=1.0, maximum=900.0, jitter=0.0)
    for _ in range(5000):
        delay = backoff.next_backoff("ns/a")
    assert delay == 900.0


def test_rate_limited_requeue_reports_the_delay_it_used():
    queue = RateLimitingQueue(ExponentialBackoff(base=0.05, maximum=1.0, jitter=0.0))
    assert queue.add_rate_limited("ns/a") == 0.05
    assert queue.failures("ns/a") == 1
    assert queue.get(timeout=1.0) == "ns/a"
    queue.forget("ns/a")
    assert queue.failures("ns/a") == 0
