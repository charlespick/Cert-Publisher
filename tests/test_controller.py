"""The behaviours the CronJob could not have: per-publication failure, backoff,
event-driven wake-ups, and a resync that does not stampede."""

import datetime
import threading
import time

import pytest

from cert_publisher import controller as controller_mod
from cert_publisher.controller import (
    Controller,
    ControllerConfig,
    _owning_publication_key,
    _publication_key,
)
from cert_publisher.reconcile import Result
from cert_publisher.status import ERROR, PUBLISHED


class _FakeKube:
    def __init__(self, publications):
        self.publications = publications
        self.status = {}
        self.recorded = []

    def get_publication(self, namespace, name):
        return self.publications.get(f"{namespace}/{name}")

    def patch_publication_status(self, namespace, name, status):
        self.status.setdefault(f"{namespace}/{name}", {}).update(status)

    def record_event(self, pub, event_type, reason, message):
        self.recorded.append((event_type, reason, message))


def _pub(name="web01", namespace="default"):
    return {
        "metadata": {"name": name, "namespace": namespace, "generation": 1,
                     "uid": "u-1"},
        "spec": {"dnsNames": [f"{name}.example.com"]},
    }


def _controller(kube, **overrides):
    config = ControllerConfig(
        resync_seconds=1000.0, resync_jitter=0.0,
        backoff_base_seconds=7.0, backoff_max_seconds=100.0,
        startup_spread_seconds=0.0, **overrides,
    )
    return Controller(kube, config)


# -- event -> key mapping -------------------------------------------------


def test_a_publication_maps_to_its_own_key():
    assert _publication_key(_pub()) == "default/web01"


def test_an_owned_certificate_maps_to_the_publication_that_owns_it():
    """This is what makes an issuance wake the publication waiting on it."""
    certificate = {
        "metadata": {
            "name": "web01", "namespace": "default",
            "ownerReferences": [{
                "apiVersion": "certpublisher.makerland.xyz/v1alpha1",
                "kind": "CertPublication", "name": "web01", "controller": True,
            }],
        }
    }
    assert _owning_publication_key(certificate) == "default/web01"


def test_a_certificate_we_do_not_own_is_ignored():
    """Every Certificate in the cluster streams past; only ours are ours."""
    foreign = {
        "metadata": {
            "name": "someone-else", "namespace": "default",
            "ownerReferences": [
                {"apiVersion": "apps/v1", "kind": "Deployment", "name": "web"},
                {"apiVersion": "other.example.com/v1", "kind": "CertPublication",
                 "name": "impostor"},
            ],
        }
    }
    assert _owning_publication_key(foreign) is None


def test_an_unowned_object_is_ignored():
    assert _owning_publication_key({"metadata": {"name": "x", "namespace": "d"}}) is None


# -- reconcile outcomes ---------------------------------------------------


def test_a_failing_publication_is_recorded_and_retried_not_raised(monkeypatch):
    """The whole point of the refactor: one bad host is one bad publication."""
    kube = _FakeKube({"default/web01": _pub()})
    ctrl = _controller(kube)

    def _boom(_kube, _pub):
        raise ConnectionError("web01.example.com: connection refused")

    monkeypatch.setattr(controller_mod, "reconcile_publication", _boom)
    ctrl._reconcile("default/web01")

    status = kube.status["default/web01"]
    assert status["phase"] == ERROR
    assert "connection refused" in status["message"]
    assert "retrying in" in status["message"]
    assert status["nextRetryTime"]
    # Queued for a retry rather than dropped, and backed off rather than spun.
    assert ctrl.queue.failures("default/web01") == 1
    assert ctrl.queue.get(timeout=0.05) is None, "retried with no backoff at all"


def test_one_failing_publication_does_not_touch_another(monkeypatch):
    kube = _FakeKube({"default/web01": _pub(), "default/web02": _pub("web02")})
    ctrl = _controller(kube)

    def _selective(_kube, pub):
        if pub["metadata"]["name"] == "web01":
            raise ConnectionError("down")
        return Result()

    monkeypatch.setattr(controller_mod, "reconcile_publication", _selective)
    ctrl._reconcile("default/web01")
    ctrl._reconcile("default/web02")

    assert kube.status["default/web01"]["phase"] == ERROR
    assert "default/web02" not in kube.status  # the fake reconcile wrote nothing
    assert ctrl.queue.failures("default/web02") == 0


def test_repeated_failures_back_off_further_each_time(monkeypatch):
    kube = _FakeKube({"default/web01": _pub()})
    ctrl = _controller(kube)
    monkeypatch.setattr(
        controller_mod, "reconcile_publication",
        lambda *_: (_ for _ in ()).throw(ConnectionError("down")),
    )

    for _ in range(3):
        ctrl._reconcile("default/web01")
    assert ctrl.queue.failures("default/web01") == 3


def test_a_success_clears_the_backoff_and_the_retry_time(monkeypatch):
    kube = _FakeKube({"default/web01": _pub()})
    ctrl = _controller(kube)
    monkeypatch.setattr(
        controller_mod, "reconcile_publication",
        lambda *_: (_ for _ in ()).throw(ConnectionError("down")),
    )
    ctrl._reconcile("default/web01")
    assert ctrl.queue.failures("default/web01") == 1

    monkeypatch.setattr(controller_mod, "reconcile_publication", lambda *_: Result())
    ctrl._reconcile("default/web01")
    assert ctrl.queue.failures("default/web01") == 0


def test_a_deleted_publication_is_dropped_rather_than_retried(monkeypatch):
    kube = _FakeKube({})
    ctrl = _controller(kube)
    monkeypatch.setattr(
        controller_mod, "reconcile_publication",
        lambda *_: pytest.fail("reconciled a publication that no longer exists"),
    )

    ctrl._reconcile("default/gone")
    assert ctrl.queue.get(timeout=0.05) is None


def test_a_reconcile_that_asks_to_be_seen_again_is_requeued_then(monkeypatch):
    kube = _FakeKube({"default/web01": _pub()})
    ctrl = _controller(kube)
    monkeypatch.setattr(
        controller_mod, "reconcile_publication",
        lambda *_: Result(requeue_after=datetime.timedelta(seconds=0.05)),
    )

    ctrl._reconcile("default/web01")
    assert ctrl.queue.get(timeout=1.0) == "default/web01"


def test_a_settled_reconcile_falls_back_to_the_resync_interval(monkeypatch):
    """Drift on a host outside the cluster raises no event; only this finds it."""
    kube = _FakeKube({"default/web01": _pub()})
    ctrl = _controller(kube)
    monkeypatch.setattr(controller_mod, "reconcile_publication", lambda *_: Result())

    ctrl._reconcile("default/web01")
    assert ctrl.queue.get(timeout=0.05) is None  # not immediately
    assert len(ctrl.queue) == 1  # but scheduled


class _WatchedKube(_FakeKube):
    """Delivers each status write back as a watch event, as the apiserver does.

    A status-subresource write still bumps the resourceVersion, so a
    controller watching its own resource hears about every one of its writes.
    """

    def __init__(self, publications):
        super().__init__(publications)
        self.watcher = None

    def patch_publication_status(self, namespace, name, status):
        super().patch_publication_status(namespace, name, status)
        pub = self.publications[f"{namespace}/{name}"]
        self.watcher._handle({"type": "MODIFIED", "object": pub})


def _watched_controller(monkeypatch, outcome):
    kube = _WatchedKube({"default/web01": _pub()})
    ctrl = _controller(kube)
    kube.watcher = ctrl._watchers[0]
    monkeypatch.setattr(controller_mod, "reconcile_publication", outcome)
    # The initial watch delivers the publication once, which is a real reason
    # to reconcile it.
    kube.watcher._handle({"type": "ADDED", "object": kube.publications["default/web01"]})
    assert ctrl.queue.get(timeout=0.05) == "default/web01"
    return kube, ctrl


def _reconcile_as_a_worker_would(ctrl, key):
    ctrl._reconcile(key)
    ctrl.queue.done(key)


def test_writing_status_does_not_trigger_another_reconcile(monkeypatch):
    """Otherwise every reconcile queues the next, and the resync never runs."""
    def _published(kube, pub):
        from cert_publisher.status import set_status
        set_status(kube, pub, PUBLISHED, "Certificate up to date")
        return Result()

    _, ctrl = _watched_controller(monkeypatch, _published)
    _reconcile_as_a_worker_would(ctrl, "default/web01")
    assert ctrl.queue.get(timeout=0.05) is None, "reconciled again off its own status write"


def test_a_failure_status_write_does_not_bypass_the_backoff(monkeypatch):
    """A down host must be retried on the backoff, not hammered in a loop."""
    _, ctrl = _watched_controller(
        monkeypatch, lambda *_: (_ for _ in ()).throw(ConnectionError("down")),
    )
    _reconcile_as_a_worker_would(ctrl, "default/web01")
    assert ctrl.queue.get(timeout=0.05) is None, "retried with no backoff at all"
    assert ctrl.queue.failures("default/web01") == 1


def test_editing_the_spec_still_triggers_a_reconcile(monkeypatch):
    kube, ctrl = _watched_controller(monkeypatch, lambda *_: Result())
    _reconcile_as_a_worker_would(ctrl, "default/web01")

    edited = kube.publications["default/web01"]
    edited["metadata"]["generation"] = 2
    kube.watcher._handle({"type": "MODIFIED", "object": edited})
    assert ctrl.queue.get(timeout=0.05) == "default/web01"


def test_only_the_publications_watcher_seeds_work_on_a_relist():
    ctrl = _controller(_FakeKube({}))
    publications, *owned = ctrl._watchers
    assert publications._on_sync_key == ctrl._enqueue_startup
    assert all(w._on_sync_key == ctrl.queue.add for w in owned)


def test_a_failure_to_read_the_publication_is_retried_not_swallowed():
    class _Unreadable(_FakeKube):
        def get_publication(self, namespace, name):
            raise RuntimeError("apiserver said no")

    ctrl = _controller(_Unreadable({}))
    ctrl._reconcile("default/web01")
    assert ctrl.queue.failures("default/web01") == 1


def test_resyncs_are_scattered_rather_than_synchronised():
    """A fleet issued on the same afternoon must not reconcile in lockstep."""
    kube = _FakeKube({})
    ctrl = Controller(kube, ControllerConfig(resync_seconds=1000.0, resync_jitter=0.5))
    delays = []
    ctrl.queue.add_after = lambda key, delay: delays.append(delay)

    for index in range(50):
        ctrl._enqueue_resync(f"default/web{index}")

    assert len(set(delays)) > 1
    assert all(500.0 <= delay <= 1500.0 for delay in delays)


def test_startup_spreads_the_first_look_at_a_fleet():
    kube = _FakeKube({})
    ctrl = Controller(kube, ControllerConfig(startup_spread_seconds=60.0))
    delays = []
    ctrl.queue.add_after = lambda key, delay: delays.append(delay)

    for index in range(50):
        ctrl._enqueue_startup(f"default/web{index}")

    assert all(0.0 <= delay <= 60.0 for delay in delays)
    assert len(set(delays)) > 1


def test_healthy_until_a_watch_goes_silent():
    kube = _FakeKube({})
    ctrl = _controller(kube, watch_timeout_seconds=10)
    assert ctrl.healthy()  # not started yet

    ctrl._started = True
    assert ctrl.healthy()
    for watcher in ctrl._watchers:
        watcher._last_healthy -= 10_000
    assert not ctrl.healthy()


def test_the_silence_clock_starts_when_the_watchers_do(monkeypatch):
    """Time between building the watchers and starting them is not silence."""
    ctrl = _controller(_FakeKube({}))
    for watcher in ctrl._watchers:
        watcher._last_healthy -= 10_000  # built long ago
        monkeypatch.setattr(watcher, "_run", lambda stop_event: stop_event.wait())

    ctrl.start()
    try:
        assert ctrl.healthy()
    finally:
        ctrl.stop()


def test_ready_only_once_every_watch_has_listed():
    """A missing cert-manager CRD or RBAC grant leaves the pod unready rather
    than running and never hearing about issuances."""
    ctrl = _controller(_FakeKube({}))
    assert not ctrl.ready(), "ready before it had even started"
    ctrl._started = True
    publications, *owned = ctrl._watchers
    publications.synced = True
    assert not ctrl.ready(), "ready with the cert-manager watches never listed"
    for watcher in owned:
        watcher.synced = True
    assert ctrl.ready()


def test_a_wedged_reconcile_fails_liveness():
    """A provisioner call that never returns holds its worker forever. The
    CronJob's activeDeadlineSeconds used to be what noticed; now this is."""
    kube = _FakeKube({})
    ctrl = _controller(kube, reconcile_timeout_seconds=60.0)
    ctrl._started = True

    ctrl._in_flight["worker-0"] = ("default/web01", time.monotonic())
    assert ctrl.healthy(), "a reconcile that has only just started is not wedged"

    ctrl._in_flight["worker-0"] = ("default/web01", time.monotonic() - 3600)
    assert not ctrl.healthy()


def test_stop_reports_a_worker_that_did_not_finish():
    """A False here is a write about to be cut off, and main exits non-zero."""
    kube = _FakeKube({})
    ctrl = _controller(kube, shutdown_timeout_seconds=0.1)
    assert ctrl.stop() is True, "never started, so nothing to drain"

    running, release = threading.Event(), threading.Event()
    thread = threading.Thread(
        target=lambda: (running.set(), release.wait(5)), daemon=True
    )
    thread.start()
    running.wait(1)
    ctrl._started = True
    ctrl._threads.append(thread)
    try:
        assert ctrl.stop() is False
    finally:
        release.set()


def test_an_interrupted_shutdown_names_the_publications_it_cut_off(caplog):
    """The write is lost when the process exits; whoever reads the logs needs
    to know which host to go and look at."""
    ctrl = _controller(_FakeKube({}), shutdown_timeout_seconds=0.1)
    running, release = threading.Event(), threading.Event()
    thread = threading.Thread(
        target=lambda: (running.set(), release.wait(5)),
        name="worker-0", daemon=True,
    )
    thread.start()
    running.wait(1)
    ctrl._started = True
    ctrl._threads.append(thread)
    ctrl._in_flight["worker-0"] = ("default/idrac01", time.monotonic())
    try:
        with caplog.at_level("ERROR", logger="cert-publisher.controller"):
            ctrl.stop()
    finally:
        release.set()
    assert "default/idrac01" in caplog.text


def test_the_worker_survives_a_bug_in_the_controller(monkeypatch):
    """A worker that dies takes every publication behind it with it."""
    kube = _FakeKube({"default/web01": _pub()})
    ctrl = _controller(kube)
    monkeypatch.setattr(
        Controller, "_reconcile",
        lambda self, key: (_ for _ in ()).throw(RuntimeError("bug")),
    )
    ctrl.queue.add("default/web01")
    ctrl._stop_event.clear()

    # One pass of the worker loop, then stop it.
    key = ctrl.queue.get(timeout=0.1)
    try:
        ctrl._reconcile(key)
    except RuntimeError:
        pass
    finally:
        ctrl.queue.done(key)

    # The real loop swallows it; assert the contract it relies on.
    assert ctrl.queue.get(timeout=0.05) is None


def test_published_status_is_reported_not_just_logged(monkeypatch):
    from cert_publisher.status import set_status

    kube = _FakeKube({"default/web01": _pub()})
    ctrl = _controller(kube)

    def _publish(k, pub):
        set_status(k, pub, PUBLISHED, "Certificate published",
                   published_fingerprint="abc", mark_published=True)
        return Result()

    monkeypatch.setattr(controller_mod, "reconcile_publication", _publish)
    ctrl._reconcile("default/web01")

    status = kube.status["default/web01"]
    assert status["phase"] == PUBLISHED
    assert status["publishedFingerprint"] == "abc"
    assert [c["status"] for c in status["conditions"] if c["type"] == "Ready"] == ["True"]
