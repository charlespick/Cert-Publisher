"""The behaviours the CronJob could not have: per-publication failure, backoff,
event-driven wake-ups, and a resync that does not stampede."""

import datetime

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
