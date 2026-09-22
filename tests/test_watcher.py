"""The watch loop: what turns "a certificate was issued" into a reconcile."""

import threading
import time

from kubernetes.client.rest import ApiException

from cert_publisher.controller import (
    CERTIFICATES,
    PUBLICATIONS,
    ControllerConfig,
    _Watcher,
)


class _FakeCustom:
    def __init__(self, items=(), version="100"):
        self.items = list(items)
        self.version = version
        self.list_calls = []

    def list_cluster_custom_object(self, group, version, plural, **kwargs):
        self.list_calls.append((plural, kwargs))
        return {"metadata": {"resourceVersion": self.version}, "items": self.items}

    def list_namespaced_custom_object(self, group, version, namespace, plural, **kwargs):
        self.list_calls.append((plural, namespace, kwargs))
        return {"metadata": {"resourceVersion": self.version}, "items": self.items}


class _FakeKube:
    def __init__(self, custom):
        self.custom = custom


def _pub(name):
    return {"metadata": {"name": name, "namespace": "default"}}


def _watcher(resource, custom, keys, sync_keys=None, **config):
    return _Watcher(
        _FakeKube(custom), resource, ControllerConfig(**config),
        on_key=keys.append,
        on_sync_key=(sync_keys if sync_keys is None else sync_keys.append),
    )


def test_syncing_publications_queues_every_one_of_them():
    """A pod that has just won the lease has no idea what happened while
    nobody was leading, so it looks at everything."""
    custom = _FakeCustom([_pub("web01"), _pub("web02")], version="77")
    keys, synced = [], []
    watcher = _watcher(PUBLICATIONS, custom, keys, synced)

    assert watcher._sync() == "77"
    assert synced == ["default/web01", "default/web02"]
    assert keys == []


def test_syncing_an_owned_resource_only_takes_the_version():
    """The publications those objects belong to are already queued, and there
    can be a great many spent CertificateRequests."""
    custom = _FakeCustom([_pub("web01")], version="88")
    keys, synced = [], []
    watcher = _watcher(CERTIFICATES, custom, keys, synced)

    assert watcher._sync() == "88"
    assert synced == [] and keys == []
    assert custom.list_calls[0][1] == {"limit": 1}


def test_a_list_with_no_version_is_an_error_not_a_silent_watch_from_now():
    class _Versionless(_FakeCustom):
        def list_cluster_custom_object(self, *a, **k):
            return {"metadata": {}, "items": []}

    watcher = _watcher(PUBLICATIONS, _Versionless(), [], [])
    try:
        watcher._sync()
    except RuntimeError as exc:
        assert "resourceVersion" in str(exc)
    else:
        raise AssertionError("accepted a list with no resourceVersion")


def test_a_publication_event_queues_that_publication():
    keys = []
    watcher = _watcher(PUBLICATIONS, _FakeCustom(), keys, [])
    watcher._handle({"type": "MODIFIED", "object": _pub("web01")})
    assert keys == ["default/web01"]


def _versioned(name, generation):
    pub = _pub(name)
    pub["metadata"]["generation"] = generation
    return pub


def test_a_status_only_change_to_a_publication_is_ignored():
    """Our own status writes arrive as MODIFIED events; reacting to them would
    make every reconcile queue the next one."""
    custom = _FakeCustom([_versioned("web01", 3)])
    keys = []
    watcher = _watcher(PUBLICATIONS, custom, keys, [])
    watcher._sync()

    watcher._handle({"type": "MODIFIED", "object": _versioned("web01", 3)})
    assert keys == []


def test_a_spec_change_to_a_publication_is_queued():
    custom = _FakeCustom([_versioned("web01", 3)])
    keys = []
    watcher = _watcher(PUBLICATIONS, custom, keys, [])
    watcher._sync()

    watcher._handle({"type": "MODIFIED", "object": _versioned("web01", 4)})
    assert keys == ["default/web01"]


def _signed(name, generation, stamp):
    pub = _versioned(name, generation)
    if stamp:
        pub["status"] = {"lastSigningTime": stamp}
    return pub


def test_clearing_last_signing_time_is_queued_although_it_is_a_status_write():
    """It is the documented way to skip the signing cooldown; dropping it as
    "status only" would leave the publication waiting out the full hour."""
    keys = []
    watcher = _watcher(PUBLICATIONS, _FakeCustom([_signed("idrac01", 1, "t0")]), keys, [])
    watcher._sync()

    watcher._handle({"type": "MODIFIED", "object": _signed("idrac01", 1, None)})
    assert keys == ["default/idrac01"]


def test_our_own_signing_stamp_is_still_filtered():
    """Only the operator sets lastSigningTime, as part of a reconcile that is
    already running; that write must not queue another."""
    keys = []
    watcher = _watcher(PUBLICATIONS, _FakeCustom([_signed("idrac01", 1, None)]), keys, [])
    watcher._sync()

    watcher._handle({"type": "MODIFIED", "object": _signed("idrac01", 1, "t1")})
    watcher._handle({"type": "MODIFIED", "object": _signed("idrac01", 1, "t1")})
    assert keys == []


def test_a_new_publication_and_a_deleted_one_are_both_queued():
    keys = []
    watcher = _watcher(PUBLICATIONS, _FakeCustom(), keys, [])
    watcher._handle({"type": "ADDED", "object": _versioned("web01", 1)})
    watcher._handle({"type": "DELETED", "object": _versioned("web01", 1)})
    # Recreated under the same name: generation starts again at 1.
    watcher._handle({"type": "ADDED", "object": _versioned("web01", 1)})
    assert keys == ["default/web01"] * 3


def test_an_issued_certificate_queues_the_publication_waiting_on_it():
    keys = []
    watcher = _watcher(CERTIFICATES, _FakeCustom(), keys, [])
    watcher._handle({"type": "MODIFIED", "object": {"metadata": {
        "name": "web01", "namespace": "default",
        "ownerReferences": [{
            "apiVersion": "certpublisher.makerland.xyz/v1alpha1",
            "kind": "CertPublication", "name": "web01",
        }],
    }}})
    assert keys == ["default/web01"]


def test_events_carrying_nothing_to_map_are_ignored():
    keys = []
    watcher = _watcher(CERTIFICATES, _FakeCustom(), keys, [])
    watcher._handle({"type": "BOOKMARK", "object": "not-a-dict"})
    watcher._handle({"type": "MODIFIED", "object": {"metadata": {"name": "x"}}})
    assert keys == []


def test_a_scoped_watcher_only_looks_at_its_namespace():
    custom = _FakeCustom()
    watcher = _watcher(PUBLICATIONS, custom, [], [], namespace="certs")
    watcher._sync()
    assert custom.list_calls[0][1] == "certs"


def test_an_expired_watch_relists_immediately_rather_than_backing_off():
    """A 410 is routine -- the apiserver compacted past us -- and the gap it
    leaves should be as short as possible."""
    custom = _FakeCustom([_pub("web01")])
    synced = []
    watcher = _watcher(PUBLICATIONS, custom, [], synced, backoff_base_seconds=30.0)
    stop = threading.Event()

    calls = []

    def _fake_watch_from(resource_version, stop_event):
        calls.append(resource_version)
        if len(calls) == 1:
            raise ApiException(status=410, reason="Gone")
        stop.set()
        return resource_version

    watcher._watch_from = _fake_watch_from
    started = threading.Event()
    thread = threading.Thread(target=lambda: (started.set(), watcher._run(stop)))
    thread.start()
    thread.join(timeout=5)

    assert not thread.is_alive(), "backed off after a 410 instead of relisting"
    assert len(custom.list_calls) == 2, "did not relist after the watch expired"


def test_a_transient_failure_resumes_rather_than_relisting():
    """Only a 410 means the position is gone. Relisting on anything else pays
    for a full list and requeues every publication in the cluster for nothing."""
    custom = _FakeCustom([_pub("web01")], version="55")
    watcher = _watcher(PUBLICATIONS, custom, [], [], backoff_base_seconds=0.01)
    stop = threading.Event()

    seen = []

    def _fake_watch_from(resource_version, stop_event):
        seen.append(resource_version)
        if len(seen) == 1:
            raise ApiException(status=500, reason="Internal Server Error")
        stop.set()
        return resource_version

    watcher._watch_from = _fake_watch_from
    thread = threading.Thread(target=watcher._run, args=(stop,), daemon=True)
    thread.start()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert seen == ["55", "55"], "did not resume from the last known position"
    assert len(custom.list_calls) == 1, "relisted after a transient failure"


def test_a_watch_that_keeps_failing_is_not_reported_as_hung():
    """A restart does not fix missing RBAC or a missing CRD; it only interrupts
    every publication that is working. Liveness is for a loop that hangs."""
    custom = _FakeCustom()
    watcher = _watcher(PUBLICATIONS, custom, [], [], backoff_base_seconds=30.0)
    watcher._last_healthy -= 10_000
    stop = threading.Event()

    def _fake_watch_from(resource_version, stop_event):
        raise ApiException(status=403, reason="Forbidden")

    watcher._watch_from = _fake_watch_from
    thread = threading.Thread(target=watcher._run, args=(stop,), daemon=True)
    thread.start()
    thread.join(timeout=0.5)

    # Counted alive through the backoff it chose to wait out.
    assert watcher.last_healthy > time.monotonic() + 20
    stop.set()
    thread.join(timeout=5)


def test_a_broken_watch_backs_off_before_reconnecting():
    """A watch the apiserver keeps rejecting -- missing RBAC, a missing CRD --
    must not become a hot loop against it."""
    custom = _FakeCustom()
    watcher = _watcher(PUBLICATIONS, custom, [], [], backoff_base_seconds=30.0)
    stop = threading.Event()

    def _fake_watch_from(resource_version, stop_event):
        raise ApiException(status=403, reason="Forbidden")

    watcher._watch_from = _fake_watch_from
    thread = threading.Thread(target=watcher._run, args=(stop,), daemon=True)
    thread.start()
    thread.join(timeout=1.0)

    assert thread.is_alive(), "reconnected without waiting"
    assert len(custom.list_calls) == 1
    stop.set()
    thread.join(timeout=5)
