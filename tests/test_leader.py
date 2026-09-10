"""Leader election: two replicas must never publish to the same host at once."""

import datetime

import pytest
from kubernetes.client import V1Lease, V1LeaseSpec, V1ObjectMeta
from kubernetes.client.rest import ApiException

from cert_publisher import leader as leader_mod
from cert_publisher.leader import LeaderElector, _micro_time


class _FakeLeases:
    """Enough of CoordinationV1Api to exercise the real acquire/renew rules."""

    def __init__(self):
        self.store: dict[tuple[str, str], V1Lease] = {}
        self.version = 0

    def _model(self, namespace, body) -> V1Lease:
        spec = body["spec"]
        self.version += 1
        return V1Lease(
            metadata=V1ObjectMeta(
                name=body["metadata"]["name"], namespace=namespace,
                resource_version=str(self.version),
            ),
            spec=V1LeaseSpec(
                holder_identity=spec["holderIdentity"],
                lease_duration_seconds=spec["leaseDurationSeconds"],
                acquire_time=_parse(spec["acquireTime"]),
                renew_time=_parse(spec["renewTime"]),
                lease_transitions=spec["leaseTransitions"],
            ),
        )

    def read_namespaced_lease(self, name, namespace):
        lease = self.store.get((namespace, name))
        if lease is None:
            raise ApiException(status=404, reason="Not Found")
        return lease

    def create_namespaced_lease(self, namespace, body):
        key = (namespace, body["metadata"]["name"])
        if key in self.store:
            raise ApiException(status=409, reason="Conflict")
        self.store[key] = self._model(namespace, body)
        return self.store[key]

    def replace_namespaced_lease(self, name, namespace, body):
        key = (namespace, name)
        current = self.store.get(key)
        if current is None:
            raise ApiException(status=404, reason="Not Found")
        if body["metadata"]["resourceVersion"] != current.metadata.resource_version:
            raise ApiException(status=409, reason="Conflict")
        self.store[key] = self._model(namespace, body)
        return self.store[key]


def _parse(value):
    if value is None:
        return None
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=datetime.UTC
    )


def _elector(api, identity, **kwargs):
    return LeaderElector(
        api, name="cert-publisher", namespace="cert-publisher",
        identity=identity, lease_duration=15.0, renew_deadline=10.0,
        retry_period=2.0, **kwargs,
    )


def _held_by(api):
    return api.store[("cert-publisher", "cert-publisher")].spec.holder_identity


# -- timestamps -----------------------------------------------------------


def test_micro_time_always_carries_six_fractional_digits():
    """The apiserver parses MicroTime with a layout that demands exactly six.

    datetime.isoformat() drops the fraction when it is zero, which would fail
    one renewal in a million -- silently, and as a lost leadership.
    """
    exact = datetime.datetime(2026, 1, 2, 3, 4, 5, 0, tzinfo=datetime.UTC)
    assert _micro_time(exact) == "2026-01-02T03:04:05.000000Z"
    assert _micro_time(None) is None


def test_micro_time_normalises_to_utc():
    other = datetime.timezone(datetime.timedelta(hours=5))
    when = datetime.datetime(2026, 1, 2, 8, 4, 5, 7, tzinfo=other)
    assert _micro_time(when) == "2026-01-02T03:04:05.000007Z"


# -- acquire / renew ------------------------------------------------------


def test_the_first_candidate_creates_the_lease_and_wins():
    api = _FakeLeases()
    assert _elector(api, "pod-a").try_acquire_or_renew() is True
    assert _held_by(api) == "pod-a"


def test_a_second_candidate_does_not_steal_a_live_lease():
    api = _FakeLeases()
    _elector(api, "pod-a").try_acquire_or_renew()

    challenger = _elector(api, "pod-b")
    assert challenger.try_acquire_or_renew() is False
    assert _held_by(api) == "pod-a"


def test_a_candidate_waits_a_full_lease_duration_before_stealing(monkeypatch):
    """Expiry is judged from when *we* saw the record, not from its timestamp."""
    api = _FakeLeases()
    _elector(api, "pod-a").try_acquire_or_renew()

    clock = [1000.0]
    monkeypatch.setattr(leader_mod.time, "monotonic", lambda: clock[0])
    challenger = _elector(api, "pod-b")

    assert challenger.try_acquire_or_renew() is False  # first sighting
    clock[0] += 14.0
    assert challenger.try_acquire_or_renew() is False  # not yet expired
    clock[0] += 2.0
    assert challenger.try_acquire_or_renew() is True
    assert _held_by(api) == "pod-b"


def test_taking_over_counts_a_transition(monkeypatch):
    api = _FakeLeases()
    _elector(api, "pod-a").try_acquire_or_renew()

    clock = [1000.0]
    monkeypatch.setattr(leader_mod.time, "monotonic", lambda: clock[0])
    challenger = _elector(api, "pod-b")
    challenger.try_acquire_or_renew()
    clock[0] += 30.0
    challenger.try_acquire_or_renew()

    lease = api.store[("cert-publisher", "cert-publisher")]
    assert lease.spec.lease_transitions == 1


def test_renewing_keeps_the_original_acquire_time():
    api = _FakeLeases()
    holder = _elector(api, "pod-a")
    holder.try_acquire_or_renew()
    acquired = api.store[("cert-publisher", "cert-publisher")].spec.acquire_time

    holder.try_acquire_or_renew()
    lease = api.store[("cert-publisher", "cert-publisher")]
    assert lease.spec.acquire_time == acquired
    assert lease.spec.lease_transitions == 0


def test_losing_the_write_race_is_not_winning_the_lease(monkeypatch):
    """Two candidates that both see an expired lease: only one may come away
    believing it holds it."""
    api = _FakeLeases()
    _elector(api, "pod-a").try_acquire_or_renew()

    clock = [1000.0]
    monkeypatch.setattr(leader_mod.time, "monotonic", lambda: clock[0])
    b, c = _elector(api, "pod-b"), _elector(api, "pod-c")
    b.try_acquire_or_renew()
    c.try_acquire_or_renew()
    clock[0] += 30.0

    assert b.try_acquire_or_renew() is True
    # c is still holding the resourceVersion it read before b's write.
    assert c.try_acquire_or_renew() is False
    assert _held_by(api) == "pod-b"


def test_an_unreachable_apiserver_is_not_leadership():
    class _Down(_FakeLeases):
        def read_namespaced_lease(self, name, namespace):
            raise ApiException(status=500, reason="Internal Server Error")

    assert _elector(_Down(), "pod-a").try_acquire_or_renew() is False


# -- release --------------------------------------------------------------


def test_a_clean_shutdown_releases_the_lease():
    """A rolling update should hand over in about a second, not a full lease."""
    api = _FakeLeases()
    holder = _elector(api, "pod-a")
    holder.try_acquire_or_renew()

    holder.release()
    lease = api.store[("cert-publisher", "cert-publisher")]
    assert lease.spec.holder_identity is None
    assert lease.spec.lease_duration_seconds == 1


def test_releasing_a_lease_someone_else_now_holds_is_a_no_op(monkeypatch):
    api = _FakeLeases()
    former = _elector(api, "pod-a")
    former.try_acquire_or_renew()

    clock = [1000.0]
    monkeypatch.setattr(leader_mod.time, "monotonic", lambda: clock[0])
    successor = _elector(api, "pod-b")
    successor.try_acquire_or_renew()
    clock[0] += 30.0
    successor.try_acquire_or_renew()

    former.release()
    assert _held_by(api) == "pod-b"


# -- configuration --------------------------------------------------------


def test_timings_that_could_let_two_replicas_lead_are_refused():
    api = _FakeLeases()
    with pytest.raises(ValueError, match="leaseDuration"):
        _LeaderElector = LeaderElector
        _LeaderElector(api, name="n", namespace="ns", identity="i",
                       lease_duration=10.0, renew_deadline=10.0, retry_period=2.0)
    with pytest.raises(ValueError, match="renewDeadline"):
        LeaderElector(api, name="n", namespace="ns", identity="i",
                      lease_duration=15.0, renew_deadline=2.0, retry_period=2.0)
