"""Leader election: two replicas must never publish to the same host at once."""

import datetime
import threading

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
        # Every call's _request_timeout, so a call that could block forever is
        # visible to the tests rather than only to a partitioned cluster.
        self.timeouts: list[float | None] = []

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

    def read_namespaced_lease(self, name, namespace, **kwargs):
        self.timeouts.append(kwargs.get("_request_timeout"))
        lease = self.store.get((namespace, name))
        if lease is None:
            raise ApiException(status=404, reason="Not Found")
        return lease

    def create_namespaced_lease(self, namespace, body, **kwargs):
        self.timeouts.append(kwargs.get("_request_timeout"))
        key = (namespace, body["metadata"]["name"])
        if key in self.store:
            raise ApiException(status=409, reason="Conflict")
        self.store[key] = self._model(namespace, body)
        return self.store[key]

    def replace_namespaced_lease(self, name, namespace, body, **kwargs):
        self.timeouts.append(kwargs.get("_request_timeout"))
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


def test_an_unfinished_publish_keeps_the_lease_rather_than_handing_it_over():
    """A worker still talking to a host is exactly who a standby must not race,
    so the lease is left to expire instead of released."""
    api = _FakeLeases()
    holder = _elector(api, "pod-a")
    stop = threading.Event()

    holder.run(
        on_started_leading=stop.set,  # win, then immediately shut down
        on_stopped_leading=lambda: False,  # ...with a publish still in flight
        stop_event=stop,
    )

    assert _held_by(api) == "pod-a", "handed over while a host was being written to"


def test_a_drained_shutdown_still_hands_over_immediately():
    api = _FakeLeases()
    holder = _elector(api, "pod-a")
    stop = threading.Event()

    holder.run(
        on_started_leading=stop.set,
        on_stopped_leading=lambda: True,
        stop_event=stop,
    )

    assert _held_by(api) is None


def test_reachable_is_reported_once_the_lease_has_been_read():
    """Readiness waits for this, so a pod that cannot reach the apiserver
    does not pass it and let a rollout replace a working pod."""
    api = _FakeLeases()
    _elector(api, "pod-a").try_acquire_or_renew()  # someone else leads
    calls = []
    stop = threading.Event()

    standby = _elector(api, "pod-b")
    original = standby.try_acquire_or_renew

    def _once_then_stop(**kwargs):
        result = original(**kwargs)
        stop.set()
        return result

    standby.try_acquire_or_renew = _once_then_stop
    standby.run(
        on_started_leading=lambda: pytest.fail("stole a live lease"),
        on_stopped_leading=lambda: True,
        stop_event=stop,
        on_reachable=lambda: calls.append("reachable"),
    )
    assert calls == ["reachable"]


def test_an_unreachable_apiserver_is_never_reported_reachable():
    class _Down(_FakeLeases):
        def read_namespaced_lease(self, name, namespace, **kwargs):
            raise ApiException(status=403, reason="Forbidden")

    calls = []
    stop = threading.Event()
    elector = _elector(_Down(), "pod-a")
    original = elector.try_acquire_or_renew

    def _once_then_stop(**kwargs):
        result = original(**kwargs)
        stop.set()
        return result

    elector.try_acquire_or_renew = _once_then_stop
    elector.run(
        on_started_leading=lambda: None,
        on_stopped_leading=lambda: True,
        stop_event=stop,
        on_reachable=lambda: calls.append("reachable"),
    )
    assert calls == []


# -- bounded calls --------------------------------------------------------


def test_every_lease_call_carries_a_request_timeout():
    """An unbounded renewal can block past the deadline that would have raised
    LeadershipLost, leaving this replica sure it leads while a standby leads."""
    api = _FakeLeases()
    holder = _elector(api, "pod-a")
    holder.try_acquire_or_renew()  # read (404) + create
    holder.try_acquire_or_renew()  # read + replace
    holder.release()

    assert api.timeouts, "no Lease call was made"
    assert all(timeout == 10.0 for timeout in api.timeouts), api.timeouts


class _ClockedStop:
    """A stop event that is never set, whose waits pass on a fake clock."""

    def __init__(self, clock):
        self._clock = clock

    def is_set(self):
        return False

    def wait(self, timeout):
        self._clock[0] += timeout
        return False


def test_a_blocked_renewal_gives_up_within_the_renew_deadline(monkeypatch):
    """A read and a write that each hang for a full request timeout must not
    add up to twice the deadline: a standby may take over 15s after the last
    renewal it saw, so the holder has to know it has lost within 10s."""
    clock = [1000.0]
    monkeypatch.setattr(leader_mod.time, "monotonic", lambda: clock[0])
    api = _FakeLeases()
    holder = _elector(api, "pod-a")
    assert holder.try_acquire_or_renew() is True
    renewed = clock[0]

    class _Degraded(_FakeLeases):
        """Reads crawl in just under their timeout; writes never return."""

        def read_namespaced_lease(self, name, namespace, **kwargs):
            lease = super().read_namespaced_lease(name, namespace, **kwargs)
            clock[0] += kwargs["_request_timeout"] * 0.99
            return lease

        def replace_namespaced_lease(self, name, namespace, body, **kwargs):
            self.timeouts.append(kwargs.get("_request_timeout"))
            clock[0] += kwargs["_request_timeout"]
            raise TimeoutError("read timed out")

    degraded = _Degraded()
    degraded.store, degraded.version = api.store, api.version
    holder._api = degraded
    with pytest.raises(leader_mod.LeadershipLost):
        holder._hold(_ClockedStop(clock))

    assert clock[0] - renewed <= 10.0, (
        f"believed it led for {clock[0] - renewed:.1f}s after its last renewal"
    )
    assert all(0 < timeout <= 10.0 for timeout in holder._api.timeouts)


def test_a_slow_read_leaves_the_write_only_what_is_left(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(leader_mod.time, "monotonic", lambda: clock[0])

    class _SlowRead(_FakeLeases):
        def read_namespaced_lease(self, name, namespace, **kwargs):
            lease = super().read_namespaced_lease(name, namespace, **kwargs)
            clock[0] += 7.0
            return lease

    api = _SlowRead()
    holder = _elector(api, "pod-a")
    holder.try_acquire_or_renew()  # read (404) + create
    api.timeouts.clear()

    assert holder.try_acquire_or_renew(deadline=clock[0] + 10.0) is True
    assert api.timeouts == [10.0, 3.0]


def test_an_attempt_with_no_time_left_does_not_call_the_apiserver(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(leader_mod.time, "monotonic", lambda: clock[0])
    api = _FakeLeases()
    holder = _elector(api, "pod-a")
    holder.try_acquire_or_renew()
    api.timeouts.clear()

    assert holder.try_acquire_or_renew(deadline=clock[0]) is False
    assert api.timeouts == []


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
