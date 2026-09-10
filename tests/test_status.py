"""Status is the operator's only output, so it has to carry the whole story."""

from cert_publisher.status import (
    ERROR,
    PENDING,
    PUBLISHED,
    REASON_MISCONFIGURED,
    set_status,
)


class _FakeKube:
    def __init__(self):
        self.patched = []
        self.recorded = []

    def patch_publication_status(self, namespace, name, status):
        self.patched.append(status)

    def record_event(self, pub, event_type, reason, message):
        self.recorded.append((event_type, reason, message))


def _pub():
    return {"metadata": {"name": "web01", "namespace": "default", "generation": 3,
                         "uid": "u-1"}}


def _ready(status):
    return next(c for c in status["conditions"] if c["type"] == "Ready")


def test_a_published_publication_is_ready():
    kube, pub = _FakeKube(), _pub()
    set_status(kube, pub, PUBLISHED, "Certificate published",
               published_fingerprint="abc", mark_published=True)

    condition = _ready(kube.patched[-1])
    assert condition["status"] == "True"
    assert condition["reason"] == "Published"
    assert condition["observedGeneration"] == 3


def test_anything_else_is_not_ready_and_says_why():
    kube, pub = _FakeKube(), _pub()
    set_status(kube, pub, ERROR, "renewBefore is longer than the lifetime",
               reason=REASON_MISCONFIGURED)

    condition = _ready(kube.patched[-1])
    assert condition["status"] == "False"
    assert condition["reason"] == REASON_MISCONFIGURED
    assert kube.patched[-1]["reason"] == REASON_MISCONFIGURED


def test_the_transition_time_does_not_move_while_the_answer_is_unchanged():
    """It marks when the publication became ready; a resync must not reset it."""
    kube, pub = _FakeKube(), _pub()
    set_status(kube, pub, PUBLISHED, "Certificate published")
    first = _ready(kube.patched[-1])["lastTransitionTime"]

    set_status(kube, pub, PUBLISHED, "Certificate up to date")
    assert _ready(kube.patched[-1])["lastTransitionTime"] == first


def test_the_transition_time_moves_when_readiness_flips():
    kube, pub = _FakeKube(), _pub()
    set_status(kube, pub, PUBLISHED, "Certificate published")
    set_status(kube, pub, ERROR, "host unreachable")

    assert _ready(kube.patched[-1])["status"] == "False"


def test_conditions_we_do_not_own_are_left_alone():
    kube, pub = _FakeKube(), _pub()
    pub["status"] = {"conditions": [
        {"type": "SomebodyElses", "status": "True", "reason": "R", "message": "m",
         "lastTransitionTime": "2020-01-01T00:00:00Z"},
    ]}
    set_status(kube, pub, PUBLISHED, "Certificate published")

    types = {c["type"] for c in kube.patched[-1]["conditions"]}
    assert types == {"SomebodyElses", "Ready"}


def test_an_event_is_recorded_when_the_outcome_changes():
    kube, pub = _FakeKube(), _pub()
    set_status(kube, pub, PENDING, "Awaiting certificate issuance")
    set_status(kube, pub, PUBLISHED, "Certificate published")

    assert [reason for _, reason, _ in kube.recorded] == [
        "AwaitingIssuance", "Published",
    ]


def test_no_event_is_recorded_when_nothing_changed():
    """Otherwise every publication emits one on every resync, forever."""
    kube, pub = _FakeKube(), _pub()
    set_status(kube, pub, PUBLISHED, "Certificate up to date")
    set_status(kube, pub, PUBLISHED, "Certificate up to date")
    set_status(kube, pub, PUBLISHED, "Certificate up to date")

    assert len(kube.recorded) == 1


def test_a_failure_is_a_warning_event():
    kube, pub = _FakeKube(), _pub()
    set_status(kube, pub, ERROR, "host unreachable")
    assert kube.recorded[-1][0] == "Warning"


def test_the_retry_time_is_cleared_by_the_next_outcome():
    """A stale "retrying at" on a publication that has since succeeded would
    be worse than none at all."""
    kube, pub = _FakeKube(), _pub()
    set_status(kube, pub, ERROR, "host unreachable",
               next_retry="2026-01-01T00:00:00Z")
    assert kube.patched[-1]["nextRetryTime"] == "2026-01-01T00:00:00Z"
    assert pub["status"]["nextRetryTime"] == "2026-01-01T00:00:00Z"

    set_status(kube, pub, PUBLISHED, "Certificate published")
    assert kube.patched[-1]["nextRetryTime"] is None
    assert "nextRetryTime" not in pub["status"]


def test_a_failed_status_write_does_not_fail_the_reconcile():
    class _Broken(_FakeKube):
        def patch_publication_status(self, namespace, name, status):
            raise RuntimeError("apiserver said no")

    set_status(_Broken(), _pub(), PUBLISHED, "Certificate published")


def test_a_failed_status_write_records_no_event():
    class _Broken(_FakeKube):
        def patch_publication_status(self, namespace, name, status):
            raise RuntimeError("apiserver said no")

    kube = _Broken()
    set_status(kube, _pub(), PUBLISHED, "Certificate published")
    assert kube.recorded == []
