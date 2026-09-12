"""Report reconcile outcomes onto the CertPublication ``.status`` subresource.

Status is the operator's only output. A CronJob could get away with failing the
pod and letting the operator read the logs; a controller that never exits
cannot, so every outcome -- success, "still waiting", and each distinct kind of
failure -- has to be legible from ``kubectl get`` and ``kubectl describe``
alone. That means three things are written together:

* the ``phase``/``message`` pair the printer columns and humans read;
* a standard ``Ready`` entry in ``.status.conditions``, with a machine-readable
  ``reason`` and a ``lastTransitionTime`` that only moves when the answer
  actually changes, so it can be waited on (``kubectl wait --for=condition=Ready``)
  and alerted on;
* an Event, but only when the answer changed, so a publication reconciled every
  half hour for a year does not bury its one interesting transition.
"""

from __future__ import annotations

import logging

from .kube import Kube
from .utils import now_rfc3339

log = logging.getLogger("cert-publisher.status")

# Phases surfaced on .status.phase (and the Phase printer column).
PENDING = "Pending"  # waiting on cert-manager to issue the certificate
PUBLISHED = "Published"  # target host has the current certificate
ERROR = "Error"  # last reconcile raised

# The condition type this operator owns. "Ready" is the conventional name for
# "the thing this resource asks for is in effect".
READY = "Ready"

# Machine-readable condition reasons. These are API surface: alerts and
# `kubectl wait` select on them, so they change only with the same care as a
# field name.
REASON_PUBLISHED = "Published"
REASON_AWAITING_ISSUANCE = "AwaitingIssuance"
REASON_SIGNING_PENDING = "SigningRequestPending"
REASON_SIGNING_FAILED = "SigningRequestFailed"
REASON_SIGNING_NOT_SIGNED = "SigningRequestNotSigned"
REASON_SIGNING_COOLDOWN = "SigningCooldown"
REASON_UNUSABLE_CERTIFICATE = "UnusableCertificate"
REASON_MISCONFIGURED = "Misconfigured"
REASON_RECONCILE_ERROR = "ReconcileError"

_DEFAULT_REASONS = {
    PUBLISHED: REASON_PUBLISHED,
    PENDING: REASON_AWAITING_ISSUANCE,
    ERROR: REASON_RECONCILE_ERROR,
}

# The apiserver rejects a condition message longer than this.
_MAX_MESSAGE = 32 * 1024


# Distinguishes "caller didn't mention this field" from "caller wants it
# cleared": a merge patch removes a key whose value is null, so None is a
# meaningful value here rather than an absent one.
_UNSET = object()


def _ready_condition(pub: dict, phase: str, reason: str, message: str) -> dict:
    """The ``Ready`` condition for this outcome, merged onto the current one.

    ``lastTransitionTime`` is carried over while the answer is unchanged: it
    marks when the publication *became* ready or unready, which is the whole
    point of the field, so a reconcile that confirms the status quo must not
    move it.
    """
    current = (pub.get("status") or {}).get("conditions") or []
    existing = next((c for c in current if c.get("type") == READY), None)

    state = "True" if phase == PUBLISHED else "False"
    if existing and existing.get("status") == state:
        transitioned = existing.get("lastTransitionTime") or now_rfc3339()
    else:
        transitioned = now_rfc3339()

    condition = {
        "type": READY,
        "status": state,
        "reason": reason,
        "message": message[:_MAX_MESSAGE],
        "lastTransitionTime": transitioned,
    }
    generation = pub["metadata"].get("generation")
    if generation is not None:
        condition["observedGeneration"] = generation
    return condition


def _conditions(pub: dict, condition: dict) -> list[dict]:
    """The full conditions list to write, preserving any we do not own."""
    current = (pub.get("status") or {}).get("conditions") or []
    return [c for c in current if c.get("type") != READY] + [condition]


def set_status(
    kube: Kube,
    pub: dict,
    phase: str,
    message: str,
    *,
    reason: str | None = None,
    published_fingerprint: str | None = None,
    mark_published: bool = False,
    pending_request: str | None | object = _UNSET,
    mark_signing: bool = False,
    next_retry: str | None = None,
    strict: bool = False,
) -> None:
    """Patch ``.status`` for a publication.

    ``lastPublishedTime`` is only advanced when ``mark_published`` is set (an
    actual install happened); a steady-state "up to date" reconcile leaves the
    previous publish timestamp intact via the merge patch.

    Status is best-effort by default: reporting an outcome must never be the
    thing that fails a reconcile. ``strict`` inverts that for the one caller
    whose *next* step depends on the write having landed.
    """
    meta = pub["metadata"]
    reason = reason or _DEFAULT_REASONS.get(phase, phase)
    previous = pub.get("status") or {}

    condition = _ready_condition(pub, phase, reason, message)
    status: dict = {
        "phase": phase,
        "message": message,
        "reason": reason,
        "lastReconcileTime": now_rfc3339(),
        "observedGeneration": meta.get("generation"),
        # A merge patch replaces a list wholesale, so the full set is written
        # every time rather than the one entry that changed.
        "conditions": _conditions(pub, condition),
    }
    if published_fingerprint is not None:
        status["publishedFingerprint"] = published_fingerprint
    if mark_published:
        status["lastPublishedTime"] = now_rfc3339()
    if pending_request is not _UNSET:
        # None clears the field: the merge patch drops a null-valued key.
        status["pendingRequestName"] = pending_request
    if mark_signing:
        # Stamped when a signing round opens, so a round that never converges
        # is throttled instead of rotating the host's key every reconcile.
        status["lastSigningTime"] = now_rfc3339()
    # Always written, so it is cleared by any outcome that did not schedule a
    # retry: a stale "retrying at" on a publication that has since succeeded
    # would be worse than none at all.
    status["nextRetryTime"] = next_retry

    try:
        kube.patch_publication_status(meta["namespace"], meta["name"], status)
    except Exception:
        if strict:
            raise
        # Status is best-effort; never fail a reconcile over it.
        log.exception(
            "[%s/%s] failed to update status", meta["namespace"], meta["name"]
        )
        return

    # Keep the in-memory copy in step so a later write in the same reconcile
    # compares against what is actually stored, applying the same merge-patch
    # rules the apiserver just did: a null drops the key rather than setting it.
    merged = dict(previous)
    for key, value in status.items():
        if value is None:
            merged.pop(key, None)
        else:
            merged[key] = value
    pub["status"] = merged

    _record_transition(kube, pub, previous, phase, reason, message)


def _record_transition(
    kube: Kube, pub: dict, previous: dict, phase: str, reason: str, message: str
) -> None:
    """Emit an Event, but only when this outcome differs from the last one.

    Without the guard every publication would emit an Event on every resync
    forever, which is both noise in ``kubectl describe`` and load on etcd.
    """
    if (previous.get("phase"), previous.get("reason")) == (phase, reason):
        return
    kube.record_event(
        pub,
        "Normal" if phase != ERROR else "Warning",
        reason,
        message,
    )
