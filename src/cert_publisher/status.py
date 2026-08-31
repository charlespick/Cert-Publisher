"""Report reconcile outcomes onto the CertPublication ``.status`` subresource."""

from __future__ import annotations

import datetime
import logging

from .kube import Kube

log = logging.getLogger("cert-publisher.status")

# Phases surfaced on .status.phase (and the Phase printer column).
PENDING = "Pending"  # waiting on cert-manager to issue the certificate
PUBLISHED = "Published"  # target host has the current certificate
ERROR = "Error"  # last reconcile raised


# Distinguishes "caller didn't mention this field" from "caller wants it
# cleared": a merge patch removes a key whose value is null, so None is a
# meaningful value here rather than an absent one.
_UNSET = object()


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def set_status(
    kube: Kube,
    pub: dict,
    phase: str,
    message: str,
    *,
    published_fingerprint: str | None = None,
    mark_published: bool = False,
    pending_request: str | None | object = _UNSET,
    mark_signing: bool = False,
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
    status: dict = {
        "phase": phase,
        "message": message,
        "lastReconcileTime": _now(),
        "observedGeneration": meta.get("generation"),
    }
    if published_fingerprint is not None:
        status["publishedFingerprint"] = published_fingerprint
    if mark_published:
        status["lastPublishedTime"] = _now()
    if pending_request is not _UNSET:
        # None clears the field: the merge patch drops a null-valued key.
        status["pendingRequestName"] = pending_request
    if mark_signing:
        # Stamped when a signing round opens, so a round that never converges
        # is throttled instead of rotating the host's key every reconcile.
        status["lastSigningTime"] = _now()

    try:
        kube.patch_publication_status(meta["namespace"], meta["name"], status)
    except Exception:
        if strict:
            raise
        # Status is best-effort; never fail a reconcile over it.
        log.exception(
            "[%s/%s] failed to update status", meta["namespace"], meta["name"]
        )
