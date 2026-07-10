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


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def set_status(
    kube: Kube,
    pub: dict,
    phase: str,
    message: str,
    *,
    published_fingerprint: str | None = None,
    mark_published: bool = False,
) -> None:
    """Patch ``.status`` for a publication.

    ``lastPublishedTime`` is only advanced when ``mark_published`` is set (an
    actual install happened); a steady-state "up to date" reconcile leaves the
    previous publish timestamp intact via the merge patch.
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

    try:
        kube.patch_publication_status(meta["namespace"], meta["name"], status)
    except Exception:  # status is best-effort; never fail a reconcile over it
        log.exception(
            "[%s/%s] failed to update status", meta["namespace"], meta["name"]
        )
