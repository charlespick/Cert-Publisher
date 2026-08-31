"""Translate a CertPublication into a cert-manager Certificate."""

from __future__ import annotations

import base64

from .kube import CM_GROUP, CM_VERSION, GROUP, VERSION

# Fields we pass straight through from the CertPublication spec to the
# cert-manager Certificate spec when present.
_PASSTHROUGH = ("commonName", "duration", "renewBefore", "usages", "privateKey")


def _owner_reference(pub: dict) -> dict:
    meta = pub["metadata"]
    return {
        "apiVersion": f"{GROUP}/{VERSION}",
        "kind": "CertPublication",
        "name": meta["name"],
        "uid": meta["uid"],
        "controller": True,
        "blockOwnerDeletion": True,
    }


def build_certificate_spec(pub: dict, secret_name: str) -> dict:
    """Build the cert-manager Certificate ``spec`` a CertPublication maps to."""
    spec = pub["spec"]

    cert_spec: dict = {
        "secretName": secret_name,
        "dnsNames": spec["dnsNames"],
        "issuerRef": spec["issuerRef"],
    }
    for key in _PASSTHROUGH:
        if key in spec:
            cert_spec[key] = spec[key]
    return cert_spec


def build_certificate_body(pub: dict, secret_name: str) -> dict:
    """Build the cert-manager Certificate object for a CertPublication.

    The Certificate is named after the publication and owned by it, so it is
    garbage collected when the publication is deleted. cert-manager itself owns
    the renewal/rotation policy via ``issuerRef``/``duration``/``renewBefore``.
    """
    meta = pub["metadata"]

    return {
        "apiVersion": f"{CM_GROUP}/{CM_VERSION}",
        "kind": "Certificate",
        "metadata": {
            "name": meta["name"],
            "namespace": meta["namespace"],
            "ownerReferences": [_owner_reference(pub)],
        },
        "spec": build_certificate_spec(pub, secret_name),
    }


def certificate_spec_drift(existing: dict, pub: dict, secret_name: str) -> dict | None:
    """Return the desired spec if the existing Certificate is out of date.

    Only the fields this operator manages are compared, so cert-manager's own
    defaulting (and any fields it adds) never registers as drift. Returns
    ``None`` when the existing Certificate already matches the publication.
    """
    desired = build_certificate_spec(pub, secret_name)
    current = existing.get("spec") or {}
    if all(current.get(key) == value for key, value in desired.items()):
        return None
    return desired


def build_certificate_request_body(pub: dict, name: str, csr_pem: bytes) -> dict:
    """Build a cert-manager CertificateRequest that signs a host-generated CSR.

    Used for provisioners whose target keeps its own private key. Only fields
    cert-manager accepts on a CertificateRequest are set -- notably not
    ``renewBefore``, which has no meaning here: a CertificateRequest is signed
    once and never renewed, so renewal timing is the reconciler's job.

    The request is owned by the publication so it is garbage collected with it.
    """
    meta = pub["metadata"]
    spec = pub["spec"]

    request_spec: dict = {
        "request": base64.b64encode(csr_pem).decode(),
        "issuerRef": spec["issuerRef"],
        "isCA": False,
    }
    for key in ("duration", "usages"):
        if key in spec:
            request_spec[key] = spec[key]

    return {
        "apiVersion": f"{CM_GROUP}/{CM_VERSION}",
        "kind": "CertificateRequest",
        "metadata": {
            "name": name,
            "namespace": meta["namespace"],
            "ownerReferences": [_owner_reference(pub)],
        },
        "spec": request_spec,
    }


# CertificateRequest outcomes, as reported by certificate_request_state().
CR_READY = "ready"
CR_PENDING = "pending"
CR_FAILED = "failed"


def certificate_request_state(request: dict) -> tuple[str, str]:
    """Classify a CertificateRequest as ready, still pending, or failed.

    Returns the state and a human-readable reason for the publication status.
    A failed request is terminal: its spec is immutable, so the reconciler has
    to delete it and generate a fresh CSR rather than wait.
    """
    conditions = (request.get("status") or {}).get("conditions") or []
    by_type = {c.get("type"): c for c in conditions}

    for terminal in ("Denied", "InvalidRequest"):
        condition = by_type.get(terminal)
        if condition and condition.get("status") == "True":
            return CR_FAILED, f"{terminal}: {condition.get('message') or 'no detail'}"

    ready = by_type.get("Ready")
    if ready is None:
        return CR_PENDING, "awaiting cert-manager"
    if ready.get("status") == "True":
        return CR_READY, ready.get("message") or "issued"
    if ready.get("reason") == "Failed":
        return CR_FAILED, f"Failed: {ready.get('message') or 'no detail'}"
    return CR_PENDING, ready.get("message") or "awaiting issuance"


def issued_certificate(request: dict) -> bytes:
    """The signed certificate from a ready CertificateRequest."""
    encoded = (request.get("status") or {}).get("certificate")
    if not encoded:
        raise ValueError("CertificateRequest is ready but carries no certificate")
    return base64.b64decode(encoded)
