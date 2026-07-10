"""Translate a CertPublication into a cert-manager Certificate."""

from __future__ import annotations

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
