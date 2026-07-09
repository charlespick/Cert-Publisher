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


def build_certificate_body(pub: dict, secret_name: str) -> dict:
    """Build the cert-manager Certificate object for a CertPublication.

    The Certificate is named after the publication and owned by it, so it is
    garbage collected when the publication is deleted. cert-manager itself owns
    the renewal/rotation policy via ``issuerRef``/``duration``/``renewBefore``.
    """
    meta = pub["metadata"]
    spec = pub["spec"]

    cert_spec: dict = {
        "secretName": secret_name,
        "dnsNames": spec["dnsNames"],
        "issuerRef": spec["issuerRef"],
    }
    for key in _PASSTHROUGH:
        if key in spec:
            cert_spec[key] = spec[key]

    return {
        "apiVersion": f"{CM_GROUP}/{CM_VERSION}",
        "kind": "Certificate",
        "metadata": {
            "name": meta["name"],
            "namespace": meta["namespace"],
            "ownerReferences": [_owner_reference(pub)],
        },
        "spec": cert_spec,
    }
