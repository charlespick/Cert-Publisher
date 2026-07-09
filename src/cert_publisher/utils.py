"""Certificate parsing and fingerprint helpers."""

from __future__ import annotations

import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes

_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def leaf_pem(pem: bytes) -> bytes:
    """Return the first (leaf) certificate block from a PEM bundle.

    cert-manager stores ``tls.crt`` as the leaf followed by the issuing chain;
    for identity comparisons we only care about the leaf.
    """
    match = _CERT_RE.search(pem)
    if not match:
        raise ValueError("no certificate found in PEM data")
    return match.group(0)


def leaf_certificate(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(leaf_pem(pem))


def sha256_fingerprint(pem: bytes) -> str:
    """Lowercase hex SHA-256 fingerprint of the leaf certificate."""
    return leaf_certificate(pem).fingerprint(hashes.SHA256()).hex()


def sha1_thumbprint(pem: bytes) -> str:
    """Uppercase hex SHA-1 thumbprint (the form Windows uses in Cert:\\ stores)."""
    return leaf_certificate(pem).fingerprint(hashes.SHA1()).hex().upper()
