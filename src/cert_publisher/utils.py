"""Certificate parsing and fingerprint helpers."""

from __future__ import annotations

import datetime
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


_GO_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)([hms])")

# cert-manager renews once a certificate is this far through its lifetime when
# the publication doesn't say otherwise, matching cert-manager's own default of
# renewing at two thirds of the duration.
_DEFAULT_RENEW_FRACTION = 1 / 3


def parse_go_duration(value: str) -> datetime.timedelta:
    """Parse the Go duration strings cert-manager uses (e.g. ``"2160h"``).

    Only the hour/minute/second units cert-manager accepts on ``duration`` and
    ``renewBefore`` are supported; anything else is rejected rather than
    silently treated as zero.
    """
    text = value.strip()
    if not text:
        raise ValueError("empty duration")
    matches = list(_GO_DURATION_RE.finditer(text))
    if not matches or "".join(m.group(0) for m in matches) != text:
        raise ValueError(f"not a Go duration: {value!r}")
    seconds = 0.0
    for amount, unit in (m.groups() for m in matches):
        seconds += float(amount) * {"h": 3600, "m": 60, "s": 1}[unit]
    return datetime.timedelta(seconds=seconds)


def certificate_dns_names(cert: x509.Certificate) -> set[str]:
    """The DNS names in a certificate's subjectAltName extension."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return set()
    return set(san.value.get_values_for_type(x509.DNSName))


def renewal_due(
    cert: x509.Certificate,
    *,
    renew_before: str | None = None,
    now: datetime.datetime | None = None,
) -> bool:
    """Whether ``cert`` is inside its renewal window (or already invalid).

    ``renew_before`` is the publication's Go duration if it set one; otherwise
    the window is the final third of the certificate's own lifetime.
    """
    now = now or datetime.datetime.now(datetime.UTC)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    if now < not_before or now >= not_after:
        return True
    if renew_before:
        window = parse_go_duration(renew_before)
    else:
        window = (not_after - not_before) * _DEFAULT_RENEW_FRACTION
    return (not_after - now) <= window
