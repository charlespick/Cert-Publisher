import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cert_publisher.certmanager import build_certificate_body
from cert_publisher.utils import leaf_pem, sha1_thumbprint, sha256_fingerprint


def _self_signed() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_fingerprints_match_openssl_form():
    pem = _self_signed()
    cert = x509.load_pem_x509_certificate(pem)
    assert sha256_fingerprint(pem) == cert.fingerprint(hashes.SHA256()).hex()
    assert sha1_thumbprint(pem) == cert.fingerprint(hashes.SHA1()).hex().upper()


def test_leaf_pem_picks_first_of_bundle():
    a = _self_signed()
    b = _self_signed()
    bundle = a + b
    assert leaf_pem(bundle) == a.strip()


def test_build_certificate_body():
    pub = {
        "metadata": {"name": "web01", "namespace": "default", "uid": "abc-123"},
        "spec": {
            "dnsNames": ["web01.example.com"],
            "issuerRef": {"name": "letsencrypt-prod", "kind": "ClusterIssuer"},
            "duration": "2160h",
        },
    }
    body = build_certificate_body(pub, "web01-tls")
    assert body["kind"] == "Certificate"
    assert body["metadata"]["ownerReferences"][0]["uid"] == "abc-123"
    assert body["spec"]["secretName"] == "web01-tls"
    assert body["spec"]["duration"] == "2160h"
    assert body["spec"]["dnsNames"] == ["web01.example.com"]
