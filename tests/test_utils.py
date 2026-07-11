import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cert_publisher.certmanager import (
    build_certificate_body,
    certificate_spec_drift,
)
from cert_publisher.status import PUBLISHED, set_status
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


def test_ssh_load_private_key_detects_type():
    import paramiko

    from cert_publisher.provisioners.ssh import _load_private_key

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    loaded = _load_private_key(pem, None)
    assert isinstance(loaded, paramiko.RSAKey)


def test_ssh_load_private_key_rejects_garbage():
    import paramiko
    import pytest

    from cert_publisher.provisioners.ssh import _load_private_key

    with pytest.raises(paramiko.SSHException):
        _load_private_key("not a key", None)


def test_certificate_spec_drift_detects_dns_change():
    pub = {
        "metadata": {"name": "web01", "namespace": "default", "uid": "abc-123"},
        "spec": {
            "dnsNames": ["web01.example.com"],
            "issuerRef": {"name": "letsencrypt-prod", "kind": "ClusterIssuer"},
        },
    }
    existing = build_certificate_body(pub, "web01-tls")
    # Same spec: no drift.
    assert certificate_spec_drift(existing, pub, "web01-tls") is None
    # Changed subjects: drift returns the desired spec.
    pub["spec"]["dnsNames"] = ["web01.example.com", "www.example.com"]
    drift = certificate_spec_drift(existing, pub, "web01-tls")
    assert drift is not None
    assert drift["dnsNames"] == ["web01.example.com", "www.example.com"]


def test_certificate_spec_drift_ignores_cert_manager_defaults():
    pub = {
        "metadata": {"name": "web01", "namespace": "default", "uid": "abc-123"},
        "spec": {
            "dnsNames": ["web01.example.com"],
            "issuerRef": {"name": "letsencrypt-prod", "kind": "ClusterIssuer"},
        },
    }
    existing = build_certificate_body(pub, "web01-tls")
    # cert-manager adds fields we don't manage; these must not read as drift.
    existing["spec"]["revisionHistoryLimit"] = 1
    existing["spec"]["privateKey"] = {"algorithm": "RSA"}
    assert certificate_spec_drift(existing, pub, "web01-tls") is None


class _FakeResult:
    def __init__(self, std_out=b"", std_err=b"", status_code=0):
        self.std_out = std_out
        self.std_err = std_err
        self.status_code = status_code


class _FakeWinRMSession:
    """Records every PowerShell script run so uploads can be asserted on."""

    def __init__(self):
        self.scripts = []

    def run_ps(self, script):
        self.scripts.append(script)
        # GetTempFileName is used to allocate a remote scratch path.
        if script.strip() == "[IO.Path]::GetTempFileName()":
            return _FakeResult(std_out=b"C:\\Temp\\tmp123.tmp\r\n")
        return _FakeResult()


def _winrm_provisioner():
    from cert_publisher.provisioners.base import Credentials
    from cert_publisher.provisioners.winrm import WinRMProvisioner

    return WinRMProvisioner(
        host="win01.example.com", port=5986, username="Administrator",
        thumbprint="AA:BB", transport="ntlm", credentials=Credentials(password="p"),
        mode="file", store_location="LocalMachine", store_name="My",
        cert_path="C:\\certs\\web.crt", key_path=None, post_install_script=None,
    )


def test_winrm_upload_chunks_stay_within_command_limit():
    import base64

    from cert_publisher.provisioners import winrm as winrm_mod

    prov = _winrm_provisioner()
    session = _FakeWinRMSession()
    # Payload large enough to require several chunks.
    data = b"x" * 20_000
    remote = prov._upload_b64(session, data)
    assert remote == "C:\\Temp\\tmp123.tmp"

    b64 = base64.b64encode(data).decode()
    writes = [s for s in session.scripts if "[IO.File]::" in s]
    assert len(writes) > 1  # multiple chunks, not one giant command
    assert "WriteAllText" in writes[0]
    assert all("AppendAllText" in w for w in writes[1:])
    # Every command line must stay well under the WinRM limit.
    assert all(len(w) < winrm_mod._UPLOAD_CHUNK + 200 for w in writes)
    # Concatenated chunks reconstruct the original base64 exactly.
    joined = "".join(
        w.split("'")[3] for w in writes  # the chunk literal is the 2nd '...'
    )
    assert joined == b64


def test_winrm_write_file_uploads_via_temp_file():
    prov = _winrm_provisioner()
    session = _FakeWinRMSession()
    prov._write_file(session, "C:\\certs\\web.crt", b"hello")
    final = session.scripts[-1]
    # Final command references the uploaded temp file, not an inlined blob.
    assert "ReadAllText" in final
    assert "C:\\certs\\web.crt" in final


class _FakeKube:
    def __init__(self):
        self.patched = None

    def patch_publication_status(self, namespace, name, status):
        self.patched = (namespace, name, status)


def test_set_status_patches_expected_fields():
    kube = _FakeKube()
    pub = {"metadata": {"name": "web01", "namespace": "default", "generation": 3}}
    set_status(
        kube, pub, PUBLISHED, "Certificate published",
        published_fingerprint="deadbeef", mark_published=True,
    )
    namespace, name, status = kube.patched
    assert (namespace, name) == ("default", "web01")
    assert status["phase"] == PUBLISHED
    assert status["publishedFingerprint"] == "deadbeef"
    assert status["observedGeneration"] == 3
    assert "lastPublishedTime" in status
    assert "lastReconcileTime" in status


def test_set_status_omits_publish_time_when_not_marked():
    kube = _FakeKube()
    pub = {"metadata": {"name": "web01", "namespace": "default", "generation": 1}}
    set_status(kube, pub, PUBLISHED, "up to date", published_fingerprint="abc")
    _, _, status = kube.patched
    assert "lastPublishedTime" not in status

