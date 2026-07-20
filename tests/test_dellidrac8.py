import base64
import datetime
import json
import ssl

import pytest
import requests
from cryptography import x509

import cert_publisher.provisioners.dellidrac8 as dm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from cert_publisher.provisioners.base import Credentials
from cert_publisher.provisioners.dellidrac8 import DelliDRAC8Provisioner


def _cert_and_key() -> tuple[bytes, bytes, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idrac01.example.com")])
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
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem, cert


def _provisioner(**overrides) -> DelliDRAC8Provisioner:
    kwargs = dict(
        host="idrac01.example.com",
        port=443,
        username="root",
        credentials=Credentials(password="secret"),
        bootstrap_thumbprint=None,
        ca_bundle=None,
        reboot=True,
    )
    kwargs.update(overrides)
    return DelliDRAC8Provisioner(**kwargs)


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, body=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body
        self.text = text if text else (json.dumps(body) if body is not None else "")

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class _FakeSession:
    """Records Redfish calls and returns queued responses by URL suffix."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []
        self.closed = False

    def post(self, url, json=None, timeout=None):
        self.calls.append(("POST", url, json))
        for suffix, resp in self.responses.items():
            if url.endswith(suffix):
                return resp
        raise AssertionError(f"unexpected POST to {url}")

    def delete(self, url, timeout=None):
        self.calls.append(("DELETE", url, None))
        return _FakeResponse(204)

    def close(self):
        self.closed = True


# -- from_spec / config -------------------------------------------------


def test_from_spec_defaults_and_thumbprint_normalization():
    spec = {
        "host": "idrac01.example.com",
        "username": "root",
        "auth": {"secretRef": {"name": "creds"}},
        "bootstrapThumbprint": "aa:bb cc:DD",
    }

    class _Kube:
        def get_secret(self, ns, name):
            return object()

        def secret_data(self, secret):
            return {"password": b"pw"}

    prov = DelliDRAC8Provisioner.from_spec(spec, _Kube(), "default")
    assert prov.port == 443
    assert prov.reboot is True
    assert prov.bootstrap_thumbprint == "AABBCCDD"  # colons/spaces stripped, upper


# -- host verification --------------------------------------------------


def test_verify_endpoint_accepts_currently_valid(monkeypatch):
    prov = _provisioner()
    monkeypatch.setattr(prov, "_endpoint_currently_valid", lambda trust: True)
    monkeypatch.setattr(
        prov, "_peer_der", lambda: pytest.fail("thumbprint path should be skipped")
    )
    prov._verify_endpoint(b"whatever")  # does not raise


def test_verify_endpoint_falls_back_to_bootstrap_thumbprint(monkeypatch):
    _, _, cert = _cert_and_key()
    der = cert.public_bytes(serialization.Encoding.DER)
    thumb = __import__("hashlib").sha256(der).hexdigest().upper()

    prov = _provisioner(bootstrap_thumbprint=thumb)
    monkeypatch.setattr(prov, "_endpoint_currently_valid", lambda trust: False)
    monkeypatch.setattr(prov, "_peer_der", lambda: der)
    prov._verify_endpoint()  # matches bootstrap thumbprint, does not raise


def test_verify_endpoint_rejects_on_mismatch(monkeypatch):
    _, _, cert = _cert_and_key()
    der = cert.public_bytes(serialization.Encoding.DER)

    prov = _provisioner(bootstrap_thumbprint="DEADBEEF")
    monkeypatch.setattr(prov, "_endpoint_currently_valid", lambda trust: False)
    monkeypatch.setattr(prov, "_peer_der", lambda: der)
    with pytest.raises(RuntimeError, match="does not match the configured bootstrap"):
        prov._verify_endpoint()


def test_verify_endpoint_rejects_without_any_signal(monkeypatch):
    prov = _provisioner(bootstrap_thumbprint=None)
    monkeypatch.setattr(prov, "_endpoint_currently_valid", lambda trust: False)
    with pytest.raises(RuntimeError, match="no bootstrapThumbprint is configured"):
        prov._verify_endpoint()


# -- is_current ---------------------------------------------------------


def test_is_current_true_when_endpoint_serves_desired_leaf(monkeypatch):
    cert_pem, _, cert = _cert_and_key()
    der = cert.public_bytes(serialization.Encoding.DER)

    prov = _provisioner()
    monkeypatch.setattr(prov, "_verify_endpoint", lambda trust=None: None)
    monkeypatch.setattr(prov, "_peer_der", lambda: der)
    assert prov.is_current(cert_pem) is True


def test_is_current_false_when_endpoint_serves_other_cert(monkeypatch):
    cert_pem, _, _ = _cert_and_key()
    _, _, other = _cert_and_key()
    other_der = other.public_bytes(serialization.Encoding.DER)

    prov = _provisioner()
    monkeypatch.setattr(prov, "_verify_endpoint", lambda trust=None: None)
    monkeypatch.setattr(prov, "_peer_der", lambda: other_der)
    assert prov.is_current(cert_pem) is False


# -- pkcs12 build -------------------------------------------------------


def test_build_pkcs12_round_trips():
    cert_pem, key_pem, cert = _cert_and_key()
    pfx = DelliDRAC8Provisioner._build_pkcs12(cert_pem, key_pem, "pw123")
    key, loaded_cert, _ = pkcs12.load_key_and_certificates(pfx, b"pw123")
    assert key is not None
    assert loaded_cert.fingerprint(hashes.SHA256()) == cert.fingerprint(hashes.SHA256())


# -- install flow -------------------------------------------------------


def test_install_imports_then_reboots(monkeypatch):
    cert_pem, key_pem, _ = _cert_and_key()
    prov = _provisioner()
    monkeypatch.setattr(prov, "_verify_endpoint", lambda trust=None: None)

    session = _FakeSession(
        {
            "ImportSSLCertificate": _FakeResponse(
                202, body={"@Message.ExtendedInfo": [{"MessageId": "Base.1.5.Success"}]}
            ),
            "Manager.Reset": _FakeResponse(204),
        }
    )
    monkeypatch.setattr(prov, "_open_session", lambda: (session, "/redfish/v1/x"))

    prov.install(cert_pem, key_pem)

    posts = [c for c in session.calls if c[0] == "POST"]
    assert posts[0][1].endswith("ImportSSLCertificate")
    payload = posts[0][2]
    assert payload["CertificateType"] == "CustomCertificate"
    assert payload["Passphrase"]
    # SSLCertificateFile is base64 of a real PKCS#12 that decrypts with Passphrase.
    pfx = base64.b64decode(payload["SSLCertificateFile"])
    pkcs12.load_key_and_certificates(pfx, payload["Passphrase"].encode())
    # Reset requested with GracefulRestart, and the session was closed.
    assert posts[1][1].endswith("Manager.Reset")
    assert posts[1][2] == {"ResetType": "GracefulRestart"}
    assert session.closed


def test_install_skips_reboot_when_disabled(monkeypatch):
    cert_pem, key_pem, _ = _cert_and_key()
    prov = _provisioner(reboot=False)
    monkeypatch.setattr(prov, "_verify_endpoint", lambda trust=None: None)

    session = _FakeSession({"ImportSSLCertificate": _FakeResponse(200)})
    monkeypatch.setattr(prov, "_open_session", lambda: (session, None))

    prov.install(cert_pem, key_pem)
    assert not any(c[1].endswith("Manager.Reset") for c in session.calls)


def test_install_raises_on_import_error(monkeypatch):
    cert_pem, key_pem, _ = _cert_and_key()
    prov = _provisioner()
    monkeypatch.setattr(prov, "_verify_endpoint", lambda trust=None: None)

    session = _FakeSession(
        {
            "ImportSSLCertificate": _FakeResponse(
                400,
                body={
                    "error": {
                        "@Message.ExtendedInfo": [{"Message": "Invalid passphrase"}]
                    }
                },
            )
        }
    )
    monkeypatch.setattr(prov, "_open_session", lambda: (session, None))

    with pytest.raises(RuntimeError, match="Invalid passphrase"):
        prov.install(cert_pem, key_pem)
    assert session.closed  # session still closed on failure


# -- response parsing ---------------------------------------------------


def test_error_detail_falls_back_to_text():
    resp = _FakeResponse(500, text="   boom   ")
    assert DelliDRAC8Provisioner._error_detail(resp) == "boom"


def test_message_id_extracted_from_extended_info():
    resp = _FakeResponse(
        200, body={"@Message.ExtendedInfo": [{"MessageId": "Base.1.5.Success"}]}
    )
    assert DelliDRAC8Provisioner._message_id(resp) == "Base.1.5.Success"


# -- retry integration --------------------------------------------------


def test_endpoint_valid_returns_false_on_cert_verification_error(monkeypatch):
    # A reachable host serving an untrusted/invalid cert is a definitive "no":
    # it returns False (falling back to bootstrap) without consuming retries.
    calls = []

    def _raise(*args, **kwargs):
        calls.append(1)
        raise ssl.SSLCertVerificationError("self-signed certificate")

    monkeypatch.setattr(dm.socket, "create_connection", _raise)
    prov = _provisioner()
    assert prov._endpoint_currently_valid(None) is False
    assert len(calls) == 1  # not retried


def test_endpoint_valid_retries_transient_then_raises(monkeypatch):
    # A host that stays unreachable is retried, then surfaces a clear
    # ConnectionError rather than a misleading "not trusted".
    monkeypatch.setenv("RETRY_ATTEMPTS", "3")
    monkeypatch.setenv("RETRY_BASE_DELAY", "0")
    calls = []

    def _timeout(*args, **kwargs):
        calls.append(1)
        raise TimeoutError("timed out")

    monkeypatch.setattr(dm.socket, "create_connection", _timeout)
    prov = _provisioner()
    with pytest.raises(ConnectionError, match="validity check"):
        prov._endpoint_currently_valid(None)
    assert len(calls) == 3  # exhausted all attempts


def test_open_session_retries_transient_connection(monkeypatch):
    monkeypatch.setenv("RETRY_ATTEMPTS", "3")
    monkeypatch.setenv("RETRY_BASE_DELAY", "0")

    class _FlakySession:
        def __init__(self):
            self.headers = {}
            self.verify = None
            self.auth = None
            self.posts = 0

        def post(self, url, json=None, timeout=None):
            self.posts += 1
            if self.posts == 1:
                raise requests.exceptions.ConnectionError("connection refused")
            return _FakeResponse(201, headers={"X-Auth-Token": "tok", "Location": "/s/1"})

    flaky = _FlakySession()
    monkeypatch.setattr(dm.requests, "Session", lambda: flaky)
    prov = _provisioner()

    session, location = prov._open_session()
    assert session is flaky
    assert flaky.posts == 2  # one transient failure, then success
    assert flaky.headers["X-Auth-Token"] == "tok"
    assert location == "/s/1"
