"""Tests for the iDRAC8 (host-keyed) provisioner and its reconcile flow."""

import base64
import datetime
import hashlib
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cert_publisher import reconcile as reconcile_mod
from cert_publisher.certmanager import (
    CR_FAILED,
    CR_PENDING,
    CR_READY,
    build_certificate_request_body,
    certificate_request_state,
    issued_certificate,
)
from cert_publisher.provisioners import build_provisioner, manages_own_key
from cert_publisher.provisioners.idrac8 import IDRAC8Provisioner
from cert_publisher.status import ERROR, PENDING, PUBLISHED
from cert_publisher.utils import parse_go_duration, renewal_due, sha256_fingerprint
from cert_publisher.wsman import WSManClient, WSManError, _output_fields, _param_elements

# -- helpers ---------------------------------------------------------------


def _cert(
    *,
    cn="idrac01.example.com",
    dns=("idrac01.example.com",),
    days_valid=365,
    age_days=0,
) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=age_days))
        .not_valid_after(now - datetime.timedelta(days=age_days) + datetime.timedelta(days=days_valid))
    )
    if dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in dns]), critical=False
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


class _FakeKube:
    def __init__(self, request=None):
        self.request = request
        self.created = []
        self.deleted = []
        self.status = {}
        self.events = []

    def get_certificate_request(self, namespace, name):
        return self.request

    def create_certificate_request(self, namespace, body):
        self.events.append("create")
        self.created.append(body)
        return body

    def delete_certificate_request(self, namespace, name):
        self.deleted.append(name)

    def patch_publication_status(self, namespace, name, status):
        self.events.append("status")
        self.status.update(status)

    def get_secret(self, namespace, name):
        return None


def _csr(cn="idrac01.example.com", key_usage=True) -> bytes:
    """A real CSR shaped like the one an iDRAC8 emits."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    )
    if key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


class _FakeProv:
    """Stands in for IDRAC8Provisioner at the reconcile boundary."""

    def __init__(self, installed=None, csr=None):
        self.installed = installed
        self.csr = csr if csr is not None else _csr()
        self.imported = None
        self.csr_args = None

    def installed_certificate(self):
        return self.installed

    def generate_csr(self, *, common_name, dns_names):
        self.csr_args = (common_name, dns_names)
        return self.csr

    def import_certificate(self, cert_pem):
        self.imported = cert_pem


def _pub(status=None, **spec_extra):
    spec = {
        "dnsNames": ["idrac01.example.com"],
        "issuerRef": {"name": "ca", "kind": "ClusterIssuer"},
        "provisioner": {"type": "idrac8", "idrac8": {}},
    }
    spec.update(spec_extra)
    return {
        "metadata": {"name": "idrac01", "namespace": "default", "uid": "u1", "generation": 1},
        "spec": spec,
        "status": status or {},
    }


def _provisioner(**kw):
    from cert_publisher.provisioners.base import Credentials

    defaults = {
        "host": "idrac01.example.com",
        "port": 443,
        "username": "root",
        "credentials": Credentials(password="pw"),
        "bootstrap_thumbprint": None,
        "ca_bundle": None,
        "reset": True,
    }
    defaults.update(kw)
    return IDRAC8Provisioner(**defaults)


# -- WS-Man client ---------------------------------------------------------


def test_param_elements_repeats_arrays_and_escapes_values():
    assert _param_elements("A", "x") == "<n1:A>x</n1:A>"
    assert _param_elements("A", ["x", "y"]) == "<n1:A>x</n1:A><n1:A>y</n1:A>"
    assert _param_elements("A", "a&b<c") == "<n1:A>a&amp;b&lt;c</n1:A>"


def test_envelope_carries_selectors_action_and_params():
    client = WSManClient.__new__(WSManClient)
    client.url = "https://h:443/wsman"
    client.timeout = 60
    envelope = client._envelope(
        "http://schemas.dell.com/x/DCIM_iDRACCardService", "ExportSSLCertificate",
        {"SSLCertType": "1"}, {"Name": "DCIM:iDRACCardService"},
    )
    assert "DCIM:iDRACCardService" in envelope
    assert "/ExportSSLCertificate</wsa:Action>" in envelope
    assert "<n1:SSLCertType>1</n1:SSLCertType>" in envelope
    assert "ExportSSLCertificate_INPUT" in envelope


def _envelope_with(body: str) -> bytes:
    return (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        f"<s:Body>{body}</s:Body></s:Envelope>"
    ).encode()


class _FakeResponse:
    def __init__(self, content, status_code=200):
        self.content = content
        self.status_code = status_code
        self.text = content.decode() if isinstance(content, bytes) else content


class _FakeSession:
    def __init__(self, response):
        self.response = response
        self.headers = {}
        self.sent = None

    def post(self, url, data=None, timeout=None, allow_redirects=None):
        self.sent = data
        self.allow_redirects = allow_redirects
        return self.response

    def close(self):
        pass


def _client_with(response):
    client = WSManClient.__new__(WSManClient)
    client.host, client.url, client.timeout = "h", "https://h/wsman", 60
    client.session = _FakeSession(response)
    return client


def test_invoke_returns_output_fields():
    body = (
        '<n1:ExportSSLCertificate_OUTPUT xmlns:n1="x">'
        "<n1:CertificateFile>PEM</n1:CertificateFile>"
        "<n1:ReturnValue>0</n1:ReturnValue>"
        "</n1:ExportSSLCertificate_OUTPUT>"
    )
    client = _client_with(_FakeResponse(_envelope_with(body)))
    out = client.invoke("DCIM_iDRACCardService", "ExportSSLCertificate", {})
    assert out["CertificateFile"] == "PEM"


def test_invoke_raises_on_soap_fault():
    body = "<s:Fault><s:Reason><s:Text>ActionNotSupported</s:Text></s:Reason></s:Fault>"
    client = _client_with(_FakeResponse(_envelope_with(body)))
    with pytest.raises(WSManError, match="ActionNotSupported"):
        client.invoke("DCIM_iDRACCardService", "Bogus", {})


def test_invoke_raises_with_the_idrac_message_on_bad_return_value():
    body = (
        '<n1:ImportSSLCertificate_OUTPUT xmlns:n1="x">'
        "<n1:Message>Missing required parameter SSLCertificateFile</n1:Message>"
        "<n1:ReturnValue>2</n1:ReturnValue>"
        "</n1:ImportSSLCertificate_OUTPUT>"
    )
    client = _client_with(_FakeResponse(_envelope_with(body)))
    with pytest.raises(WSManError, match="Missing required parameter"):
        client.invoke("DCIM_iDRACCardService", "ImportSSLCertificate", {})


def test_invoke_accepts_job_created_return_value():
    body = (
        '<n1:X_OUTPUT xmlns:n1="x"><n1:ReturnValue>4096</n1:ReturnValue></n1:X_OUTPUT>'
    )
    client = _client_with(_FakeResponse(_envelope_with(body)))
    assert client.invoke("DCIM_iDRACCardService", "X", {})["ReturnValue"] == "4096"


def test_invoke_raises_on_http_error():
    client = _client_with(_FakeResponse(b"nope", status_code=401))
    with pytest.raises(WSManError, match="HTTP 401"):
        client.invoke("DCIM_iDRACCardService", "X", {})


def test_output_fields_joins_repeated_elements():
    import xml.etree.ElementTree as ET

    root = ET.fromstring(
        _envelope_with('<n1:X_OUTPUT xmlns:n1="x"><n1:A>1</n1:A><n1:A>2</n1:A></n1:X_OUTPUT>')
    )
    assert _output_fields(root, "X")["A"] == "1, 2"


# -- host authentication ---------------------------------------------------


def test_authenticate_prefers_a_currently_valid_certificate(monkeypatch):
    der = b"trusted-der"
    prov = _provisioner(bootstrap_thumbprint="00" * 32)
    monkeypatch.setattr(prov, "_peer_der", lambda *, verify: der if verify else b"other")
    assert prov._authenticate_endpoint() == hashlib.sha256(der).hexdigest()


def test_authenticate_falls_back_to_the_bootstrap_thumbprint(monkeypatch):
    der = b"factory-der"
    prov = _provisioner(bootstrap_thumbprint=hashlib.sha256(der).hexdigest().upper())
    monkeypatch.setattr(prov, "_peer_der", lambda *, verify: None if verify else der)
    assert prov._authenticate_endpoint() == hashlib.sha256(der).hexdigest()


def test_authenticate_rejects_a_thumbprint_mismatch(monkeypatch):
    prov = _provisioner(bootstrap_thumbprint="aa" * 32)
    monkeypatch.setattr(prov, "_peer_der", lambda *, verify: None if verify else b"x")
    with pytest.raises(RuntimeError, match="thumbprint mismatch"):
        prov._authenticate_endpoint()


def test_authenticate_refuses_when_untrusted_and_no_bootstrap(monkeypatch):
    prov = _provisioner(bootstrap_thumbprint=None)
    monkeypatch.setattr(prov, "_peer_der", lambda *, verify: None if verify else b"x")
    with pytest.raises(RuntimeError, match="bootstrapThumbprint"):
        prov._authenticate_endpoint()


def test_thumbprint_is_normalised():
    prov = _provisioner(bootstrap_thumbprint="AA:BB:cc ")
    assert prov.bootstrap_thumbprint == "aabbcc"


def test_verification_failure_is_not_retried_as_a_connection_error(monkeypatch):
    """A cert that doesn't validate is an expected state, not a transient fault."""
    calls = []

    class _Sock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _boom(*args, **kwargs):
        calls.append(1)
        raise ssl.SSLCertVerificationError("unable to get local issuer certificate")

    prov = _provisioner()
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: _Sock())
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", _boom)
    assert prov._peer_der(verify=True) is None
    assert len(calls) == 1  # not retried


def test_connect_pins_the_certificate_it_accepted(monkeypatch):
    der = b"accepted"
    prov = _provisioner()
    monkeypatch.setattr(prov, "_peer_der", lambda *, verify: der if verify else None)
    captured = {}

    class _Client:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr("cert_publisher.provisioners.idrac8.WSManClient", _Client)
    prov._connect()
    assert captured["pin_sha256"] == hashlib.sha256(der).hexdigest()


def test_connect_requires_a_password(monkeypatch):
    from cert_publisher.provisioners.base import Credentials

    prov = _provisioner(credentials=Credentials(password=None))
    with pytest.raises(ValueError, match="requires a password"):
        prov._connect()


# -- provisioner operations ------------------------------------------------


class _RecordingClient:
    def __init__(self, outputs, attributes=None):
        self.outputs = outputs
        self.calls = []
        # InstanceID suffix -> CurrentValue, as WSManClient.get would report.
        self.attributes = attributes if attributes is not None else {}
        self.gets = []

    def get(self, cim_class, selectors):
        instance = selectors["InstanceID"]
        self.gets.append(instance)
        return {"CurrentValue": self.attributes.get(instance.split("#", 1)[1], "")}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def invoke(self, cim_class, method, params=None, **kw):
        self.calls.append((method, params or {}))
        if isinstance(self.outputs.get(method), Exception):
            raise self.outputs[method]
        return self.outputs.get(method, {})


def test_installed_certificate_reads_the_live_handshake(monkeypatch):
    """The certificate clients actually see is the one that decides renewal."""
    pem = _cert()
    der = x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)
    prov = _provisioner()
    monkeypatch.setattr(prov, "_peer_der", lambda *, verify: der if verify else None)

    got = prov.installed_certificate()

    assert x509.load_pem_x509_certificate(got).fingerprint(hashes.SHA256()) == (
        x509.load_pem_x509_certificate(pem).fingerprint(hashes.SHA256())
    )


def test_installed_certificate_sends_no_credentials(monkeypatch):
    """The common 'nothing to do' reconcile must not open a WS-Man session."""
    der = x509.load_pem_x509_certificate(_cert()).public_bytes(serialization.Encoding.DER)
    prov = _provisioner()
    monkeypatch.setattr(prov, "_peer_der", lambda *, verify: der if verify else None)
    monkeypatch.setattr(
        prov, "_connect",
        lambda: pytest.fail("installed_certificate must not open a WS-Man session"),
    )
    assert prov.installed_certificate() is not None


def test_installed_certificate_propagates_an_unreachable_host(monkeypatch):
    """An unreachable host must error, not read as 'needs renewal'."""
    prov = _provisioner()

    def _boom(*, verify):
        raise ConnectionError("host is down")

    monkeypatch.setattr(prov, "_peer_der", _boom)
    with pytest.raises(ConnectionError):
        prov.installed_certificate()


def test_generate_csr_applies_the_subject_then_generates(monkeypatch):
    """SetAttributes only stages; a config job commits it before the CSR."""
    applied = {}

    class _Client(_RecordingClient):
        def invoke(self, cim_class, method, params=None, **kw):
            out = super().invoke(cim_class, method, params, **kw)
            if method == "CreateTargetedConfigJob":
                # The job is what makes the staged values current.
                self.attributes.update(applied)
            return out

    client = _Client({"GenerateSSLCSR": {"SSLCSRFile": "CSRDATA"}}, attributes={})
    applied.update({
        "Security.1#CsrCommonName": "a.example.com",
        "Security.1#CsrSubjectAltName": "a.example.com,b.example.com",
    })
    prov = _provisioner()
    monkeypatch.setattr(prov, "_connect", lambda: client)

    csr = prov.generate_csr(
        common_name="a.example.com", dns_names=["a.example.com", "b.example.com"]
    )

    assert csr == b"CSRDATA\n"
    methods = [m for m, _ in client.calls]
    assert methods == ["SetAttributes", "CreateTargetedConfigJob", "GenerateSSLCSR"]
    attrs = client.calls[0][1]
    assert attrs["Target"] == "iDRAC.Embedded.1"
    # SetAttributes wants "<GroupID>#<AttributeName>", not the dotted form.
    assert attrs["AttributeName"] == [
        "Security.1#CsrCommonName", "Security.1#CsrSubjectAltName",
    ]
    assert attrs["AttributeValue"] == ["a.example.com", "a.example.com,b.example.com"]


def test_generate_csr_skips_the_config_job_when_the_subject_already_matches(monkeypatch):
    """Steady-state renewals must not run a job on every round."""
    client = _RecordingClient(
        {"GenerateSSLCSR": {"SSLCSRFile": "CSRDATA"}},
        attributes={
            "Security.1#CsrCommonName": "a.example.com",
            "Security.1#CsrSubjectAltName": "a.example.com",
        },
    )
    prov = _provisioner()
    monkeypatch.setattr(prov, "_connect", lambda: client)

    prov.generate_csr(common_name="a.example.com", dns_names=["a.example.com"])

    assert [m for m, _ in client.calls] == ["GenerateSSLCSR"]


def test_generate_csr_refuses_when_the_subject_never_applies(monkeypatch):
    """A CSR minted from a stale subject is what a public CA then refuses."""
    # The job never makes the staged values current.
    client = _RecordingClient({"GenerateSSLCSR": {"SSLCSRFile": "X"}}, attributes={})
    prov = _provisioner()
    monkeypatch.setattr(prov, "_connect", lambda: client)
    monkeypatch.setattr("cert_publisher.provisioners.idrac8._APPLY_TIMEOUT", 0)
    monkeypatch.setattr("cert_publisher.provisioners.idrac8._APPLY_POLL_INTERVAL", 0)

    with pytest.raises(RuntimeError, match="did not apply the CSR subject"):
        prov.generate_csr(common_name="a.example.com", dns_names=["a.example.com"])

    assert "GenerateSSLCSR" not in [m for m, _ in client.calls]


def test_generate_csr_raises_when_no_csr_comes_back(monkeypatch):
    client = _RecordingClient(
        {"GenerateSSLCSR": {}},
        attributes={
            "Security.1#CsrCommonName": "a",
            "Security.1#CsrSubjectAltName": "a",
        },
    )
    prov = _provisioner()
    monkeypatch.setattr(prov, "_connect", lambda: client)
    with pytest.raises(RuntimeError, match="returned no SSLCSRFile"):
        prov.generate_csr(common_name="a", dns_names=["a"])


def test_import_sends_raw_pem_not_base64(monkeypatch):
    """PEM is already base64-armoured; wrapping it again is rejected."""
    pem = _cert()
    client = _RecordingClient({})
    prov = _provisioner()
    monkeypatch.setattr(prov, "_connect", lambda: client)
    prov.import_certificate(pem)
    params = client.calls[0][1]
    assert params["SSLCertificateFile"] == pem.decode()
    assert params["SSLCertificateFile"].startswith("-----BEGIN CERTIFICATE-----")
    # Import takes CertificateType; only Export takes SSLCertType (DCIM1043).
    assert params["CertificateType"] == "1"
    assert "SSLCertType" not in params


def test_import_sends_the_full_chain_leaf_first(monkeypatch):
    """Firmware 2.86.86.86 accepts leaf + intermediate here and serves both,
    so the whole ACME bundle is imported rather than stripped to the leaf."""
    leaf = _cert()
    intermediate = _cert(cn="Issuing CA", dns=())
    bundle = leaf + intermediate

    client = _RecordingClient({})
    prov = _provisioner()
    monkeypatch.setattr(prov, "_connect", lambda: client)
    prov.import_certificate(bundle)

    sent = client.calls[0][1]["SSLCertificateFile"]
    assert sent == bundle.decode()
    assert sent.count("BEGIN CERTIFICATE") == 2
    assert sent.startswith(leaf.decode().rstrip())


def test_import_resets_the_idrac_to_apply_the_certificate(monkeypatch):
    """Firmware 2.86.86.86 answers DH010: the cert is inactive until reset."""
    client = _RecordingClient({})
    prov = _provisioner()
    monkeypatch.setattr(prov, "_connect", lambda: client)
    prov.import_certificate(_cert())
    assert [m for m, _ in client.calls] == ["ImportSSLCertificate", "iDRACReset"]


def test_reset_can_be_disabled(monkeypatch):
    client = _RecordingClient({})
    prov = _provisioner(reset=False)
    monkeypatch.setattr(prov, "_connect", lambda: client)
    prov.import_certificate(_cert())
    assert [m for m, _ in client.calls] == ["ImportSSLCertificate"]


# -- renewal policy --------------------------------------------------------


def test_parse_go_duration_rejects_unsupported_units():
    assert parse_go_duration("2160h") == datetime.timedelta(days=90)
    with pytest.raises(ValueError):
        parse_go_duration("5d")
    with pytest.raises(ValueError):
        parse_go_duration("")


def test_renewal_due_uses_the_final_third_by_default():
    fresh = x509.load_pem_x509_certificate(_cert(days_valid=300, age_days=0))
    old = x509.load_pem_x509_certificate(_cert(days_valid=300, age_days=250))
    assert renewal_due(fresh) is False
    assert renewal_due(old) is True


def test_renewal_due_honours_renew_before():
    cert = x509.load_pem_x509_certificate(_cert(days_valid=60))
    assert renewal_due(cert, renew_before="24h") is False
    assert renewal_due(cert, renew_before="2160h") is True


def test_renewal_due_when_expired():
    cert = x509.load_pem_x509_certificate(_cert(days_valid=1, age_days=5))
    assert renewal_due(cert) is True


def test_renewal_reason_none_when_healthy():
    pem = _cert(days_valid=300)
    status = {"publishedFingerprint": sha256_fingerprint(pem)}
    assert reconcile_mod._renewal_reason(pem, _pub()["spec"], status) is None


@pytest.mark.parametrize(
    "installed, status, expected",
    [
        (None, {}, "not serving a certificate"),
        (b"garbage", {"publishedFingerprint": "x"}, "could not be parsed"),
        (_cert(), {}, "no certificate has been published"),
        (_cert(), {"publishedFingerprint": "deadbeef"}, "was not published by cert-publisher"),
    ],
)
def test_renewal_reason_explains_why(installed, status, expected):
    reason = reconcile_mod._renewal_reason(installed, _pub()["spec"], status)
    assert reason is not None and expected in reason


def test_renewal_reason_flags_missing_dns_names():
    pem = _cert(dns=("other.example.com",))
    status = {"publishedFingerprint": sha256_fingerprint(pem)}
    reason = reconcile_mod._renewal_reason(pem, _pub()["spec"], status)
    assert "does not cover idrac01.example.com" in reason


def test_renewal_reason_flags_expiry():
    pem = _cert(days_valid=300, age_days=250)
    status = {"publishedFingerprint": sha256_fingerprint(pem)}
    reason = reconcile_mod._renewal_reason(pem, _pub()["spec"], status)
    assert "due for renewal" in reason


# -- CertificateRequest ----------------------------------------------------


def test_build_certificate_request_body():
    csr = _csr()
    body = build_certificate_request_body(_pub(duration="2160h"), "idrac01-abc", csr)
    assert body["kind"] == "CertificateRequest"
    assert body["spec"]["request"] == base64.b64encode(csr).decode()
    assert body["spec"]["duration"] == "2160h"
    assert body["spec"]["isCA"] is False
    assert "renewBefore" not in body["spec"]
    assert body["metadata"]["ownerReferences"][0]["name"] == "idrac01"


@pytest.mark.parametrize(
    "conditions, expected",
    [
        ([], CR_PENDING),
        ([{"type": "Ready", "status": "True"}], CR_READY),
        ([{"type": "Ready", "status": "False", "reason": "Pending"}], CR_PENDING),
        ([{"type": "Ready", "status": "False", "reason": "Failed"}], CR_FAILED),
        ([{"type": "Denied", "status": "True"}], CR_FAILED),
        ([{"type": "InvalidRequest", "status": "True"}], CR_FAILED),
    ],
)
def test_certificate_request_state(conditions, expected):
    state, _ = certificate_request_state({"status": {"conditions": conditions}})
    assert state == expected


def test_issued_certificate_requires_material():
    with pytest.raises(ValueError):
        issued_certificate({"status": {}})
    assert issued_certificate(
        {"status": {"certificate": base64.b64encode(b"PEM").decode()}}
    ) == b"PEM"


# -- reconcile flow --------------------------------------------------------


def test_idrac8_takes_the_host_keyed_path():
    assert manages_own_key("idrac8") is True
    assert manages_own_key("ssh") is False
    assert manages_own_key("winrm") is False


def test_reconcile_reports_up_to_date_without_signing(monkeypatch):
    pem = _cert(days_valid=300)
    kube = _FakeKube()
    prov = _FakeProv(installed=pem)
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: prov)
    pub = _pub(status={"publishedFingerprint": sha256_fingerprint(pem)})

    reconcile_mod.reconcile_publication(kube, pub)

    assert kube.status["phase"] == PUBLISHED
    assert kube.created == []
    assert prov.csr_args is None


def test_reconcile_generates_a_csr_and_creates_a_request(monkeypatch):
    kube = _FakeKube()
    prov = _FakeProv(installed=None)
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: prov)

    reconcile_mod.reconcile_publication(kube, _pub())

    assert prov.csr_args == ("idrac01.example.com", ["idrac01.example.com"])
    assert len(kube.created) == 1
    name = kube.created[0]["metadata"]["name"]
    assert name.startswith("idrac01-")
    assert kube.status["phase"] == PENDING
    assert kube.status["pendingRequestName"] == name


def test_reconcile_imports_a_ready_request_then_deletes_it(monkeypatch):
    signed = _cert()
    kube = _FakeKube(request={
        "status": {
            "conditions": [{"type": "Ready", "status": "True"}],
            "certificate": base64.b64encode(signed).decode(),
        }
    })
    prov = _FakeProv()
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: prov)

    reconcile_mod.reconcile_publication(kube, _pub(status={"pendingRequestName": "idrac01-abc"}))

    assert prov.imported == signed
    assert kube.deleted == ["idrac01-abc"]
    assert kube.status["phase"] == PUBLISHED
    assert kube.status["publishedFingerprint"] == sha256_fingerprint(signed)
    assert kube.status["pendingRequestName"] is None


def test_reconcile_does_not_regenerate_a_csr_while_one_is_pending(monkeypatch):
    kube = _FakeKube(request={"status": {"conditions": []}})
    prov = _FakeProv()
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: prov)

    reconcile_mod.reconcile_publication(kube, _pub(status={"pendingRequestName": "idrac01-abc"}))

    assert prov.csr_args is None  # the host's key was not rotated
    assert kube.created == []
    assert kube.status["phase"] == PENDING


def test_reconcile_drops_a_failed_request_so_a_new_one_is_made(monkeypatch):
    kube = _FakeKube(request={
        "status": {"conditions": [{"type": "Denied", "status": "True", "message": "no"}]}
    })
    prov = _FakeProv()
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: prov)

    reconcile_mod.reconcile_publication(kube, _pub(status={"pendingRequestName": "idrac01-abc"}))

    assert kube.deleted == ["idrac01-abc"]
    assert kube.status["pendingRequestName"] is None
    assert kube.status["phase"] == PENDING


def test_reconcile_recovers_when_the_pending_request_vanished(monkeypatch):
    kube = _FakeKube(request=None)
    prov = _FakeProv()
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: prov)

    reconcile_mod.reconcile_publication(kube, _pub(status={"pendingRequestName": "gone"}))

    assert kube.status["pendingRequestName"] is None
    assert kube.status["phase"] == PENDING


def test_reconcile_keeps_the_request_when_the_import_fails(monkeypatch):
    """A failed import must not rotate the host key for a fresh CSR next run."""
    signed = _cert()
    kube = _FakeKube(request={
        "status": {
            "conditions": [{"type": "Ready", "status": "True"}],
            "certificate": base64.b64encode(signed).decode(),
        }
    })

    class _Failing(_FakeProv):
        def import_certificate(self, cert_pem):
            raise RuntimeError("import blew up")

    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: _Failing())

    with pytest.raises(RuntimeError, match="import blew up"):
        reconcile_mod.reconcile_publication(kube, _pub(status={"pendingRequestName": "idrac01-abc"}))

    assert kube.deleted == []


def test_build_provisioner_constructs_idrac8():
    class _K:
        def get_secret(self, ns, name):
            class _S:
                def __init__(self):
                    self.data = {"password": base64.b64encode(b"pw").decode()}
            return _S()

        @staticmethod
        def secret_data(secret):
            return {"password": b"pw"}

    prov = build_provisioner(
        {
            "type": "idrac8",
            "idrac8": {
                "host": "h", "username": "u",
                "auth": {"secretRef": {"name": "s"}},
                "bootstrapThumbprint": "AB:CD",
            },
        },
        _K(), "default",
    )
    assert isinstance(prov, IDRAC8Provisioner)
    assert prov.bootstrap_thumbprint == "abcd"
    assert prov.reset is True


# -- review follow-ups: transport hardening --------------------------------


def test_soap_fault_is_reported_even_on_a_500():
    """iDRAC returns domain faults as HTTP 500 with a fault body."""
    body = "<s:Fault><s:Reason><s:Text>InvalidParameter</s:Text></s:Reason></s:Fault>"
    client = _client_with(_FakeResponse(_envelope_with(body), status_code=500))
    with pytest.raises(WSManError, match="InvalidParameter"):
        client.invoke("DCIM_iDRACCardService", "ImportSSLCertificate", {})


def test_unparseable_body_is_reported_rather_than_crashing():
    client = _client_with(_FakeResponse(b"<not xml", status_code=200))
    with pytest.raises(WSManError, match="unparseable"):
        client.invoke("DCIM_iDRACCardService", "X", {})


def test_invoke_does_not_follow_redirects():
    """A redirect would carry Basic credentials off the pinned connection."""
    body = '<n1:X_OUTPUT xmlns:n1="x"><n1:ReturnValue>0</n1:ReturnValue></n1:X_OUTPUT>'
    client = _client_with(_FakeResponse(_envelope_with(body)))
    client.invoke("DCIM_iDRACCardService", "X", {})
    assert client.session.allow_redirects is False


def test_invoke_refuses_a_class_it_has_no_selectors_for():
    client = _client_with(_FakeResponse(b""))
    with pytest.raises(WSManError, match="no WS-Man selectors"):
        client.invoke("DCIM_SomethingElse", "X", {})


def test_output_fields_does_not_merge_a_differently_prefixed_element():
    import xml.etree.ElementTree as ET

    root = ET.fromstring(
        _envelope_with(
            '<n1:DCIM_X_OUTPUT xmlns:n1="x"><n1:ReturnValue>2</n1:ReturnValue></n1:DCIM_X_OUTPUT>'
            '<n2:X_OUTPUT xmlns:n2="y"><n2:ReturnValue>0</n2:ReturnValue></n2:X_OUTPUT>'
        )
    )
    assert _output_fields(root, "X")["ReturnValue"] == "0"


def test_ca_bundle_replaces_the_system_trust_store(monkeypatch):
    """A BMC has no public identity; an explicit bundle must narrow, not widen."""
    contexts = []
    real_default = ssl.create_default_context

    def _spy_default(*a, **k):
        ctx = real_default(*a, **k)
        contexts.append(("default", ctx))
        return ctx

    monkeypatch.setattr(ssl, "create_default_context", _spy_default)
    loaded = {}
    monkeypatch.setattr(
        ssl.SSLContext, "load_verify_locations",
        lambda self, *a, **k: loaded.update(k),
    )
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: (_ for _ in ()).throw(OSError("stop")))

    prov = _provisioner(ca_bundle="-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n")
    with pytest.raises(ConnectionError):
        prov._peer_der(verify=True)

    # The default (system-trust) context must not have been used for the
    # verifying probe when an explicit bundle is configured.
    assert contexts == []
    assert "cadata" in loaded


# -- review follow-ups: reconcile safety -----------------------------------


def _stamp(delta):
    return (datetime.datetime.now(datetime.UTC) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_pending_request_name_is_recorded_before_the_request_is_created(monkeypatch):
    """A create we cannot confirm must still be findable next run."""
    kube = _FakeKube()
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: _FakeProv())

    reconcile_mod.reconcile_publication(kube, _pub())

    assert kube.events.index("status") < kube.events.index("create")


def test_a_second_signing_round_is_refused_right_after_the_first(monkeypatch):
    """Otherwise a non-converging round rotates the key and resets the BMC forever."""
    kube = _FakeKube()
    prov = _FakeProv(installed=None)
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: prov)

    reconcile_mod.reconcile_publication(
        kube, _pub(status={"lastSigningTime": _stamp(datetime.timedelta(minutes=-5))})
    )

    assert kube.status["phase"] == ERROR
    assert prov.csr_args is None  # the host's key was not rotated again
    assert kube.created == []


def test_signing_resumes_once_the_cooldown_has_passed(monkeypatch):
    kube = _FakeKube()
    prov = _FakeProv(installed=None)
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: prov)

    reconcile_mod.reconcile_publication(
        kube, _pub(status={"lastSigningTime": _stamp(datetime.timedelta(hours=-3))})
    )

    assert prov.csr_args is not None
    assert len(kube.created) == 1


def test_a_never_signed_request_is_eventually_failed(monkeypatch):
    kube = _FakeKube(request={
        "metadata": {"creationTimestamp": _stamp(datetime.timedelta(hours=-5))},
        "status": {"conditions": []},
    })
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: _FakeProv())

    reconcile_mod.reconcile_publication(kube, _pub(status={"pendingRequestName": "r"}))

    assert kube.status["phase"] == ERROR
    assert kube.deleted == ["r"]
    assert kube.status["pendingRequestName"] is None


def test_a_recent_unsigned_request_is_still_waited_on(monkeypatch):
    kube = _FakeKube(request={
        "metadata": {"creationTimestamp": _stamp(datetime.timedelta(minutes=-2))},
        "status": {"conditions": []},
    })
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: _FakeProv())

    reconcile_mod.reconcile_publication(kube, _pub(status={"pendingRequestName": "r"}))

    assert kube.status["phase"] == PENDING
    assert kube.deleted == []


def test_a_signed_certificate_missing_the_dns_names_is_not_imported(monkeypatch):
    """Importing it would be re-detected as stale and reset the BMC every run."""
    signed = _cert(dns=("wrong.example.com",))
    kube = _FakeKube(request={
        "status": {
            "conditions": [{"type": "Ready", "status": "True"}],
            "certificate": base64.b64encode(signed).decode(),
        }
    })
    prov = _FakeProv()
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: prov)

    reconcile_mod.reconcile_publication(kube, _pub(status={"pendingRequestName": "r"}))

    assert prov.imported is None
    assert kube.status["phase"] == ERROR
    assert "does not cover" in kube.status["message"]
    assert kube.deleted == ["r"]


def test_an_already_installed_certificate_is_not_imported_twice(monkeypatch):
    """A crash between import and status must not cause a second BMC reset."""
    signed = _cert()
    kube = _FakeKube(request={
        "status": {
            "conditions": [{"type": "Ready", "status": "True"}],
            "certificate": base64.b64encode(signed).decode(),
        }
    })
    prov = _FakeProv(installed=signed)
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: prov)

    reconcile_mod.reconcile_publication(kube, _pub(status={"pendingRequestName": "r"}))

    assert prov.imported is None  # skipped: the host already holds it
    assert kube.status["phase"] == PUBLISHED
    assert kube.status["publishedFingerprint"] == sha256_fingerprint(signed)


# -- review round 2 --------------------------------------------------------


def test_renew_before_longer_than_the_lifetime_is_an_error(monkeypatch):
    """Otherwise the cert is 'due' the instant it is issued: reboot every round."""
    pem = _cert(days_valid=90)
    kube = _FakeKube()
    prov = _FakeProv(installed=pem)
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: prov)

    reconcile_mod.reconcile_publication(
        kube, _pub(renewBefore="8760h", status={"publishedFingerprint": sha256_fingerprint(pem)})
    )

    assert kube.status["phase"] == ERROR
    assert "longer than the lifetime" in kube.status["message"]
    assert prov.csr_args is None
    assert kube.created == []


def test_an_invalid_renew_before_is_reported_not_raised(monkeypatch):
    pem = _cert()
    kube = _FakeKube()
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: _FakeProv(installed=pem))

    reconcile_mod.reconcile_publication(kube, _pub(renewBefore="5d"))

    assert kube.status["phase"] == ERROR
    assert "not a valid duration" in kube.status["message"]


def test_a_sane_renew_before_still_renews(monkeypatch):
    kube = _FakeKube()
    prov = _FakeProv(installed=_cert(days_valid=90, age_days=85))
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: prov)

    reconcile_mod.reconcile_publication(kube, _pub(renewBefore="720h"))

    assert len(kube.created) == 1


def test_no_request_is_created_when_its_name_cannot_be_recorded(monkeypatch):
    """The pre-create status write is the record that makes the CR findable."""
    class _StatusFails(_FakeKube):
        def patch_publication_status(self, namespace, name, status):
            self.events.append("status")
            raise RuntimeError("api server said no")

    kube = _StatusFails()
    prov = _FakeProv(installed=None)
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: prov)

    with pytest.raises(RuntimeError, match="api server said no"):
        reconcile_mod.reconcile_publication(kube, _pub())

    assert kube.created == []  # no orphaned CertificateRequest


def test_the_cooldown_message_does_not_claim_an_import_happened(monkeypatch):
    """lastSigningTime is stamped at CSR generation, before anything is signed."""
    kube = _FakeKube()
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: _FakeProv(installed=None))

    reconcile_mod.reconcile_publication(
        kube, _pub(status={"lastSigningTime": _stamp(datetime.timedelta(minutes=-5))})
    )

    message = kube.status["message"]
    assert "signing round started" in message
    assert "was signed and imported" not in message


# -- first contact with real hardware --------------------------------------


def test_key_usages_come_from_the_csr_not_the_publication():
    """cert-manager demands the declared key usages match the CSR exactly."""
    from cert_publisher.certmanager import csr_usages

    # An iDRAC8 encodes contentCommitment, which no publication here declares.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "h.example.com")]))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )
    assert csr_usages(csr) == [
        "digital signature", "content commitment", "key encipherment",
    ]

    body = build_certificate_request_body(
        _pub(usages=["server auth", "digital signature", "key encipherment"]),
        "n", csr,
    )
    # The CSR carries no extendedKeyUsage, so no extended usage is declared --
    # declaring "server auth" is exactly what cert-manager rejected.
    assert body["spec"]["usages"] == [
        "digital signature", "content commitment", "key encipherment",
    ]


def test_a_csr_without_key_usages_falls_back_to_the_publication():
    from cert_publisher.certmanager import csr_usages

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "h.example.com")]))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )
    assert csr_usages(csr) == []
    body = build_certificate_request_body(_pub(usages=["server auth"]), "n", csr)
    assert "usages" not in body["spec"]




def test_editing_the_publication_clears_the_signing_cooldown(monkeypatch):
    """An operator fixing the spec shouldn't have to wait out a retry limit."""
    kube = _FakeKube()
    prov = _FakeProv(installed=None)
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: prov)

    pub = _pub(status={
        "lastSigningTime": _stamp(datetime.timedelta(minutes=-5)),
        "observedGeneration": 1,
    })
    pub["metadata"]["generation"] = 2  # the spec was edited

    reconcile_mod.reconcile_publication(kube, pub)

    assert prov.csr_args is not None
    assert len(kube.created) == 1
    assert kube.status["phase"] == PENDING


def test_the_cooldown_still_holds_when_the_spec_is_unchanged(monkeypatch):
    kube = _FakeKube()
    prov = _FakeProv(installed=None)
    monkeypatch.setattr(reconcile_mod, "build_provisioner", lambda *a: prov)

    pub = _pub(status={
        "lastSigningTime": _stamp(datetime.timedelta(minutes=-5)),
        "observedGeneration": 1,
    })
    pub["metadata"]["generation"] = 1

    reconcile_mod.reconcile_publication(kube, pub)

    assert prov.csr_args is None
    assert kube.status["phase"] == ERROR
    assert "Editing the publication retries immediately" in kube.status["message"]


def test_extended_key_usages_are_derived_when_the_csr_carries_them():
    """Hosts that do encode an EKU should have it declared, unlike an iDRAC8."""
    from cert_publisher.certmanager import csr_usages

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "h.example.com")]))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )
    assert csr_usages(csr) == [
        "digital signature", "key encipherment", "server auth", "client auth",
    ]
