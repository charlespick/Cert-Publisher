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
    now = datetime.datetime.now(datetime.UTC)
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


def _self_signed_pair() -> tuple[bytes, bytes]:
    """A self-signed leaf and its unencrypted private key, both PEM."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
    now = datetime.datetime.now(datetime.UTC)
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
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


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


class _FakeErrorRecord:
    """Stands in for a pypsrp ErrorRecord.

    ``_error_text`` reads these with ``str()``, which on a real ErrorRecord
    renders its ``ToString`` -- and yields the literal "None" when the record
    carries none, which is why that case is worth simulating.
    """

    def __init__(self, text):
        self._text = text

    def __str__(self):
        return self._text


class _Streams:
    def __init__(self):
        self.error = []


class _RecordingPool:
    """Stands in for a pypsrp RunspacePool, recording each invoked pipeline.

    ``PowerShell`` is patched to ``_FakePowerShell`` in the tests below, so
    every ``_invoke`` lands here as (script text, bound parameters) instead of
    going near a socket.

    ``outputs`` supplies the output objects successive pipelines return.
    ``errors`` is the error stream every pipeline reports, and ``had_errors``
    says whether that counts as a failed pipeline (a terminating error) or a
    pipeline that merely wrote to the error stream.
    """

    def __init__(self, outputs=None, errors=None, had_errors=False):
        self.invocations = []
        self.keys_exchanged = False
        self.errors = list(errors or [])
        self.had_errors = had_errors
        self._outputs = list(outputs or [])

    def exchange_keys(self):
        self.keys_exchanged = True

    def serialize(self, value, metadata):
        # The real pool encrypts this under the negotiated session key; all the
        # tests need is to see that the value went through the SecureString path.
        return ("secure-string", metadata.tag, value)


class _FakePowerShell:
    def __init__(self, pool):
        self.pool = pool
        self.script = None
        self.parameters = {}
        self.had_errors = False
        self.streams = _Streams()
        self.output = []

    def add_script(self, script):
        self.script = script
        return self

    def add_parameter(self, name, value):
        self.parameters[name] = value
        return self

    def invoke(self):
        self.pool.invocations.append((self.script, self.parameters))
        self.had_errors = self.pool.had_errors
        self.streams.error = [_FakeErrorRecord(text) for text in self.pool.errors]
        if self.pool._outputs:
            self.output = self.pool._outputs.pop(0)


def _winrm_provisioner():
    from cert_publisher.provisioners.base import Credentials
    from cert_publisher.provisioners.winrm import WinRMProvisioner

    return WinRMProvisioner(
        host="win01.example.com", port=5986, username="Administrator",
        thumbprint="AA:BB", transport="ntlm", credentials=Credentials(password="p"),
        mode="file", store_location="LocalMachine", store_name="My",
        cert_path="C:\\certs\\web.crt", key_path=None, post_install_script=None,
    )


def test_winrm_rejects_a_transport_pypsrp_cannot_speak():
    import pytest

    from cert_publisher.provisioners.base import Credentials
    from cert_publisher.provisioners.winrm import WinRMProvisioner

    with pytest.raises(ValueError, match="unsupported winrm transport"):
        WinRMProvisioner(
            host="win01.example.com", port=5986, username="Administrator",
            thumbprint="AA:BB", transport="kerberos5",
            credentials=Credentials(password="p"),
            mode="file", store_location="LocalMachine", store_name="My",
            cert_path="C:\\certs\\web.crt", key_path=None, post_install_script=None,
        )


def test_winrm_wsman_pins_thumbprint_on_live_connection(monkeypatch):
    import requests

    from cert_publisher.provisioners import winrm as winrm_mod

    real_requests_session = requests.Session()

    class _FakeTransport:
        endpoint = "https://win01.example.com:5986/wsman"
        session = None

        def _build_session(self):
            return real_requests_session

    class _FakeWSMan:
        def __init__(self, server, **kwargs):
            self.server = server
            self.kwargs = kwargs
            self.transport = _FakeTransport()

    monkeypatch.setattr(winrm_mod, "WSMan", _FakeWSMan)

    prov = _winrm_provisioner()  # thumbprint "AA:BB" normalises to "AABB"
    wsman = prov._wsman()

    # pypsrp itself is told not to validate; the pin is enforced on the real
    # request connection instead, which pypsrp would otherwise only build on
    # its first send.
    assert wsman.kwargs["cert_validation"] is False
    assert wsman.kwargs["auth"] == "ntlm"
    assert wsman.transport.session is real_requests_session
    adapter = real_requests_session.get_adapter("https://win01.example.com:5986/wsman")
    assert isinstance(adapter, winrm_mod._PinnedHTTPAdapter)
    pool_kw = adapter.poolmanager.connection_pool_kw
    assert pool_kw["assert_fingerprint"] == "AABB"
    assert pool_kw["cert_reqs"] == "CERT_NONE"


def test_winrm_refuses_to_pin_after_a_request_could_have_gone_out():
    import pytest

    class _UsedTransport:
        endpoint = "https://win01.example.com:5986/wsman"
        session = object()

    class _UsedWSMan:
        transport = _UsedTransport()

    prov = _winrm_provisioner()
    with pytest.raises(RuntimeError, match="already holds a request session"):
        prov._pin_transport(_UsedWSMan())


def test_pinned_adapter_accepts_matching_cert_and_rejects_others(tmp_path):
    """Prove the pin actually enforces the thumbprint on a live TLS handshake,
    not just that the right kwargs reach urllib3."""
    import hashlib
    import http.server
    import ssl
    import threading

    import requests

    from cert_publisher.provisioners.winrm import _PinnedHTTPAdapter

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
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
    cert_file = tmp_path / "cert.pem"
    key_file = tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    matching = hashlib.sha1(der).hexdigest().upper()

    class _QuietHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _QuietHandler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    # Swallow the connection-reset noise from handshakes the client aborts.
    httpd.handle_error = lambda request, client_address: None
    port = httpd.socket.getsockname()[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        url = f"https://127.0.0.1:{port}/"

        ok = requests.Session()
        ok.verify = False
        ok.mount("https://", _PinnedHTTPAdapter(matching))
        # The server has no GET handler, so a 501 back proves the TLS peer was
        # accepted. urllib3 normalises the fingerprint, so lower-case matches too.
        assert ok.get(url, timeout=5).status_code == 501
        ok.mount("https://", _PinnedHTTPAdapter(matching.lower()))
        assert ok.get(url, timeout=5).status_code == 501

        bad = requests.Session()
        bad.verify = False
        bad.mount("https://", _PinnedHTTPAdapter("0" * 40))
        try:
            bad.get(url, timeout=5)
            raise AssertionError("expected the pinned adapter to reject the cert")
        except requests.exceptions.SSLError:
            pass
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_winrm_write_file_binds_the_payload_as_a_parameter(monkeypatch):
    from cert_publisher.provisioners import winrm as winrm_mod

    monkeypatch.setattr(winrm_mod, "PowerShell", _FakePowerShell)

    prov = _winrm_provisioner()
    pool = _RecordingPool()
    prov._write_file(pool, "C:\\certs\\web.crt", b"hello")

    (script, params), = pool.invocations
    # One pipeline, running the bundled script verbatim -- no chunked upload,
    # no base64 staging file, nothing spliced into the script text.
    assert script == winrm_mod._script("write-file.ps1")
    assert params == {"Path": "C:\\certs\\web.crt", "Content": b"hello"}
    assert "hello" not in script


def test_winrm_cert_store_install_binds_the_pfx_password_as_a_secure_string(monkeypatch):
    from cert_publisher.provisioners import winrm as winrm_mod

    monkeypatch.setattr(winrm_mod, "PowerShell", _FakePowerShell)

    prov = _winrm_provisioner()
    prov.mode = "certStore"
    pool = _RecordingPool()
    cert_pem, key_pem = _self_signed_pair()
    prov._install_cert_store(pool, cert_pem, key_pem)

    (script, params), = pool.invocations
    assert script == winrm_mod._script("install-cert-store.ps1")
    assert isinstance(params["PfxBytes"], bytes)
    assert params["StoreLocation"] == "LocalMachine"
    assert params["StoreName"] == "My"
    assert params["Exportable"] is False

    # The random per-install password reaches the host only as a SecureString
    # bound parameter, negotiated over an exchanged session key -- never as
    # script text and never alongside the PFX in any other parameter.
    assert pool.keys_exchanged
    kind, tag, password = params["Password"]
    assert (kind, tag) == ("secure-string", "SS")
    assert password not in script
    assert not any(password in str(v) for name, v in params.items() if name != "Password")


def test_winrm_cert_store_probe_binds_the_thumbprint_and_reports_drift(monkeypatch):
    from cert_publisher.provisioners import winrm as winrm_mod

    monkeypatch.setattr(winrm_mod, "PowerShell", _FakePowerShell)

    prov = _winrm_provisioner()
    prov.mode = "certStore"
    prov.exportable_private_key = True
    cert_pem = _self_signed()

    pool = _RecordingPool(outputs=[["present:sealed"]])
    assert prov._cert_store_is_current(pool, cert_pem) is True
    (script, params), = pool.invocations
    assert script == winrm_mod._script("probe-cert-store.ps1")
    assert params["Thumbprint"] == sha1_thumbprint(cert_pem)
    assert "exportablePrivateKey is enabled" in prov.pending_warning

    # An absent certificate reads as not current, with no drift warning.
    prov.pending_warning = None
    assert prov._cert_store_is_current(_RecordingPool(outputs=[["absent"]]), cert_pem) is False
    assert prov.pending_warning is None


def test_winrm_file_mode_compares_the_remote_leaf_thumbprint(monkeypatch):
    import base64

    from cert_publisher.provisioners import winrm as winrm_mod

    monkeypatch.setattr(winrm_mod, "PowerShell", _FakePowerShell)

    prov = _winrm_provisioner()
    cert_pem = _self_signed()
    remote = base64.b64encode(cert_pem).decode()

    assert prov._file_is_current(_RecordingPool(outputs=[[remote]]), cert_pem) is True
    assert prov._file_is_current(_RecordingPool(outputs=[[]]), cert_pem) is False
    assert prov._file_is_current(_RecordingPool(outputs=[[remote]]), _self_signed()) is False


def test_winrm_post_install_runs_in_the_configured_psrp_endpoint(monkeypatch):
    from cert_publisher.provisioners import winrm as winrm_mod

    pool = _RecordingPool()
    opened = {}

    class _FakeRunspacePool:
        def __init__(self, wsman, configuration_name="Microsoft.PowerShell", host=None):
            opened["configuration_name"] = configuration_name
            opened["host"] = host

        def __enter__(self):
            return pool

        def __exit__(self, *exc):
            return None

    monkeypatch.setattr(winrm_mod, "RunspacePool", _FakeRunspacePool)
    monkeypatch.setattr(winrm_mod, "PowerShell", _FakePowerShell)

    prov = _winrm_provisioner()
    prov.post_install_script = "Write-Host hi"
    prov.powershell = "7"
    cert_pem = _self_signed()
    prov._run_post_install(object(), cert_pem)

    # PowerShell 7 means a different PSRP session configuration, not a
    # pwsh.exe child process.
    assert opened["configuration_name"] == "PowerShell.7"
    # The operator's script is the one cert-publisher didn't write, so it's the
    # one that might prompt; it must never run hostless.
    assert opened["host"] is not None
    (script, params), = pool.invocations
    assert script == winrm_mod._script("run-post-install.ps1")
    assert params == {"Script": "Write-Host hi", "Thumbprint": sha1_thumbprint(cert_pem)}
    assert "Write-Host hi" not in script


def test_winrm_install_and_probe_runspaces_get_a_host(monkeypatch):
    from cert_publisher.provisioners import winrm as winrm_mod

    pool = _RecordingPool(outputs=[["absent"]])
    opened = []

    class _FakeWSMan:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

    class _FakeRunspacePool:
        def __init__(self, wsman, configuration_name="Microsoft.PowerShell", host=None):
            opened.append(host)

        def __enter__(self):
            return pool

        def __exit__(self, *exc):
            return None

    monkeypatch.setattr(winrm_mod, "RunspacePool", _FakeRunspacePool)
    monkeypatch.setattr(winrm_mod, "PowerShell", _FakePowerShell)
    monkeypatch.setattr(winrm_mod.WinRMProvisioner, "_verify_endpoint", lambda self: None)
    monkeypatch.setattr(winrm_mod.WinRMProvisioner, "_wsman", lambda self: _FakeWSMan())

    prov = _winrm_provisioner()
    prov.mode = "certStore"
    cert_pem, key_pem = _self_signed_pair()

    assert prov.is_current(cert_pem) is False
    prov.install(cert_pem, key_pem)

    # Even cert-publisher's own scripts can prompt -- every parameter is
    # mandatory, so one that failed to bind would ask -- and a hostless
    # runspace never answers, hanging the run instead of failing it.
    assert len(opened) == 2
    assert all(host is not None for host in opened)


def test_bundled_powershell_scripts_are_static_and_parameterised():
    from cert_publisher.provisioners import winrm as winrm_mod

    for name in (
        "probe-cert-store.ps1",
        "install-cert-store.ps1",
        "write-file.ps1",
        "read-file-b64.ps1",
        "run-post-install.ps1",
    ):
        script = winrm_mod._script(name)
        assert "param(" in script
        # The two patterns that made the old transport read as a dropper:
        # an encoded command line, and a secret turned back into a
        # SecureString from plaintext on the host.
        assert "encodedcommand" not in script.lower()
        assert "ConvertTo-SecureString" not in script


def test_winrm_invoke_raises_with_the_remote_error_text(monkeypatch):
    import pytest

    from cert_publisher.provisioners import winrm as winrm_mod

    monkeypatch.setattr(winrm_mod, "PowerShell", _FakePowerShell)

    prov = _winrm_provisioner()
    pool = _RecordingPool(
        errors=["Access is denied", "The store could not be opened"],
        had_errors=True,
    )
    with pytest.raises(RuntimeError) as excinfo:
        prov._write_file(pool, "C:\\certs\\web.crt", b"hello")

    message = str(excinfo.value)
    assert "write-file.ps1 failed on the remote host" in message
    assert "Access is denied" in message
    assert "The store could not be opened" in message


def test_winrm_invoke_raises_even_when_the_host_returned_no_detail(monkeypatch):
    import pytest

    from cert_publisher.provisioners import winrm as winrm_mod

    monkeypatch.setattr(winrm_mod, "PowerShell", _FakePowerShell)

    prov = _winrm_provisioner()
    with pytest.raises(RuntimeError, match="no error detail returned by the host"):
        prov._write_file(_RecordingPool(had_errors=True), "C:\\certs\\web.crt", b"hello")


def test_winrm_invoke_tolerates_non_terminating_errors_but_logs_them(monkeypatch, caplog):
    import logging

    from cert_publisher.provisioners import winrm as winrm_mod

    monkeypatch.setattr(winrm_mod, "PowerShell", _FakePowerShell)

    prov = _winrm_provisioner()
    pool = _RecordingPool(errors=["something non-fatal"], had_errors=False)
    with caplog.at_level(logging.WARNING, logger="cert-publisher.winrm"):
        prov._write_file(pool, "C:\\certs\\web.crt", b"hello")
    assert "something non-fatal" in caplog.text


def test_winrm_error_text_skips_records_that_carry_no_message():
    from cert_publisher.provisioners import winrm as winrm_mod

    powershell = _FakePowerShell(_RecordingPool())
    powershell.streams.error = [_FakeErrorRecord(t) for t in ("None", "real failure", "   ")]
    assert winrm_mod._error_text(powershell) == "real failure"

    powershell.streams.error = []
    assert winrm_mod._error_text(powershell) == "no error detail returned by the host"


def test_winrm_host_refuses_prompts_instead_of_blocking_on_them():
    import pytest

    from cert_publisher.provisioners import winrm as winrm_mod

    host = winrm_mod._unattended_host()

    # A prompting hook would otherwise wedge the run: with no answer to the
    # host call, poll_invoke swallows the operation timeout and retries forever.
    for call, args in (
        ("ReadLine", ()),
        ("ReadLineAsSecureString", ()),
        ("Prompt", ("Caption", "Message", [])),
        ("PromptForCredential1", ("Caption", "Message", "user", "target")),
        ("PromptForCredential2", ("Caption", "Message", "user", "target", 1, 0)),
        ("PromptForChoice", ("Caption", "Message", [], 0)),
    ):
        with pytest.raises(RuntimeError, match="cannot answer prompts"):
            getattr(host.ui, call)(None, None, *args)

    with pytest.raises(RuntimeError, match="cannot answer prompts"):
        host.ui.raw_ui.ReadKey(None, None)
    with pytest.raises(RuntimeError, match="cannot answer prompts"):
        host.EnterNestedPrompt(None, None)

    # Every non-interactive getter must answer something: pypsrp only replies
    # when the method returns non-None, so a None here hangs exactly like
    # having no host at all.
    assert host.GetName(None, None)
    assert host.GetInstanceId(None, None)
    assert host.GetCurrentCulture(None, None) is not None
    assert host.GetCurrentUICulture(None, None) is not None
    assert host.ui.raw_ui.GetBufferSize(None, None) is not None


def test_winrm_accepts_legacy_pywinrm_transport_names():
    from cert_publisher.provisioners.base import Credentials
    from cert_publisher.provisioners.winrm import WinRMProvisioner

    def _build(transport):
        return WinRMProvisioner(
            host="win01.example.com", port=5986, username="Administrator",
            thumbprint="AA:BB", transport=transport,
            credentials=Credentials(password="p"),
            mode="file", store_location="LocalMachine", store_name="My",
            cert_path="C:\\certs\\web.crt", key_path=None, post_install_script=None,
        )

    # pywinrm distinguished these only by whether the listener was HTTPS, which
    # cert-publisher requires anyway; both are basic auth to pypsrp.
    assert _build("ssl").transport == "basic"
    assert _build("plaintext").transport == "basic"
    assert _build("kerberos").transport == "kerberos"


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

