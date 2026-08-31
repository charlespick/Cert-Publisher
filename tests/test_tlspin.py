"""The certificate pin is the security core of the WS-Man transport.

These tests stand up a real TLS listener and drive real ``requests`` through the
adapter, because the failure that matters is not "the code says pin" -- it is a
urllib3/requests upgrade quietly dropping ``assert_fingerprint`` support, which
only an end-to-end connection can catch.
"""

import datetime
import hashlib
import http.server
import ssl
import threading

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cert_publisher.tlspin import PinnedHTTPAdapter


def _write_self_signed(tmp_path) -> tuple[str, str, str]:
    """Return (certfile, keyfile, sha256-hex-of-DER)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    certfile = tmp_path / "cert.pem"
    keyfile = tmp_path / "key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    digest = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return str(certfile), str(keyfile), digest


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


@pytest.fixture
def tls_server(tmp_path):
    certfile, keyfile, digest = _write_self_signed(tmp_path)
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"https://127.0.0.1:{server.server_address[1]}/wsman", digest
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _session(fingerprint):
    session = requests.Session()
    session.verify = False
    session.mount("https://", PinnedHTTPAdapter(fingerprint))
    return session


def test_matching_fingerprint_connects(tls_server):
    url, digest = tls_server
    assert _session(digest).post(url, data=b"x", timeout=10).status_code == 200


def test_mismatched_fingerprint_is_refused(tls_server):
    url, _ = tls_server
    with pytest.raises(requests.exceptions.SSLError):
        _session("aa" * 32).post(url, data=b"x", timeout=10)


def test_fingerprint_is_accepted_with_colons_and_uppercase(tls_server):
    url, digest = tls_server
    colonised = ":".join(
        digest[i : i + 2] for i in range(0, len(digest), 2)
    ).upper()
    assert _session(colonised).post(url, data=b"x", timeout=10).status_code == 200


def test_wsman_client_pins_its_live_session(tls_server, monkeypatch):
    """The pin must be mounted by WSManClient itself, not just available to it."""
    from cert_publisher.wsman import WSManClient

    url, digest = tls_server
    host, port = url.split("//")[1].split("/")[0].split(":")

    good = WSManClient(
        host=host, port=int(port), username="u", password="p", pin_sha256=digest
    )
    # A real request over the client's own session must succeed...
    assert good.session.post(url, data=b"x", timeout=10).status_code == 200
    good.close()

    bad = WSManClient(
        host=host, port=int(port), username="u", password="p", pin_sha256="bb" * 32
    )
    # ...and be refused when the pin does not match the server.
    with pytest.raises(requests.exceptions.SSLError):
        bad.session.post(url, data=b"x", timeout=10)
    bad.close()
