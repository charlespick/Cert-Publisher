"""Dell iDRAC8 provisioner: install the iDRAC HTTPS certificate over Redfish.

iDRAC8 (12th/13th-gen PowerEdge) applies a new HTTPS certificate only through
the Dell OEM Redfish actions under ``DelliDRACCardService`` -- the DMTF-standard
``CertificateService`` actions used by iDRAC9/10 are not available there -- and
always requires an iDRAC reboot before the new certificate takes effect.

Host identity is verified out of band before any credentials or key material are
sent, using two independent, complementary signals (see ``_verify_endpoint``):

* the live HTTPS certificate is *currently valid* (chains to a trusted CA,
  matches the hostname, unexpired), which keeps working across renewals once a
  real certificate has been installed; or
* the endpoint certificate's SHA-256 thumbprint matches a configured *bootstrap*
  value, which covers the first run against the iDRAC's factory self-signed
  certificate, before any trusted certificate exists.

Either signal is sufficient, so a host moves seamlessly from first bootstrap
(thumbprint) to steady-state renewals (validity) with no configuration change.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import socket
import ssl

import requests
import urllib3
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    load_pem_private_key,
    pkcs12,
)
from cryptography.x509 import load_pem_x509_certificates

from ..utils import sha256_fingerprint
from .base import Credentials, Provisioner, resolve_credentials

log = logging.getLogger("cert-publisher.dellidrac8")

# The endpoint is authenticated out of band in ``_verify_endpoint``; the Redfish
# HTTP calls themselves then intentionally skip TLS verification (the iDRAC's own
# cert may be self-signed on first run), so silence urllib3's warning about it.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_SESSIONS = "/redfish/v1/SessionService/Sessions"
_IMPORT_ACTION = (
    "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService"
    "/Actions/DelliDRACCardService.ImportSSLCertificate"
)
_RESET_ACTION = "/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Manager.Reset"

# A cert-manager Secret carries the leaf and its private key; the only iDRAC
# certificate type that installs an externally supplied key pair is the custom
# PKCS#12 bundle, imported as this type with the bundle passphrase.
_CERT_TYPE = "CustomCertificate"

_TIMEOUT = 30
_CONNECT_TIMEOUT = 15


class DelliDRAC8Provisioner(Provisioner):
    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        credentials: Credentials,
        bootstrap_thumbprint: str | None,
        ca_bundle: str | None,
        reboot: bool,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.credentials = credentials
        self.bootstrap_thumbprint = (
            bootstrap_thumbprint.replace(":", "").replace(" ", "").upper()
            if bootstrap_thumbprint
            else None
        )
        self.ca_bundle = ca_bundle
        self.reboot = reboot

    @classmethod
    def from_spec(cls, spec: dict, kube, namespace: str) -> "DelliDRAC8Provisioner":
        return cls(
            host=spec["host"],
            port=int(spec.get("port", 443)),
            username=spec["username"],
            credentials=resolve_credentials(spec.get("auth", {}), kube, namespace),
            bootstrap_thumbprint=spec.get("bootstrapThumbprint"),
            ca_bundle=spec.get("caBundle"),
            reboot=bool(spec.get("reboot", True)),
        )

    @property
    def _base_url(self) -> str:
        return f"https://{self.host}:{self.port}"

    # -- host verification ------------------------------------------------

    def _peer_der(self) -> bytes:
        """Return the endpoint leaf certificate (DER) without validating it."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(
            (self.host, self.port), timeout=_CONNECT_TIMEOUT
        ) as sock:
            with ctx.wrap_socket(sock, server_hostname=self.host) as tls:
                return tls.getpeercert(binary_form=True)

    def _endpoint_currently_valid(self, trust_pem: bytes | None) -> bool:
        """Whether the live HTTPS cert validates against trusted CAs and hostname.

        Trust anchors are the system store, any operator-supplied ``caBundle``,
        and the issuing chain shipped alongside the leaf being published -- so a
        host already serving a certificate from the same CA verifies with no
        extra configuration. Hostname matching uses ``host``; for this signal to
        apply, ``host`` must be the name (or IP) present in the certificate.
        """
        ctx = ssl.create_default_context()  # system trust + hostname checking
        if self.ca_bundle:
            try:
                ctx.load_verify_locations(cadata=self.ca_bundle)
            except (ssl.SSLError, ValueError):
                log.warning("[%s] ignoring unparseable caBundle", self.host)
        if trust_pem:
            try:
                ctx.load_verify_locations(cadata=trust_pem.decode())
            except (ssl.SSLError, ValueError, UnicodeDecodeError):
                pass
        try:
            with socket.create_connection(
                (self.host, self.port), timeout=_CONNECT_TIMEOUT
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host):
                    return True
        except (ssl.SSLError, ssl.CertificateError, OSError):
            return False

    def _verify_endpoint(self, trust_pem: bytes | None = None) -> None:
        """Authenticate the iDRAC before sending credentials or key material.

        Accepts either a currently-valid endpoint certificate or a match against
        the configured bootstrap thumbprint; raises if neither holds.
        """
        if self._endpoint_currently_valid(trust_pem):
            return
        if self.bootstrap_thumbprint:
            got = hashlib.sha256(self._peer_der()).hexdigest().upper()
            if got == self.bootstrap_thumbprint:
                return
            raise RuntimeError(
                f"iDRAC endpoint at {self.host} is not currently trusted and its "
                f"certificate thumbprint does not match the configured bootstrap "
                f"value: expected {self.bootstrap_thumbprint}, got {got}"
            )
        raise RuntimeError(
            f"iDRAC endpoint at {self.host} is not currently trusted and no "
            f"bootstrapThumbprint is configured to verify it"
        )

    # -- Redfish session --------------------------------------------------

    def _open_session(self) -> tuple[requests.Session, str | None]:
        """Open a Redfish session, returning the session and its logout URI.

        Prefers token auth (``X-Auth-Token``) so the password is sent once, and
        falls back to Basic auth on every call if ``SessionService`` refuses.
        """
        if not self.credentials.password:
            raise ValueError("dellidrac8 provisioner requires a password")
        s = requests.Session()
        s.verify = False  # endpoint identity is checked out of band above
        s.headers["Content-Type"] = "application/json"
        resp = s.post(
            f"{self._base_url}{_SESSIONS}",
            json={"UserName": self.username, "Password": self.credentials.password},
            timeout=_TIMEOUT,
        )
        token = resp.headers.get("X-Auth-Token")
        if resp.status_code in (200, 201) and token:
            s.headers["X-Auth-Token"] = token
            return s, resp.headers.get("Location")
        s.auth = (self.username, self.credentials.password)
        return s, None

    def _close_session(self, s: requests.Session, location: str | None) -> None:
        try:
            if location:
                url = location if location.startswith("http") else f"{self._base_url}{location}"
                s.delete(url, timeout=_TIMEOUT)
        except requests.RequestException:
            pass  # best-effort logout; the session expires on its own regardless
        finally:
            s.close()

    # -- provisioner interface -------------------------------------------

    def is_current(self, cert_pem: bytes) -> bool:
        # The live HTTPS certificate is exactly what the iDRAC is serving, so
        # comparing its fingerprint to the desired leaf tells us whether the
        # target is already up to date (and, after a reboot, that the import and
        # restart have taken effect).
        self._verify_endpoint(cert_pem)
        return hashlib.sha256(self._peer_der()).hexdigest() == sha256_fingerprint(cert_pem)

    def install(self, cert_pem: bytes, key_pem: bytes) -> None:
        self._verify_endpoint(cert_pem)
        passphrase = secrets.token_urlsafe(24)
        pfx = self._build_pkcs12(cert_pem, key_pem, passphrase)
        payload = {
            "CertificateType": _CERT_TYPE,
            # Match Dell's reference tooling: binary PKCS#12 is base64-encoded.
            "SSLCertificateFile": base64.encodebytes(pfx).decode("ascii"),
            "Passphrase": passphrase,
        }
        session, location = self._open_session()
        try:
            self._import_certificate(session, payload)
            if self.reboot:
                self._reset(session)
        finally:
            self._close_session(session, location)

    @staticmethod
    def _build_pkcs12(cert_pem: bytes, key_pem: bytes, passphrase: str) -> bytes:
        certs = load_pem_x509_certificates(cert_pem)
        key = load_pem_private_key(key_pem, password=None)
        return pkcs12.serialize_key_and_certificates(
            name=b"cert-publisher",
            key=key,
            cert=certs[0],
            cas=certs[1:] or None,
            encryption_algorithm=BestAvailableEncryption(passphrase.encode()),
        )

    def _import_certificate(self, session: requests.Session, payload: dict) -> None:
        resp = session.post(
            f"{self._base_url}{_IMPORT_ACTION}", json=payload, timeout=_TIMEOUT
        )
        if resp.status_code not in (200, 202):
            raise RuntimeError(
                f"iDRAC certificate import failed ({resp.status_code}): "
                f"{self._error_detail(resp)}"
            )
        log.info(
            "[%s] certificate imported (%s)",
            self.host,
            self._message_id(resp) or resp.status_code,
        )

    def _reset(self, session: requests.Session) -> None:
        # iDRAC8 always requires a reboot to apply a newly imported HTTPS cert
        # (the "no reboot" improvement is iDRAC9 6.00.02+/iDRAC10 only).
        resp = session.post(
            f"{self._base_url}{_RESET_ACTION}",
            json={"ResetType": "GracefulRestart"},
            timeout=_TIMEOUT,
        )
        if resp.status_code not in (200, 202, 204):
            raise RuntimeError(
                f"iDRAC reset failed ({resp.status_code}): {self._error_detail(resp)}"
            )
        log.info(
            "[%s] iDRAC reboot requested; the new certificate applies once it is "
            "back up (typically ~2-3 min)",
            self.host,
        )

    # -- Redfish response parsing ----------------------------------------

    @staticmethod
    def _extended_info(resp: requests.Response) -> list[dict]:
        """Pull the ``@Message.ExtendedInfo`` list from a Redfish response body."""
        try:
            body = resp.json()
        except ValueError:
            return []
        if not isinstance(body, dict):
            return []
        info = body.get("@Message.ExtendedInfo")
        if info is None and isinstance(body.get("error"), dict):
            info = body["error"].get("@Message.ExtendedInfo")
        return info if isinstance(info, list) else []

    @classmethod
    def _message_id(cls, resp: requests.Response) -> str | None:
        for item in cls._extended_info(resp):
            if isinstance(item, dict) and item.get("MessageId"):
                return item["MessageId"]
        return None

    @classmethod
    def _error_detail(cls, resp: requests.Response) -> str:
        msgs = [
            item["Message"]
            for item in cls._extended_info(resp)
            if isinstance(item, dict) and item.get("Message")
        ]
        return "; ".join(msgs) if msgs else (resp.text[:500].strip() or "<no body>")
