"""WinRM provisioner: install into the Windows cert store or drop files."""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import socket
import ssl

import winrm
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    load_pem_private_key,
)
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import load_pem_x509_certificates

from ..utils import sha1_thumbprint
from .base import Credentials, Provisioner, resolve_credentials

log = logging.getLogger("cert-publisher.winrm")

MODE_CERT_STORE = "certStore"
MODE_FILE = "file"


class WinRMProvisioner(Provisioner):
    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        thumbprint: str,
        transport: str,
        credentials: Credentials,
        mode: str,
        store_location: str,
        store_name: str,
        cert_path: str | None,
        key_path: str | None,
        post_install_script: str | None,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.thumbprint = thumbprint.replace(":", "").replace(" ", "").upper()
        self.transport = transport
        self.credentials = credentials
        self.mode = mode
        self.store_location = store_location
        self.store_name = store_name
        self.cert_path = cert_path
        self.key_path = key_path
        self.post_install_script = post_install_script

    @classmethod
    def from_spec(cls, spec: dict, kube, namespace: str) -> "WinRMProvisioner":
        return cls(
            host=spec["host"],
            port=int(spec.get("port", 5986)),
            username=spec["username"],
            thumbprint=spec["thumbprint"],
            transport=spec.get("transport", "ntlm"),
            credentials=resolve_credentials(spec.get("auth", {}), kube, namespace),
            mode=spec.get("mode", MODE_CERT_STORE),
            store_location=spec.get("storeLocation", "LocalMachine"),
            store_name=spec.get("storeName", "My"),
            cert_path=spec.get("certPath"),
            key_path=spec.get("keyPath"),
            post_install_script=spec.get("postInstallScript"),
        )

    # -- host verification ------------------------------------------------

    def _verify_endpoint(self) -> None:
        """Pin the WinRM HTTPS listener to the configured SHA-1 thumbprint."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((self.host, self.port), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=self.host) as tls:
                der = tls.getpeercert(binary_form=True)
        got = hashlib.sha1(der).hexdigest().upper()
        if got != self.thumbprint:
            raise RuntimeError(
                f"WinRM endpoint thumbprint mismatch for {self.host}: "
                f"expected {self.thumbprint}, got {got}"
            )

    def _session(self) -> winrm.Session:
        if not self.credentials.password:
            raise ValueError("winrm provisioner requires a password")
        return winrm.Session(
            f"https://{self.host}:{self.port}/wsman",
            auth=(self.username, self.credentials.password),
            transport=self.transport,
            server_cert_validation="ignore",  # verified out-of-band by thumbprint
        )

    def _run_ps(self, session: winrm.Session, script: str) -> str:
        result = session.run_ps(script)
        if result.status_code != 0:
            raise RuntimeError(
                f"PowerShell exited {result.status_code}: "
                f"{result.std_err.decode(errors='replace')}"
            )
        return result.std_out.decode(errors="replace")

    # -- provisioner interface -------------------------------------------

    def is_current(self, cert_pem: bytes) -> bool:
        self._verify_endpoint()
        session = self._session()
        if self.mode == MODE_CERT_STORE:
            thumb = sha1_thumbprint(cert_pem)
            path = f"Cert:\\{self.store_location}\\{self.store_name}\\{thumb}"
            out = self._run_ps(session, f"Test-Path '{path}'")
            return out.strip().lower() == "true"

        # file mode: compare the SHA-1 of the remote cert file
        remote = self._run_ps(
            session,
            f"if (Test-Path '{self.cert_path}') "
            f"{{ [Convert]::ToBase64String([IO.File]::ReadAllBytes('{self.cert_path}')) }}",
        ).strip()
        if not remote:
            return False
        return hashlib.sha1(base64.b64decode(remote)).hexdigest() == hashlib.sha1(
            cert_pem
        ).hexdigest()

    def install(self, cert_pem: bytes, key_pem: bytes) -> None:
        self._verify_endpoint()
        session = self._session()
        if self.mode == MODE_CERT_STORE:
            self._install_cert_store(session, cert_pem, key_pem)
        elif self.mode == MODE_FILE:
            self._install_files(session, cert_pem, key_pem)
        else:
            raise ValueError(f"unknown winrm mode: {self.mode!r}")

        if self.post_install_script:
            log.info("[%s] running post-install script", self.host)
            self._run_ps(session, self.post_install_script)

    def _install_cert_store(
        self, session: winrm.Session, cert_pem: bytes, key_pem: bytes
    ) -> None:
        certs = load_pem_x509_certificates(cert_pem)
        key = load_pem_private_key(key_pem, password=None)
        pfx_password = secrets.token_urlsafe(24)
        pfx = pkcs12.serialize_key_and_certificates(
            name=b"cert-publisher",
            key=key,
            cert=certs[0],
            cas=certs[1:] or None,
            encryption_algorithm=BestAvailableEncryption(pfx_password.encode()),
        )
        b64 = base64.b64encode(pfx).decode()
        script = f"""
$ErrorActionPreference = 'Stop'
$bytes = [Convert]::FromBase64String('{b64}')
$tmp = [IO.Path]::GetTempFileName()
[IO.File]::WriteAllBytes($tmp, $bytes)
try {{
    $pw = ConvertTo-SecureString '{pfx_password}' -AsPlainText -Force
    $store = 'Cert:\\{self.store_location}\\{self.store_name}'
    Import-PfxCertificate -FilePath $tmp -CertStoreLocation $store -Password $pw | Out-Null
}} finally {{
    Remove-Item $tmp -Force
}}
"""
        self._run_ps(session, script)

    def _install_files(
        self, session: winrm.Session, cert_pem: bytes, key_pem: bytes
    ) -> None:
        self._write_file(session, self.cert_path, cert_pem)
        if self.key_path:
            self._write_file(session, self.key_path, key_pem)

    def _write_file(self, session: winrm.Session, path: str, data: bytes) -> None:
        b64 = base64.b64encode(data).decode()
        self._run_ps(
            session,
            f"[IO.File]::WriteAllBytes('{path}', [Convert]::FromBase64String('{b64}'))",
        )
