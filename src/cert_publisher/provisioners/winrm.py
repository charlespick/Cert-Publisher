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

# Maximum base64 characters embedded in a single WinRM command. pywinrm wraps
# every ``run_ps`` script as ``powershell -EncodedCommand <utf16-base64>``,
# which inflates the script ~2.7x, and WinRS rejects over-long command lines
# ("line too long"). A multi-KB certificate cannot ride in one command, so we
# stream the payload to the remote host in chunks this size; 2000 leaves ample
# headroom for the surrounding PowerShell after encoding.
_UPLOAD_CHUNK = 2000


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
        mode = spec.get("mode", MODE_CERT_STORE)
        cert_path = spec.get("certPath")
        if mode == MODE_FILE and not cert_path:
            raise ValueError("winrm file mode requires certPath")
        return cls(
            host=spec["host"],
            port=int(spec.get("port", 5986)),
            username=spec["username"],
            thumbprint=spec["thumbprint"],
            transport=spec.get("transport", "ntlm"),
            credentials=resolve_credentials(spec.get("auth", {}), kube, namespace),
            mode=mode,
            store_location=spec.get("storeLocation", "LocalMachine"),
            store_name=spec.get("storeName", "My"),
            cert_path=cert_path,
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

    # -- chunked upload ---------------------------------------------------

    def _upload_b64(self, session: winrm.Session, data: bytes) -> str:
        """Stream ``data`` to a remote temp file as base64, in WinRM-safe chunks.

        Returns the path of the remote file holding the base64 text; callers
        decode it on the far side. Splitting the payload across many small
        commands keeps every WinRM command line well under the length limit that
        a single inlined certificate would otherwise exceed. The base64 alphabet
        contains no single quotes, so each chunk embeds safely in a PowerShell
        literal.
        """
        b64 = base64.b64encode(data).decode()
        remote = self._run_ps(session, "[IO.Path]::GetTempFileName()").strip()
        for start in range(0, len(b64), _UPLOAD_CHUNK):
            chunk = b64[start : start + _UPLOAD_CHUNK]
            writer = "WriteAllText" if start == 0 else "AppendAllText"
            self._run_ps(session, f"[IO.File]::{writer}('{remote}', '{chunk}')")
        return remote

    # -- provisioner interface -------------------------------------------

    def is_current(self, cert_pem: bytes) -> bool:
        self._verify_endpoint()
        session = self._session()
        if self.mode == MODE_CERT_STORE:
            thumb = sha1_thumbprint(cert_pem)
            path = f"Cert:\\{self.store_location}\\{self.store_name}\\{thumb}"
            out = self._run_ps(session, f"Test-Path '{path}'")
            return out.strip().lower() == "true"

        # file mode: compare the leaf thumbprint of the remote cert file, so
        # PEM formatting or chain differences don't trigger spurious reinstalls.
        remote = self._run_ps(
            session,
            f"if (Test-Path '{self.cert_path}') "
            f"{{ [Convert]::ToBase64String([IO.File]::ReadAllBytes('{self.cert_path}')) }}",
        ).strip()
        if not remote:
            return False
        try:
            return sha1_thumbprint(base64.b64decode(remote)) == sha1_thumbprint(cert_pem)
        except ValueError:
            return False  # remote file isn't a parseable certificate

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
            self._run_post_install(session)

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
        b64file = self._upload_b64(session, pfx)
        script = f"""
$ErrorActionPreference = 'Stop'
$b64file = '{b64file}'
$tmp = [IO.Path]::GetTempFileName()
try {{
    $bytes = [Convert]::FromBase64String([IO.File]::ReadAllText($b64file))
    [IO.File]::WriteAllBytes($tmp, $bytes)
    $pw = ConvertTo-SecureString '{pfx_password}' -AsPlainText -Force
    $store = 'Cert:\\{self.store_location}\\{self.store_name}'
    Import-PfxCertificate -FilePath $tmp -CertStoreLocation $store -Password $pw | Out-Null
}} finally {{
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    Remove-Item $b64file -Force -ErrorAction SilentlyContinue
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
        b64file = self._upload_b64(session, data)
        script = f"""
$ErrorActionPreference = 'Stop'
$b64file = '{b64file}'
try {{
    $bytes = [Convert]::FromBase64String([IO.File]::ReadAllText($b64file))
    [IO.File]::WriteAllBytes('{path}', $bytes)
}} finally {{
    Remove-Item $b64file -Force -ErrorAction SilentlyContinue
}}
"""
        self._run_ps(session, script)

    def _run_post_install(self, session: winrm.Session) -> None:
        """Upload the post-install hook and run it by path, never inlined.

        Operator-supplied scripts can be arbitrarily long, so we stream the
        script to a remote ``.ps1`` file (chunked, like certificate uploads) and
        dot-source it rather than embedding it in a single command. Base64 also
        sidesteps any quoting hazards in the script text itself.
        """
        b64file = self._upload_b64(session, self.post_install_script.encode("utf-8"))
        script = f"""
$ErrorActionPreference = 'Stop'
$b64file = '{b64file}'
$hook = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName() + '.ps1')
try {{
    $bytes = [Convert]::FromBase64String([IO.File]::ReadAllText($b64file))
    [IO.File]::WriteAllBytes($hook, $bytes)
    & $hook
    if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}
}} finally {{
    Remove-Item $hook -Force -ErrorAction SilentlyContinue
    Remove-Item $b64file -Force -ErrorAction SilentlyContinue
}}
"""
        self._run_ps(session, script)
