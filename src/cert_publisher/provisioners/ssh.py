"""SSH provisioner: install a certificate over SFTP and reload the service."""

from __future__ import annotations

import base64
import hashlib
import io
import logging
import stat

import paramiko

from ..utils import sha256_fingerprint
from .base import Credentials, Provisioner, resolve_credentials

log = logging.getLogger("cert-publisher.ssh")


class _FingerprintPolicy(paramiko.MissingHostKeyPolicy):
    """Pin the host key to an operator-supplied SHA-256 fingerprint.

    The expected value matches OpenSSH output, e.g. ``SHA256:abc...`` (base64,
    no padding). This is what authenticates the target host.
    """

    def __init__(self, expected: str) -> None:
        self.expected = expected.strip()

    def missing_host_key(self, client, hostname, key) -> None:
        digest = hashlib.sha256(key.asbytes()).digest()
        got = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
        if got != self.expected:
            raise paramiko.SSHException(
                f"host key fingerprint mismatch for {hostname}: "
                f"expected {self.expected}, got {got}"
            )


class SSHProvisioner(Provisioner):
    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        host_fingerprint: str,
        credentials: Credentials,
        cert_path: str,
        key_path: str,
        cert_mode: int,
        key_mode: int,
        post_install_script: str | None,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.host_fingerprint = host_fingerprint
        self.credentials = credentials
        self.cert_path = cert_path
        self.key_path = key_path
        self.cert_mode = cert_mode
        self.key_mode = key_mode
        self.post_install_script = post_install_script

    @classmethod
    def from_spec(cls, spec: dict, kube, namespace: str) -> "SSHProvisioner":
        return cls(
            host=spec["host"],
            port=int(spec.get("port", 22)),
            username=spec["username"],
            host_fingerprint=spec["hostFingerprint"],
            credentials=resolve_credentials(spec.get("auth", {}), kube, namespace),
            cert_path=spec["certPath"],
            key_path=spec["keyPath"],
            cert_mode=int(str(spec.get("fileMode", "0644")), 8),
            key_mode=int(str(spec.get("keyFileMode", "0600")), 8),
            post_install_script=spec.get("postInstallScript"),
        )

    def _connect(self) -> paramiko.SSHClient:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(_FingerprintPolicy(self.host_fingerprint))

        kwargs: dict = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if self.credentials.private_key:
            kwargs["pkey"] = paramiko.PKey.from_private_key(
                io.StringIO(self.credentials.private_key),
                password=self.credentials.passphrase,
            )
        elif self.credentials.password:
            kwargs["password"] = self.credentials.password
        else:
            raise ValueError("ssh provisioner requires a password or privateKey")

        c.connect(**kwargs)
        return c

    def is_current(self, cert_pem: bytes) -> bool:
        desired = sha256_fingerprint(cert_pem)
        client = self._connect()
        try:
            sftp = client.open_sftp()
            try:
                with sftp.open(self.cert_path, "rb") as fh:
                    existing = fh.read()
            except IOError:
                return False  # not installed yet
            finally:
                sftp.close()
        finally:
            client.close()
        try:
            return sha256_fingerprint(existing) == desired
        except ValueError:
            return False

    def install(self, cert_pem: bytes, key_pem: bytes) -> None:
        client = self._connect()
        try:
            sftp = client.open_sftp()
            try:
                self._put(sftp, self.cert_path, cert_pem, self.cert_mode)
                self._put(sftp, self.key_path, key_pem, self.key_mode)
            finally:
                sftp.close()

            if self.post_install_script:
                log.info("[%s] running post-install script", self.host)
                _, stdout, stderr = client.exec_command(self.post_install_script)
                rc = stdout.channel.recv_exit_status()
                if rc != 0:
                    err = stderr.read().decode(errors="replace")
                    raise RuntimeError(f"post-install script exited {rc}: {err}")
        finally:
            client.close()

    @staticmethod
    def _put(sftp, path: str, data: bytes, mode: int) -> None:
        with sftp.open(path, "wb") as fh:
            fh.write(data)
        sftp.chmod(path, stat.S_IMODE(mode))
