"""WinRM provisioner: install into the Windows cert store or drop files.

Everything runs over PSRP (PowerShell Remoting Protocol) rather than a WinRS
``cmd.exe`` shell. That matters for more than tidiness:

* Commands execute inside a remote runspace hosted by ``wsmprovhost.exe``.
  There is no ``cmd.exe``, no ``powershell.exe`` child process, and no
  ``-EncodedCommand`` on any command line -- the three patterns that make
  ordinary certificate installs look like commodity malware to EDR.
* Arguments, including the PFX bytes and its password, are bound parameters
  carried as CLIXML in the SOAP body. They never reach a command line, so they
  never reach Sysmon EID 1, the WSMan operational log, or anything forwarding
  those to a SIEM.
* Payloads ride in the message body, which has no command-line length limit,
  so a certificate is one pipeline rather than a burst of ~20 near-identical
  process spawns.

The scripts themselves are static files bundled in the package (see
``scripts/``); nothing is assembled from interpolated data.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import socket
import ssl
from functools import cache
from importlib import resources

from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    load_pem_private_key,
    pkcs12,
)
from cryptography.x509 import load_pem_x509_certificates
from pypsrp.complex_objects import Color, Coordinates, CultureInfo, ObjectMeta, Size
from pypsrp.host import PSHost, PSHostRawUserInterface, PSHostUserInterface
from pypsrp.powershell import DEFAULT_CONFIGURATION_NAME, PowerShell, RunspacePool
from pypsrp.wsman import SUPPORTED_AUTHS, WSMan
from requests.adapters import HTTPAdapter

from ..retry import with_retries
from ..utils import sha1_thumbprint
from .base import Credentials, Provisioner, resolve_credentials

log = logging.getLogger("cert-publisher.winrm")

MODE_CERT_STORE = "certStore"
MODE_FILE = "file"

# PSRP session configurations the postInstallScript can be run in. "5.1" is
# Windows PowerShell's default endpoint, present on every supported Windows
# version; "7" is the endpoint PowerShell 7+ registers when remoting is
# enabled for it (the installer's "Enable PowerShell remoting" option, or
# Enable-PSRemoting from within pwsh). Installing PowerShell 7 alone is not
# enough -- unlike the old transport, cert-publisher no longer launches
# pwsh.exe as a child process.
_PS_CONFIGURATIONS = {"5.1": DEFAULT_CONFIGURATION_NAME, "7": "PowerShell.7"}

# pywinrm transport names PSRP has no direct equivalent for. Both mean HTTP
# Basic -- pywinrm distinguished them only by whether the listener was HTTPS,
# which cert-publisher requires unconditionally -- so both map onto pypsrp's
# "basic". Kept so publications written against the old transport keep
# reconciling instead of erroring every run.
_TRANSPORT_ALIASES = {"ssl": "basic", "plaintext": "basic"}


@cache
def _script(name: str) -> str:
    """Return the text of a bundled PowerShell script.

    Every remote operation runs one of these static, parameterised scripts, so
    the text executed on the host is byte-identical across runs and across
    hosts. That gives a SOC a stable thing to review and allowlist, instead of
    a different dynamically-built blob every reconcile.
    """
    return (
        resources.files(__package__).joinpath("scripts").joinpath(name).read_text(encoding="utf-8")
    )


def _refuse_interactive(what: str) -> None:
    """Fail a host call that would need a human, instead of blocking on it."""
    raise RuntimeError(
        f"the remote script tried to {what}, but cert-publisher runs unattended "
        "and cannot answer prompts; make the script non-interactive -- no "
        "mandatory parameters without values, Read-Host, Get-Credential, or "
        "nested prompts"
    )


class _UnattendedUI(PSHostUserInterface):
    """A host UI that refuses to prompt rather than hanging on the request.

    A runspace opened without a host answers *nothing* when the remote pipeline
    makes a host call: pypsrp logs a warning and sends no response, so the
    pipeline waits for an answer that never comes while ``poll_invoke``
    silently swallows each WSMan operation timeout and asks again -- wedging
    the CronJob run, which reconciles publications serially. The old
    ``powershell.exe`` path failed fast instead, because stdin was closed.

    Anything that prompts is a bug in an unattended hook, so refuse it loudly
    and immediately. Non-interactive host calls (writes, progress, buffer
    geometry) keep pypsrp's stock behaviour.
    """

    def ReadLine(self, runspace, pipeline):
        _refuse_interactive("read a line of input")

    def ReadLineAsSecureString(self, runspace, pipeline):
        _refuse_interactive("read a password")

    def Prompt(self, runspace, pipeline, caption, message, description):
        _refuse_interactive(f"prompt for input ({caption or message!r})")

    def PromptForCredential1(self, runspace, pipeline, caption, message, user_name, target_name):
        _refuse_interactive("prompt for credentials")

    def PromptForCredential2(
        self,
        runspace,
        pipeline,
        caption,
        message,
        user_name,
        target_name,
        allowed_credential_types,
        options,
    ):
        _refuse_interactive("prompt for credentials")

    def PromptForChoice(self, runspace, pipeline, caption, message, choices, default_choice):
        _refuse_interactive(f"prompt for a choice ({caption or message!r})")


class _UnattendedRawUI(PSHostRawUserInterface):
    def ReadKey(self, runspace, pipeline, options=4):
        _refuse_interactive("read a keypress")


class _UnattendedHost(PSHost):
    def EnterNestedPrompt(self, runspace, pipeline):
        _refuse_interactive("enter a nested prompt")


def _unattended_host() -> PSHost:
    """Build the PSHost every runspace is opened with.

    Every non-void host call has to return something: pypsrp only sends a
    response when the method returns non-None, so a getter that answers None
    leaves the remote pipeline waiting exactly like having no host at all.
    That is why the culture, version and screen geometry below are all filled
    in with real values rather than left to default.
    """
    culture = CultureInfo(
        lcid=1033,
        name="en-US",
        display_name="English (United States)",
        ietf_language_tag="en-US",
        three_letter_iso_name="eng",
        three_letter_windows_name="ENU",
        two_letter_iso_language_name="en",
    )
    # A plausible headless console. PowerShell asks for these when formatting
    # output width and when a script uses Write-Progress.
    size = Size(width=120, height=3000)
    raw_ui = _UnattendedRawUI(
        window_title="cert-publisher",
        cursor_size=25,
        foreground_color=Color(value=Color.GRAY),
        background_color=Color(value=Color.BLACK),
        cursor_position=Coordinates(x=0, y=0),
        window_position=Coordinates(x=0, y=0),
        buffer_size=size,
        max_physical_window_size=size,
        max_window_size=size,
        window_size=size,
    )
    return _UnattendedHost(
        current_culture=culture,
        current_ui_culture=culture,
        debugger_enabled=False,
        name="cert-publisher",
        private_data=None,
        ui=_UnattendedUI(raw_ui=raw_ui),
        version="1.0.0",
    )


class _PinnedHTTPAdapter(HTTPAdapter):
    """A ``requests`` adapter that pins the TLS peer to a certificate thumbprint.

    pypsrp is run with certificate validation disabled -- a WinRM listener's
    self-signed cert chains to no CA -- so urllib3 would otherwise accept any
    certificate on the connection that carries the auth exchange, the PFX and
    the command output. This adapter re-adds the check that matters: every
    connection urllib3 takes from the pool must present a leaf certificate
    whose SHA-1 hash equals ``thumbprint`` (urllib3 accepts the value with or
    without colons and in any case), or the socket is refused before a single
    request byte is written. The check runs on the pooled connection itself,
    so -- unlike a standalone probe -- it cannot be satisfied by one connection
    while the session data rides another.
    """

    def __init__(self, thumbprint: str, **kwargs) -> None:
        self._assert_fingerprint = thumbprint
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs) -> None:
        kwargs["assert_fingerprint"] = self._assert_fingerprint
        kwargs["cert_reqs"] = "CERT_NONE"
        super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["assert_fingerprint"] = self._assert_fingerprint
        kwargs["cert_reqs"] = "CERT_NONE"
        return super().proxy_manager_for(*args, **kwargs)


def _error_text(powershell: PowerShell) -> str:
    """Flatten a pipeline's error stream into one readable line."""
    parts = []
    for record in powershell.streams.error:
        text = str(record).strip()
        if text and text != "None":
            parts.append(text)
    return "; ".join(parts) or "no error detail returned by the host"


def _invoke(
    pool: RunspacePool,
    script_name: str,
    parameters: dict | None = None,
    secure_parameters: dict[str, str] | None = None,
) -> list:
    """Run a bundled script in ``pool`` and return its output objects.

    ``parameters`` are bound by name to the script's ``param()`` block, with
    Python types mapped by pypsrp (``bytes`` becomes ``byte[]``, ``bool``
    becomes ``System.Boolean``, and so on). ``secure_parameters`` are bound as
    ``SecureString``, encrypted under a session key the runspace pool
    negotiates with the host -- which is why the key exchange has to happen
    before they can be serialised at all.
    """
    powershell = PowerShell(pool)
    powershell.add_script(_script(script_name))
    for name, value in (parameters or {}).items():
        powershell.add_parameter(name, value)
    if secure_parameters:
        pool.exchange_keys()
        for name, value in secure_parameters.items():
            powershell.add_parameter(name, pool.serialize(value, ObjectMeta("SS")))

    powershell.invoke()
    if powershell.had_errors:
        raise RuntimeError(f"{script_name} failed on the remote host: {_error_text(powershell)}")
    if powershell.streams.error:
        # Non-terminating errors don't fail the pipeline (the old transport
        # didn't fail on them either, since powershell.exe still exited 0), but
        # they're worth surfacing -- a post-install hook is the usual source.
        log.warning("%s wrote to the error stream: %s", script_name, _error_text(powershell))
    return powershell.output


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
        exportable_private_key: bool = False,
        powershell: str = "5.1",
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.thumbprint = thumbprint.replace(":", "").replace(" ", "").upper()
        alias = _TRANSPORT_ALIASES.get(transport)
        if alias is not None:
            log.info(
                "winrm transport %r is a legacy pywinrm name; authenticating "
                "with %r over the HTTPS listener",
                transport,
                alias,
            )
            transport = alias
        if transport not in SUPPORTED_AUTHS:
            raise ValueError(
                f"unsupported winrm transport: {transport!r} (expected one of "
                f"{', '.join(sorted(set(SUPPORTED_AUTHS) | set(_TRANSPORT_ALIASES)))})"
            )
        self.transport = transport
        self.credentials = credentials
        self.mode = mode
        self.store_location = store_location
        self.store_name = store_name
        self.cert_path = cert_path
        self.key_path = key_path
        self.post_install_script = post_install_script
        self.exportable_private_key = exportable_private_key
        if powershell not in _PS_CONFIGURATIONS:
            raise ValueError(
                f"unsupported powershell runtime: {powershell!r} (expected '5.1' or '7')"
            )
        self.powershell = powershell
        # Set by is_current() when it detects the installed private key's
        # exportability doesn't match the desired setting; reconcile.py folds
        # this into the status message. See install-cert-store.ps1 for why this
        # can't just be fixed in place.
        self.pending_warning: str | None = None

    @property
    def _post_install_configuration(self) -> str:
        return _PS_CONFIGURATIONS[self.powershell]

    @classmethod
    def from_spec(cls, spec: dict, kube, namespace: str) -> WinRMProvisioner:
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
            exportable_private_key=bool(spec.get("exportablePrivateKey", False)),
            powershell=spec.get("powershell", "5.1"),
        )

    # -- host verification ------------------------------------------------

    def _verify_endpoint(self) -> None:
        """Pre-flight the WinRM HTTPS listener against the configured thumbprint.

        This is a fast fail-early check that gives a clear "expected X, got Y"
        error (and retries transient network blips with backoff) before any
        credential is sent. It is *not* what secures the session: that is done
        by pinning the same thumbprint on the real request connection in
        ``_wsman`` via :class:`_PinnedHTTPAdapter`, so a MITM cannot answer
        this probe on one connection and serve the session on another.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        def _peer_cert() -> bytes:
            log.debug("connecting to WinRM endpoint %s:%d", self.host, self.port)
            with (
                socket.create_connection((self.host, self.port), timeout=15) as sock,
                ctx.wrap_socket(sock, server_hostname=self.host) as tls,
            ):
                return tls.getpeercert(binary_form=True)

        der = with_retries(
            _peer_cert,
            description=f"WinRM endpoint check for {self.host}:{self.port}",
        )
        got = hashlib.sha1(der).hexdigest().upper()
        if got != self.thumbprint:
            raise RuntimeError(
                f"WinRM endpoint thumbprint mismatch for {self.host}: "
                f"expected {self.thumbprint}, got {got}"
            )
        log.debug("WinRM endpoint %s:%d thumbprint verified", self.host, self.port)

    # -- connection -------------------------------------------------------

    def _wsman(self) -> WSMan:
        if not self.credentials.password:
            raise ValueError("winrm provisioner requires a password")
        wsman = WSMan(
            self.host,
            port=self.port,
            username=self.username,
            password=self.credentials.password,
            ssl=True,
            auth=self.transport,
            # There is no CA for a WinRM listener cert; the host is
            # authenticated by pinning its thumbprint on the connection that
            # actually carries the request (below), not by PKI validation.
            cert_validation=False,
        )
        self._pin_transport(wsman)
        return wsman

    def _pin_transport(self, wsman: WSMan) -> None:
        """Bind the pinned thumbprint to the live request connection.

        pypsrp builds its ``requests.Session`` lazily, on the first send. Build
        it now, mount an adapter that makes urllib3 reject any TLS peer whose
        certificate hash doesn't match, and hand it back to the transport.
        Every WSMan operation reuses this session, so the auth handshake and
        all payloads (the PFX, its password, command output) travel only over a
        connection whose certificate has been checked -- closing the gap
        between "verify" and "use".
        """
        transport = wsman.transport
        if transport.session is not None:
            raise RuntimeError(
                "the WSMan transport already holds a request session, so a "
                "request may have gone out before the thumbprint pin was "
                "mounted; refusing to continue"
            )
        session = transport._build_session()
        # Replace only the TLS behaviour; keep pypsrp's own retry policy.
        existing = session.get_adapter(transport.endpoint)
        session.mount(
            "https://",
            _PinnedHTTPAdapter(self.thumbprint, max_retries=existing.max_retries),
        )
        transport.session = session

    # -- provisioner interface -------------------------------------------

    def is_current(self, cert_pem: bytes) -> bool:
        self.pending_warning = None
        self._verify_endpoint()
        with self._wsman() as wsman, RunspacePool(wsman, host=_unattended_host()) as pool:
            if self.mode == MODE_CERT_STORE:
                return self._cert_store_is_current(pool, cert_pem)
            return self._file_is_current(pool, cert_pem)

    def _cert_store_is_current(self, pool: RunspacePool, cert_pem: bytes) -> bool:
        result = _first_line(
            _invoke(
                pool,
                "probe-cert-store.ps1",
                {
                    "StoreLocation": self.store_location,
                    "StoreName": self.store_name,
                    "Thumbprint": sha1_thumbprint(cert_pem),
                },
            )
        )
        if not result.startswith("present"):
            return False
        if result != "present:nokey":
            self._check_exportable_drift(result)
        return True

    def _file_is_current(self, pool: RunspacePool, cert_pem: bytes) -> bool:
        # Compare the leaf thumbprint of the remote cert file, so PEM
        # formatting or chain differences don't trigger spurious reinstalls.
        remote = _first_line(_invoke(pool, "read-file-b64.ps1", {"Path": self.cert_path}))
        if not remote:
            return False
        try:
            return sha1_thumbprint(base64.b64decode(remote)) == sha1_thumbprint(cert_pem)
        except ValueError:
            return False  # remote file isn't a parseable certificate

    def _check_exportable_drift(self, probe_result: str) -> None:
        actual_exportable = probe_result == "present:exportable"
        if actual_exportable == self.exportable_private_key:
            return
        if self.exportable_private_key:
            self.pending_warning = (
                "exportablePrivateKey is enabled but the installed certificate's "
                "private key was imported as non-exportable; Windows doesn't "
                "support changing that in place, so this will take effect the "
                "next time the certificate is renewed"
            )
        else:
            self.pending_warning = (
                "exportablePrivateKey is disabled but the installed certificate's "
                "private key was imported as exportable; Windows doesn't support "
                "changing that in place, so this will take effect the next time "
                "the certificate is renewed"
            )

    def install(self, cert_pem: bytes, key_pem: bytes) -> None:
        if self.mode not in (MODE_CERT_STORE, MODE_FILE):
            raise ValueError(f"unknown winrm mode: {self.mode!r}")
        self._verify_endpoint()
        with self._wsman() as wsman:
            with RunspacePool(wsman, host=_unattended_host()) as pool:
                if self.mode == MODE_CERT_STORE:
                    self._install_cert_store(pool, cert_pem, key_pem)
                else:
                    self._install_files(pool, cert_pem, key_pem)

            if self.post_install_script:
                log.info("[%s] running post-install script", self.host)
                self._run_post_install(wsman, cert_pem)

    def _install_cert_store(self, pool: RunspacePool, cert_pem: bytes, key_pem: bytes) -> None:
        certs = load_pem_x509_certificates(cert_pem)
        key = load_pem_private_key(key_pem, password=None)
        # The PFX is encrypted in transit under a random single-use password
        # that only ever exists as a bound SecureString parameter. Neither the
        # blob nor the password touches a command line or the remote disk.
        pfx_password = secrets.token_urlsafe(24)
        pfx = pkcs12.serialize_key_and_certificates(
            name=b"cert-publisher",
            key=key,
            cert=certs[0],
            cas=certs[1:] or None,
            encryption_algorithm=BestAvailableEncryption(pfx_password.encode()),
        )
        _invoke(
            pool,
            "install-cert-store.ps1",
            {
                "PfxBytes": pfx,
                "StoreLocation": self.store_location,
                "StoreName": self.store_name,
                "Exportable": self.exportable_private_key,
            },
            secure_parameters={"Password": pfx_password},
        )

    def _install_files(self, pool: RunspacePool, cert_pem: bytes, key_pem: bytes) -> None:
        self._write_file(pool, self.cert_path, cert_pem)
        if self.key_path:
            self._write_file(pool, self.key_path, key_pem)

    def _write_file(self, pool: RunspacePool, path: str, data: bytes) -> None:
        _invoke(pool, "write-file.ps1", {"Path": path, "Content": data})

    def _run_post_install(self, wsman: WSMan, cert_pem: bytes) -> None:
        """Run the operator-supplied hook in its own runspace.

        It gets a separate pool because ``powershell: "7"`` selects a different
        PSRP session configuration; the install itself always runs in the
        default Windows PowerShell endpoint. The host matters most here -- this
        is the one script cert-publisher didn't write, so it's the one that
        might try to prompt.
        """
        with RunspacePool(
            wsman,
            configuration_name=self._post_install_configuration,
            host=_unattended_host(),
        ) as pool:
            _invoke(
                pool,
                "run-post-install.ps1",
                {
                    "Script": self.post_install_script,
                    "Thumbprint": sha1_thumbprint(cert_pem),
                },
            )


def _first_line(output: list) -> str:
    """Return the first output object as stripped text, or "" if there was none."""
    return str(output[0]).strip() if output else ""
