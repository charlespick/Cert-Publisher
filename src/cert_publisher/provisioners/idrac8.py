"""Dell iDRAC8 provisioner: sign the BMC's own key over WS-Man.

An iDRAC8 will not accept an externally generated private key by any route this
project can use. Redfish on this generation has no certificate schema at all
(no ``CertificateService``, no ``DelliDRACCardService``); its SSH is an SM-CLP /
racadm interpreter with no SFTP and no filesystem; and ``racadm sslkeyupload``
exists only in the *remote* racadm binary, which would mean shipping a vendor
container. WS-Man exposes ``ImportSSLCertificate`` but no key-upload method at
all.

So the key stays on the BMC. The iDRAC generates its own keypair and a CSR,
cert-manager signs the CSR, and the signed certificate is imported back. Nothing
secret crosses the wire in either direction, which is a stronger position than
shipping a PFX -- at the cost of cert-manager no longer owning renewal timing,
which is why :class:`CsrProvisioner` implementations are driven by a different
reconcile path.

The certificate the host is serving is read straight off the TLS handshake --
the same one that authenticates the host -- so a reconcile with nothing to do
costs a single connection and sends no credentials.

Host identity is established before any credential is sent, by either of two
complementary signals:

* the live certificate is *currently valid* -- chains to a trusted CA (system
  trust plus an optional ``caBundle``), matches the hostname, and is unexpired;
  this keeps working across renewals once a real certificate is installed; or
* the endpoint certificate's SHA-256 matches a configured ``bootstrapThumbprint``
  (trust on first use), which covers the first run against the factory
  self-signed certificate.

Whichever signal accepts the host, the hash of *that exact certificate* is then
pinned onto the connection carrying the WS-Man session, so a man-in-the-middle
cannot satisfy the check on one connection and serve the session on another.
"""

from __future__ import annotations

import hashlib
import logging
import socket
import ssl
import time

from ..retry import with_retries
from ..utils import leaf_pem
from ..wsman import WSManClient
from .base import Credentials, CsrProvisioner, resolve_credentials

log = logging.getLogger("cert-publisher.idrac8")

_SERVICE = "DCIM_iDRACCardService"

# The iDRAC's own web-server certificate. Note the parameter this is passed as
# differs by method: ImportSSLCertificate takes "CertificateType" while
# ExportSSLCertificate takes "SSLCertType" (Dell iDRAC Card Profile, DCIM1043,
# sections 8.9-8.10). The numeric value is the same. Confirmed three ways:
# Dell's own OpenManage SDK maps Web_Server_Cert=1 (CA=2, Custom_Signing=3,
# Client_Trust=4); the firmware's racadm help gives the same 1=server mapping;
# and ExportSSLCertificate(SSLCertType=1) empirically returns the web server
# certificate on firmware 2.86.86.86.
_CERT_TYPE_SERVER = "1"

# GenerateSSLCSR takes no parameters -- the iDRAC builds the CSR from these
# stored attributes -- so they are set before it is invoked. SetAttributes
# expects each name as "<GroupID>#<AttributeName>" with a HASH separator, not
# the dotted form the attributes are enumerated under (Dell iDRAC Card Profile,
# DCIM1043, section 8.4).
_ATTR_COMMON_NAME = "Security.1#CsrCommonName"
_ATTR_SUBJECT_ALT_NAME = "Security.1#CsrSubjectAltName"

# The class those attributes live on, and the InstanceID form addressing one of
# them: "<FQDD>#<GroupID>#<AttributeName>".
_ATTR_CLASS = "DCIM_iDRACCardString"
_TARGET = "iDRAC.Embedded.1"

# SetAttributes stores a *pending* value; GenerateSSLCSR reads the *current*
# one. Without a config job in between, a CSR is minted from the previous
# subject -- which is how an iDRAC's stale IP SAN ends up in a CSR that a public
# CA then refuses to sign. The job is real-time for these attributes (the iDRAC
# reports RebootRequired: No), so it costs a few seconds and no restart.
_APPLY_TIMEOUT = 90
_APPLY_POLL_INTERVAL = 3

_TIMEOUT = 60
_CONNECT_TIMEOUT = 15


def _normalise_thumbprint(value: str) -> str:
    return value.replace(":", "").replace(" ", "").strip().lower()


class IDRAC8Provisioner(CsrProvisioner):
    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        credentials: Credentials,
        bootstrap_thumbprint: str | None,
        ca_bundle: str | None,
        reset: bool,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.credentials = credentials
        self.bootstrap_thumbprint = (
            _normalise_thumbprint(bootstrap_thumbprint) if bootstrap_thumbprint else None
        )
        self.ca_bundle = ca_bundle
        self.reset = reset

    @classmethod
    def from_spec(cls, spec: dict, kube, namespace: str) -> IDRAC8Provisioner:
        return cls(
            host=spec["host"],
            port=int(spec.get("port", 443)),
            username=spec["username"],
            credentials=resolve_credentials(spec.get("auth", {}), kube, namespace),
            bootstrap_thumbprint=spec.get("bootstrapThumbprint"),
            ca_bundle=spec.get("caBundle"),
            reset=bool(spec.get("reset", True)),
        )

    # -- host authentication ---------------------------------------------

    def _peer_der(self, *, verify: bool) -> bytes | None:
        """Fetch the endpoint's DER certificate.

        With ``verify`` set, a certificate that fails PKI validation returns
        ``None`` rather than raising: "not trusted yet" is an expected state on
        first run, not a transient fault, and must not be retried or surfaced
        as a connection error. Genuine network failures still raise and are
        retried by the caller.
        """
        if verify:
            if self.ca_bundle:
                # Exclusive, not additive. A BMC has no public identity, so
                # trusting every public CA (and every corporate TLS-inspection
                # CA that lands in the container's trust store) on top of the
                # operator's own bundle would widen the check rather than
                # tighten it -- and the valid-certificate path silently
                # outranks bootstrapThumbprint, so that surface is the one that
                # decides whether the host is who it claims.
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.check_hostname = True
                ctx.load_verify_locations(cadata=self.ca_bundle)
            else:
                ctx = ssl.create_default_context()
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        def attempt() -> bytes | None:
            try:
                with (
                    socket.create_connection(
                        (self.host, self.port), timeout=_CONNECT_TIMEOUT
                    ) as sock,
                    ctx.wrap_socket(sock, server_hostname=self.host) as tls,
                ):
                    return tls.getpeercert(binary_form=True)
            except ssl.SSLCertVerificationError as exc:
                if not verify:
                    raise
                log.debug("[%s] endpoint is not PKI-valid yet: %s", self.host, exc)
                return None

        return with_retries(
            attempt,
            description=f"iDRAC endpoint check for {self.host}:{self.port}",
        )

    def _authenticated_peer(self) -> bytes:
        """Authenticate the host and return the DER certificate it presented.

        Steady state is checked first so a host that has already been published
        to keeps verifying without any configuration change as its certificate
        rotates. The bootstrap thumbprint is only consulted when PKI validation
        cannot succeed yet.
        """
        der = self._peer_der(verify=True)
        if der is not None:
            log.debug("[%s] endpoint verified against trusted CA", self.host)
            return der

        if not self.bootstrap_thumbprint:
            raise RuntimeError(
                f"iDRAC {self.host} does not present a currently valid "
                "certificate (untrusted issuer, hostname mismatch, or expired) "
                "and no bootstrapThumbprint is configured, so its identity "
                "cannot be established; set bootstrapThumbprint to the SHA-256 "
                "of the certificate it is serving today"
            )

        der = self._peer_der(verify=False)
        if der is None:
            raise RuntimeError(
                f"iDRAC {self.host} presented no certificate to check against "
                "the configured bootstrapThumbprint"
            )
        got = hashlib.sha256(der).hexdigest()
        if got != self.bootstrap_thumbprint:
            raise RuntimeError(
                f"iDRAC endpoint thumbprint mismatch for {self.host}: expected "
                f"{self.bootstrap_thumbprint}, got {got}"
            )
        log.debug("[%s] endpoint verified against bootstrap thumbprint", self.host)
        return der

    def _authenticate_endpoint(self) -> str:
        """The SHA-256 hex of the authenticated peer, for pinning the session."""
        return hashlib.sha256(self._authenticated_peer()).hexdigest()

    def _connect(self) -> WSManClient:
        """Authenticate the endpoint and open a pinned WS-Man session to it."""
        if not self.credentials.password:
            raise ValueError("idrac8 provisioner requires a password")
        pin = self._authenticate_endpoint()
        return WSManClient(
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.credentials.password,
            pin_sha256=pin,
            timeout=_TIMEOUT,
        )

    # -- provisioner interface -------------------------------------------

    def installed_certificate(self) -> bytes | None:
        """The certificate the iDRAC is actually serving on its web interface.

        This is the certificate clients see, which is the thing the publication
        is ultimately about -- so it catches a host that has never been
        published to, one whose certificate has drifted or expired, and one
        where an import succeeded but the reset that applies it did not.

        It is the same handshake that authenticates the host, so the common
        "nothing to do" reconcile costs one TLS connection and sends no
        credentials at all.
        """
        der = self._authenticated_peer()
        if der is None:
            return None
        return ssl.DER_cert_to_PEM_cert(der).encode()

    def _attribute(self, client: WSManClient, attribute: str) -> dict[str, str]:
        """Read one iDRAC attribute, including its pending value."""
        return client.get(
            _ATTR_CLASS, {"InstanceID": f"{_TARGET}#{attribute}"}
        )

    def _apply_csr_subject(self, client: WSManClient, desired: dict[str, str]) -> None:
        """Make the stored CSR subject match ``desired``, or raise trying.

        SetAttributes only stages the values, so a config job commits them and
        the result is confirmed by reading CurrentValue back -- the attribute
        itself is the thing that matters, and it is a more direct answer than
        interpreting a job status.
        """
        names = list(desired)
        client.invoke(
            _SERVICE,
            "SetAttributes",
            {
                "Target": _TARGET,
                "AttributeName": names,
                "AttributeValue": [desired[n] for n in names],
            },
        )
        log.info("[%s] applying the CSR subject", self.host)
        client.invoke(
            _SERVICE,
            "CreateTargetedConfigJob",
            {"Target": _TARGET, "ScheduledStartTime": "TIME_NOW"},
        )

        deadline = time.monotonic() + _APPLY_TIMEOUT
        while True:
            current = {n: self._attribute(client, n).get("CurrentValue", "") for n in names}
            if current == desired:
                log.debug("[%s] CSR subject applied", self.host)
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"iDRAC {self.host} did not apply the CSR subject within "
                    f"{_APPLY_TIMEOUT}s (wanted {desired}, still {current}). "
                    f"A CSR generated now would carry the previous subject, so "
                    f"none was requested."
                )
            time.sleep(_APPLY_POLL_INTERVAL)

    def generate_csr(self, *, common_name: str, dns_names: list[str]) -> bytes:
        """Rotate the iDRAC's keypair and return the PEM CSR it emits.

        The iDRAC builds the CSR from its stored ``Security.1#Csr*`` attributes,
        so the subject and SANs are made to match the publication first. Only
        the common name and SAN list are managed: the remaining fields
        (organization, locality, key size) are left as configured on the BMC
        rather than being clobbered with defaults this operator would invent.
        """
        desired = {
            _ATTR_COMMON_NAME: common_name,
            _ATTR_SUBJECT_ALT_NAME: ",".join(dns_names),
        }
        with self._connect() as client:
            current = {
                n: self._attribute(client, n).get("CurrentValue", "") for n in desired
            }
            if current == desired:
                # Steady state: nothing to change, so no config job runs and
                # renewals stay a single generate-and-sign round.
                log.debug("[%s] CSR subject already matches the publication", self.host)
            else:
                self._apply_csr_subject(client, desired)

            log.info("[%s] generating a new CSR (this rotates the iDRAC's key)",
                     self.host)
            output = client.invoke(_SERVICE, "GenerateSSLCSR", {})

        csr = output.get("SSLCSRFile", "").strip()
        if not csr:
            raise RuntimeError(
                f"iDRAC {self.host} reported success generating a CSR but "
                "returned no SSLCSRFile"
            )
        return (csr + "\n").encode()

    def import_certificate(self, cert_pem: bytes) -> None:
        """Install the signed certificate and reset the iDRAC to apply it."""
        # Raw PEM, NOT base64-of-PEM. Dell describes SSLCertificateFile as "a
        # base 64 encoded string of the ... Certificate file" (DCIM1043 8.9),
        # which means the PEM text -- PEM is already base64-armoured.
        # Base64-wrapping it a second time is rejected with the unhelpful
        # "Certificate import operation failed". ExportSSLCertificate returns
        # raw PEM, and import is its mirror image.
        #
        # Leaf only: CertificateType 1 is the single web-server certificate
        # slot (Dell's type 2 is the Directory Service CA, not a chain slot),
        # and an ACME issuer returns leaf + intermediates in one PEM.
        payload = (leaf_pem(cert_pem) + b"\n").decode()

        with self._connect() as client:
            output = client.invoke(
                _SERVICE,
                "ImportSSLCertificate",
                {
                    "SSLCertificateFile": payload,
                    "CertificateType": _CERT_TYPE_SERVER,
                },
            )
            log.info("[%s] certificate imported: %s", self.host,
                     output.get("Message", "no detail"))

            if not self.reset:
                log.warning(
                    "[%s] reset is disabled; the imported certificate stays "
                    "inactive until the iDRAC is reset by other means",
                    self.host,
                )
                return

            # An iDRAC8 keeps serving the previous certificate until it is
            # reset, so the import is only half the job. Dell's profile claims
            # the import restarts the iDRAC by itself, but firmware 2.86.86.86
            # answers DH010 -- "Reset iDRAC to apply new certificate. Until
            # iDRAC is reset, the old certificate will be active" -- so the
            # reset is issued explicitly and the documentation is not trusted
            # on this point.
            log.info("[%s] resetting the iDRAC to apply the certificate", self.host)
            client.invoke(_SERVICE, "iDRACReset", {"Force": "0"})
