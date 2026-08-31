"""Provisioner interface and shared credential resolution."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


class Provisioner(ABC):
    """Installs a cert-manager-issued keypair on a single external host.

    cert-manager generates the private key; the reconciler reads both halves
    out of the issued Secret and hands them here. Implementations are
    responsible for verifying the identity of the target host before handing
    over any credentials or key material.
    """

    @abstractmethod
    def is_current(self, cert_pem: bytes) -> bool:
        """Return True if the leaf in ``cert_pem`` is already installed."""

    @abstractmethod
    def install(self, cert_pem: bytes, key_pem: bytes) -> None:
        """Install the certificate/key and run any post-install hook."""


class CsrProvisioner(ABC):
    """Signs a certificate for a host that keeps its own private key.

    Some targets will not accept an externally generated private key at all --
    a Dell iDRAC8 has no key-upload path over any supported API. Such a host
    generates its own keypair and emits a CSR; cert-manager signs the CSR and
    the signed certificate is imported back.

    That inverts who owns the key, so it also inverts the reconcile steps: there
    is no issued Secret to compare against, and "is this current?" becomes a
    question about the certificate the host itself is holding. See
    ``reconcile._reconcile_host_keyed`` for the flow that drives these methods.

    Implementations are responsible for verifying the identity of the target
    host before handing over any credentials.
    """

    @abstractmethod
    def installed_certificate(self) -> bytes | None:
        """Return the PEM certificate the host currently serves, or None."""

    @abstractmethod
    def generate_csr(self, *, common_name: str, dns_names: list[str]) -> bytes:
        """Have the host generate a fresh keypair and return its PEM CSR.

        Callers must treat this as destructive to any previously pending CSR:
        the host rotates the held private key, invalidating any earlier CSR it
        issued. Only call it once per renewal.
        """

    @abstractmethod
    def import_certificate(self, cert_pem: bytes) -> None:
        """Install the signed certificate and apply it."""


@dataclass
class Credentials:
    """Login material resolved from a referenced Secret."""

    password: str | None = None
    private_key: str | None = None
    passphrase: str | None = None


def resolve_credentials(auth: dict, kube, namespace: str) -> Credentials:
    """Resolve ``auth.secretRef`` into concrete credentials.

    The referenced Secret may carry any of ``password``, ``privateKey`` and
    ``passphrase`` keys, and must live in the same namespace as the
    CertPublication — credential Secrets are never read cross-namespace.
    """
    ref = (auth or {}).get("secretRef")
    if not ref:
        raise ValueError("provisioner auth.secretRef is required")

    secret = kube.get_secret(namespace, ref["name"])
    if secret is None:
        raise LookupError(
            f"auth secret {ref['name']!r} not found in namespace {namespace!r}"
        )

    data = kube.secret_data(secret)

    def field(name: str) -> str | None:
        value = data.get(name)
        return value.decode() if value is not None else None

    return Credentials(
        password=field("password"),
        private_key=field("privateKey"),
        passphrase=field("passphrase"),
    )
