"""Provisioner interface and shared credential resolution."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


class Provisioner(ABC):
    """Installs a certificate on a single external host.

    Implementations are responsible for verifying the identity of the target
    host before handing over any credentials or key material.
    """

    @abstractmethod
    def is_current(self, cert_pem: bytes) -> bool:
        """Return True if the leaf in ``cert_pem`` is already installed."""

    @abstractmethod
    def install(self, cert_pem: bytes, key_pem: bytes) -> None:
        """Install the certificate/key and run any post-install hook."""


@dataclass
class Credentials:
    """Login material resolved from a referenced Secret."""

    password: str | None = None
    private_key: str | None = None
    passphrase: str | None = None


def resolve_credentials(auth: dict, kube, namespace: str) -> Credentials:
    """Resolve ``auth.secretRef`` into concrete credentials.

    The referenced Secret may carry any of ``password``, ``privateKey`` and
    ``passphrase`` keys.
    """
    ref = (auth or {}).get("secretRef")
    if not ref:
        return Credentials()

    secret = kube.get_secret(ref.get("namespace", namespace), ref["name"])
    if secret is None:
        raise LookupError(f"auth secret {ref['name']!r} not found")

    data = kube.secret_data(secret)

    def field(name: str) -> str | None:
        value = data.get(name)
        return value.decode() if value is not None else None

    return Credentials(
        password=field("password"),
        private_key=field("privateKey"),
        passphrase=field("passphrase"),
    )
