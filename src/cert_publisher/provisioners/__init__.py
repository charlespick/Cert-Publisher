"""Provisioner factory."""

from __future__ import annotations

from .base import CsrProvisioner, Provisioner
from .idrac8 import IDRAC8Provisioner
from .ssh import SSHProvisioner
from .winrm import WinRMProvisioner

__all__ = [
    "CsrProvisioner",
    "IDRAC8Provisioner",
    "Provisioner",
    "SSHProvisioner",
    "WinRMProvisioner",
    "build_provisioner",
    "manages_own_key",
]

# Provisioner types whose target host generates and keeps its own private key.
# These are driven by the CSR reconcile path instead of the issued-Secret one.
_HOST_KEYED_TYPES = frozenset({"idrac8"})


def manages_own_key(provisioner_type: str) -> bool:
    """Whether this provisioner type's host keeps its own private key.

    Answered from the type name alone so the reconciler can pick a flow before
    building the provisioner -- building one resolves credentials, and the
    existing path deliberately does not touch those until it has an issued
    certificate to publish.
    """
    return provisioner_type in _HOST_KEYED_TYPES


def build_provisioner(spec: dict, kube, namespace: str) -> Provisioner | CsrProvisioner:
    """Construct a provisioner from a CertPublication ``spec.provisioner``."""
    ptype = spec["type"]
    if ptype == "ssh":
        return SSHProvisioner.from_spec(spec["ssh"], kube, namespace)
    if ptype == "winrm":
        return WinRMProvisioner.from_spec(spec["winrm"], kube, namespace)
    if ptype == "idrac8":
        return IDRAC8Provisioner.from_spec(spec["idrac8"], kube, namespace)
    raise ValueError(f"unknown provisioner type: {ptype!r}")
