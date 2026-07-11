"""Provisioner factory."""

from __future__ import annotations

from .base import Provisioner
from .ssh import SSHProvisioner
from .winrm import WinRMProvisioner

__all__ = ["Provisioner", "SSHProvisioner", "WinRMProvisioner", "build_provisioner"]


def build_provisioner(spec: dict, kube, namespace: str) -> Provisioner:
    """Construct a provisioner from a CertPublication ``spec.provisioner``."""
    ptype = spec["type"]
    if ptype == "ssh":
        return SSHProvisioner.from_spec(spec["ssh"], kube, namespace)
    if ptype == "winrm":
        return WinRMProvisioner.from_spec(spec["winrm"], kube, namespace)
    raise ValueError(f"unknown provisioner type: {ptype!r}")
