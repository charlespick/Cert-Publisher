"""Core reconcile logic for a single CertPublication."""

from __future__ import annotations

import logging

from .certmanager import build_certificate_body
from .kube import Kube
from .provisioners import build_provisioner
from .utils import sha256_fingerprint

log = logging.getLogger("cert-publisher.reconcile")


def reconcile_publication(kube: Kube, pub: dict) -> None:
    meta = pub["metadata"]
    spec = pub["spec"]
    name = meta["name"]
    namespace = meta["namespace"]
    ref = f"{namespace}/{name}"
    secret_name = spec.get("secretName", f"{name}-tls")

    # 1. Ensure a cert-manager Certificate exists. cert-manager owns the
    #    renewal/rotation policy from here on; we only create it once.
    if kube.get_certificate(namespace, name) is None:
        log.info("[%s] creating cert-manager Certificate", ref)
        kube.create_certificate(namespace, build_certificate_body(pub, secret_name))
        log.info("[%s] Certificate created; will publish once it is issued", ref)
        return

    # 2. The Certificate exists; wait until cert-manager has populated the Secret.
    secret = kube.get_secret(namespace, secret_name)
    if secret is None or not secret.data or "tls.crt" not in secret.data:
        log.info("[%s] certificate not yet issued, waiting", ref)
        return

    data = kube.secret_data(secret)
    cert_pem = data["tls.crt"]
    key_pem = data["tls.key"]
    desired = sha256_fingerprint(cert_pem)

    # 3. Ask the provisioner whether the target already has this exact leaf.
    prov = build_provisioner(spec["provisioner"], kube, namespace)
    if prov.is_current(cert_pem):
        log.info("[%s] installed certificate is up to date (%s)", ref, desired[:16])
        return

    # 4. Publish.
    log.info("[%s] publishing certificate %s", ref, desired[:16])
    prov.install(cert_pem, key_pem)
    log.info("[%s] certificate published", ref)
