"""Core reconcile logic for a single CertPublication."""

from __future__ import annotations

import logging

from .certmanager import build_certificate_body, certificate_spec_drift
from .kube import Kube
from .provisioners import build_provisioner
from .status import PENDING, PUBLISHED, set_status
from .utils import sha256_fingerprint

log = logging.getLogger("cert-publisher.reconcile")


def reconcile_publication(kube: Kube, pub: dict) -> None:
    meta = pub["metadata"]
    spec = pub["spec"]
    name = meta["name"]
    namespace = meta["namespace"]
    ref = f"{namespace}/{name}"
    secret_name = spec.get("secretName", f"{name}-tls")

    # 1. Ensure a cert-manager Certificate exists and matches the current spec.
    #    cert-manager owns renewal/rotation timing; we own translating the
    #    publication's desired subjects/issuer into the Certificate.
    existing = kube.get_certificate(namespace, name)
    if existing is None:
        log.info("[%s] creating cert-manager Certificate", ref)
        kube.create_certificate(namespace, build_certificate_body(pub, secret_name))
        log.info("[%s] Certificate created; will publish once it is issued", ref)
        set_status(kube, pub, PENDING, "Certificate created; awaiting issuance")
        return

    drift = certificate_spec_drift(existing, pub, secret_name)
    if drift is not None:
        log.info("[%s] spec changed; updating cert-manager Certificate", ref)
        kube.patch_certificate(namespace, name, drift)
        log.info("[%s] Certificate updated; will publish once reissued", ref)
        set_status(kube, pub, PENDING, "Certificate updated; awaiting reissuance")
        return

    # 2. The Certificate exists; wait until cert-manager has populated the Secret
    #    with both the certificate and its private key.
    secret = kube.get_secret(namespace, secret_name)
    if secret is None or not secret.data or "tls.crt" not in secret.data or "tls.key" not in secret.data:
        log.info("[%s] certificate not yet issued, waiting", ref)
        set_status(kube, pub, PENDING, "Awaiting certificate issuance")
        return

    data = kube.secret_data(secret)
    cert_pem = data["tls.crt"]
    key_pem = data["tls.key"]
    desired = sha256_fingerprint(cert_pem)

    # 3. Ask the provisioner whether the target already has this exact leaf.
    prov = build_provisioner(spec["provisioner"], kube, namespace)
    if prov.is_current(cert_pem):
        log.info("[%s] installed certificate is up to date (%s)", ref, desired[:16])
        message = "Certificate up to date"
        warning = getattr(prov, "pending_warning", None)
        if warning:
            log.warning("[%s] %s", ref, warning)
            message = f"{message}, but {warning}"
        set_status(
            kube, pub, PUBLISHED, message,
            published_fingerprint=desired,
        )
        return

    # 4. Publish.
    log.info("[%s] publishing certificate %s", ref, desired[:16])
    prov.install(cert_pem, key_pem)
    log.info("[%s] certificate published", ref)
    set_status(
        kube, pub, PUBLISHED, "Certificate published",
        published_fingerprint=desired, mark_published=True,
    )
