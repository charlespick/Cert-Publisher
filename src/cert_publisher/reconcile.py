"""Core reconcile logic for a single CertPublication.

Every publication follows the same three beats -- decide whether the target is
already current, ask cert-manager for material if it isn't, install it when it
arrives -- but *who owns the private key* changes what each beat means, so there
are two implementations rather than one with branches threaded through it:

``_reconcile_secret_keyed``
    cert-manager generates the keypair. A Certificate is created, and once the
    issued Secret carries both halves they are compared against the host and
    pushed. This is the path SSH and WinRM take, and it is unchanged.

``_reconcile_host_keyed``
    The target will not accept an externally generated key (a Dell iDRAC8 has
    no key-upload path at all), so it keeps its own. There is no Certificate and
    no issued Secret; the host emits a CSR, a CertificateRequest signs it, and
    the signed certificate is imported back. Because a CertificateRequest is
    signed once and never renewed, this path also owns renewal timing.
"""

from __future__ import annotations

import datetime
import hashlib
import logging

from .certmanager import (
    CR_FAILED,
    CR_READY,
    build_certificate_body,
    build_certificate_request_body,
    certificate_request_state,
    certificate_spec_drift,
    issued_certificate,
)
from .kube import Kube
from .provisioners import build_provisioner, manages_own_key
from .status import ERROR, PENDING, PUBLISHED, set_status
from .utils import (
    certificate_dns_names,
    leaf_certificate,
    parse_go_duration,
    renewal_due,
    sha256_fingerprint,
)

log = logging.getLogger("cert-publisher.reconcile")


def reconcile_publication(kube: Kube, pub: dict) -> None:
    meta = pub["metadata"]
    spec = pub["spec"]
    ref = f"{meta['namespace']}/{meta['name']}"

    if manages_own_key(spec["provisioner"]["type"]):
        _reconcile_host_keyed(kube, pub, ref)
    else:
        _reconcile_secret_keyed(kube, pub, ref)


# -- cert-manager owns the key (ssh, winrm) -------------------------------


def _reconcile_secret_keyed(kube: Kube, pub: dict, ref: str) -> None:
    meta = pub["metadata"]
    spec = pub["spec"]
    name = meta["name"]
    namespace = meta["namespace"]
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


# -- the host owns the key (idrac8) ---------------------------------------

# A signing round that does not converge would otherwise rotate the host's key
# and reset the BMC on every reconcile. Refuse to open a new round this soon
# after the last one, turning a silent loop into a visible error.
_SIGNING_COOLDOWN = datetime.timedelta(hours=1)

# How long a CertificateRequest may sit unanswered before it is treated as
# failed. cert-manager signs in seconds; anything still pending after this is
# waiting on an approver that is never going to answer.
_REQUEST_TIMEOUT = datetime.timedelta(hours=1)


def _reconcile_host_keyed(kube: Kube, pub: dict, ref: str) -> None:
    meta = pub["metadata"]
    spec = pub["spec"]
    namespace = meta["namespace"]
    status = pub.get("status") or {}

    prov = build_provisioner(spec["provisioner"], kube, namespace)

    # 1. Finish any signing already in flight before considering a new one.
    #    Generating a CSR rotates the host's private key, so re-deciding
    #    renewal while a request is outstanding would strand the pending CSR.
    pending = status.get("pendingRequestName")
    if pending:
        _resolve_pending_request(kube, pub, prov, pending, ref)
        return

    # 2. Decide whether the certificate the host holds still does the job.
    installed = prov.installed_certificate()

    misconfigured = _renew_before_problem(installed, spec)
    if misconfigured is not None:
        # Left alone this never converges: the certificate is inside its
        # renewal window the moment it is issued, so every run would sign,
        # import and reboot the BMC again. cert-manager rejects this on a
        # Certificate; nothing validates it on this path, so do it here.
        log.error("[%s] %s", ref, misconfigured)
        set_status(kube, pub, ERROR, f"Misconfigured: {misconfigured}")
        return

    reason = _renewal_reason(installed, spec, status)
    if reason is None:
        fingerprint = sha256_fingerprint(installed)
        log.info("[%s] installed certificate is up to date (%s)", ref, fingerprint[:16])
        set_status(
            kube, pub, PUBLISHED, "Certificate up to date",
            published_fingerprint=fingerprint,
        )
        return

    # 3. Renewal is wanted -- but if we only just signed, the last round did not
    #    achieve it. Signing again would rotate the key and reset the BMC on
    #    every run, so stop and say so instead.
    #
    #    Unless the publication itself changed since we last looked: editing it
    #    is an operator saying "I've addressed that", and making them wait out
    #    a rate limit aimed at runaway retries would be the wrong answer to a
    #    deliberate act.
    since = _time_since(status.get("lastSigningTime"))
    # Absent observedGeneration means we cannot tell whether the spec moved, so
    # keep the rate limit: it exists to stop repeated BMC reboots, and the safe
    # default when uncertain is to hold rather than retry.
    observed = status.get("observedGeneration")
    spec_changed = observed is not None and observed != meta.get("generation")
    if not spec_changed and since is not None and since < _SIGNING_COOLDOWN:
        remaining = _SIGNING_COOLDOWN - since
        log.error("[%s] still needs renewal right after signing: %s", ref, reason)
        set_status(
            kube, pub, ERROR,
            f"A signing round started less than {_SIGNING_COOLDOWN} ago but "
            f"the host still needs renewal ({reason}); not starting another "
            f"for {remaining}. If a certificate was imported, check that the "
            f"iDRAC restarted to apply it and that it carries the expected "
            f"subject alternative names. If no certificate was issued, check "
            f"the issuer and any approver policy for this namespace. Editing "
            f"the publication retries immediately; so does clearing "
            f".status.lastSigningTime.",
        )
        return
    if spec_changed and since is not None and since < _SIGNING_COOLDOWN:
        log.info("[%s] publication changed; retrying without waiting out the "
                 "signing cooldown", ref)

    # 4. Have the host mint a CSR and ask cert-manager to sign it.
    log.info("[%s] renewing: %s", ref, reason)
    _start_signing(kube, pub, prov, ref, reason)


def _time_since(stamp: str | None) -> datetime.timedelta | None:
    """How long ago ``stamp`` was, or None if it is absent or unparseable."""
    if not stamp:
        return None
    try:
        when = datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.UTC
        )
    except ValueError:
        return None
    return datetime.datetime.now(datetime.UTC) - when


def _renew_before_problem(installed: bytes | None, spec: dict) -> str | None:
    """Whether ``renewBefore`` can never be satisfied by this certificate.

    A window at least as long as the certificate's whole lifetime means the
    certificate is due for renewal from the instant it is issued.
    """
    renew_before = spec.get("renewBefore")
    if not renew_before or installed is None:
        return None
    try:
        cert = leaf_certificate(installed)
    except ValueError:
        return None  # _renewal_reason reports the parse failure instead
    try:
        window = parse_go_duration(renew_before)
    except ValueError:
        return f"renewBefore {renew_before!r} is not a valid duration"
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    if window >= lifetime:
        return (
            f"renewBefore ({renew_before}) is longer than the lifetime of the "
            f"certificate being issued ({lifetime}), so it would be treated as "
            f"due for renewal the moment it is installed"
        )
    return None


def _renewal_reason(installed: bytes | None, spec: dict, status: dict) -> str | None:
    """Why the host needs a new certificate, or None if it doesn't.

    Unlike the Secret-keyed path there is no issued certificate to compare
    against -- the host's certificate is the only copy -- so "is this current?"
    is answered from the certificate itself plus the fingerprint we recorded
    when we last published. A certificate we did not install (a factory
    self-signed one, or one replaced out of band) fails the fingerprint check
    and is replaced, which is what makes the first run against a fresh iDRAC do
    the right thing.
    """
    if installed is None:
        return "the host is not serving a certificate we can read"

    try:
        cert = leaf_certificate(installed)
    except ValueError:
        return "the installed certificate could not be parsed"

    published = status.get("publishedFingerprint")
    if not published:
        return "no certificate has been published to this host yet"
    if published != sha256_fingerprint(installed):
        return "the installed certificate was not published by cert-publisher"

    missing = sorted(set(spec["dnsNames"]) - certificate_dns_names(cert))
    if missing:
        return f"the installed certificate does not cover {', '.join(missing)}"

    if renewal_due(cert, renew_before=spec.get("renewBefore")):
        return "the installed certificate is due for renewal"

    return None


def _unusable_signed_certificate(cert_pem: bytes, spec: dict) -> str | None:
    """Why the signed certificate must not be installed, or None if it is fine.

    Checked *before* importing, because importing a certificate that does not
    satisfy the publication is worse than not importing one: the next reconcile
    would see it as still needing renewal and start another round, rotating the
    host's key and resetting the BMC on every tick.
    """
    try:
        cert = leaf_certificate(cert_pem)
    except ValueError:
        return "it could not be parsed"
    missing = sorted(set(spec["dnsNames"]) - certificate_dns_names(cert))
    if missing:
        return f"it does not cover {', '.join(missing)}"
    return None


def _resolve_pending_request(
    kube: Kube, pub: dict, prov, pending: str, ref: str
) -> None:
    """Act on the outstanding CertificateRequest, if it has an answer yet."""
    meta = pub["metadata"]
    spec = pub["spec"]
    namespace = meta["namespace"]

    request = kube.get_certificate_request(namespace, pending)
    if request is None:
        log.warning("[%s] pending CertificateRequest %s is gone; will retry", ref, pending)
        set_status(
            kube, pub, PENDING,
            "Pending signing request disappeared; a new one will be created",
            pending_request=None,
        )
        return

    state, detail = certificate_request_state(request)
    if state == CR_FAILED:
        # The spec of a CertificateRequest is immutable, so a rejected one can
        # never be retried in place; drop it and start over next run.
        log.error("[%s] signing request %s failed: %s", ref, pending, detail)
        kube.delete_certificate_request(namespace, pending)
        set_status(
            kube, pub, PENDING,
            f"Signing request failed ({detail}); a new one will be created",
            pending_request=None,
        )
        return

    if state != CR_READY:
        age = _time_since(
            (request.get("metadata") or {}).get("creationTimestamp", "").replace(
                "+00:00", "Z"
            )
        )
        if age is not None and age > _REQUEST_TIMEOUT:
            # Never approved, and nothing is going to approve it now -- most
            # often an issuerRef no approver is configured for. Waiting forever
            # would let the host's certificate expire without an error.
            log.error("[%s] signing request %s was never signed", ref, pending)
            kube.delete_certificate_request(namespace, pending)
            set_status(
                kube, pub, ERROR,
                f"Signing request was not signed within {_REQUEST_TIMEOUT} "
                f"({detail}); check that an approver is configured for this "
                f"issuer. A new request will be created.",
                pending_request=None,
            )
            return
        log.info("[%s] signing request %s is pending: %s", ref, pending, detail)
        set_status(kube, pub, PENDING, f"Awaiting certificate issuance ({detail})")
        return

    cert_pem = issued_certificate(request)
    problem = _unusable_signed_certificate(cert_pem, spec)
    if problem is not None:
        log.error("[%s] refusing to import the signed certificate: %s", ref, problem)
        kube.delete_certificate_request(namespace, pending)
        set_status(
            kube, pub, ERROR,
            f"The signed certificate was not installed because {problem}. This "
            f"usually means the host's CSR did not carry the requested subject "
            f"alternative names.",
            pending_request=None,
        )
        return

    fingerprint = sha256_fingerprint(cert_pem)

    # A previous run may have imported this and then failed before recording
    # it. Re-importing would reset the BMC a second time for nothing, so check
    # first -- the host is the source of truth for what it is holding.
    if _already_installed(prov, fingerprint):
        log.info("[%s] signed certificate %s is already installed", ref, fingerprint[:16])
    else:
        log.info("[%s] importing signed certificate %s", ref, fingerprint[:16])
        prov.import_certificate(cert_pem)
        log.info("[%s] certificate published", ref)

    # Only drop the request once the host has actually taken the certificate,
    # so a failed import is retried against the same signed material instead of
    # rotating the host's key for a fresh CSR.
    kube.delete_certificate_request(namespace, pending)
    set_status(
        kube, pub, PUBLISHED, "Certificate published",
        published_fingerprint=fingerprint, mark_published=True,
        pending_request=None,
    )


def _already_installed(prov, fingerprint: str) -> bool:
    """Whether the host is already holding the certificate with this fingerprint."""
    try:
        installed = prov.installed_certificate()
    except Exception:  # a failed read must not block the import
        log.debug("could not read the installed certificate before importing",
                  exc_info=True)
        return False
    if installed is None:
        return False
    try:
        return sha256_fingerprint(installed) == fingerprint
    except ValueError:
        return False


def _start_signing(kube: Kube, pub: dict, prov, ref: str, reason: str) -> None:
    """Rotate the host's key, then submit its CSR to cert-manager."""
    meta = pub["metadata"]
    spec = pub["spec"]
    namespace = meta["namespace"]

    dns_names = spec["dnsNames"]
    common_name = spec.get("commonName") or dns_names[0]
    csr_pem = prov.generate_csr(common_name=common_name, dns_names=dns_names)

    digest = hashlib.sha256(csr_pem).hexdigest()[:10]
    request_name = f"{meta['name']}-{digest}"

    # Record the name *before* creating the request, and insist the write
    # lands. Generating a CSR has already rotated the host's key, so the
    # ordering decides what a failure costs: recorded-then-missing is
    # self-healing (the next run finds a dangling name and clears it), whereas
    # created-then-unrecorded strands a request nothing will ever look up
    # again, because the next CSR yields a different name. That only holds if
    # the write actually succeeded, hence strict -- a status write we cannot
    # confirm means we do not create the request at all.
    set_status(
        kube, pub, PENDING,
        f"Signing request submitted ({reason}); awaiting issuance",
        pending_request=request_name, mark_signing=True, strict=True,
    )
    log.info("[%s] creating CertificateRequest %s", ref, request_name)
    kube.create_certificate_request(
        namespace, build_certificate_request_body(pub, request_name, csr_pem)
    )
