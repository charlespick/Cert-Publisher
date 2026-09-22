"""Thin wrapper around the Kubernetes API for the resources we touch."""

from __future__ import annotations

import base64
import logging
import os

from kubernetes import client
from kubernetes import config as kube_config
from kubernetes.client.rest import ApiException

from .utils import now_rfc3339

log = logging.getLogger("cert-publisher.kube")

KIND = "CertPublication"

# The CertPublication custom resource this operator reconciles.
GROUP = "certpublisher.makerland.xyz"
VERSION = "v1alpha1"
PLURAL = "certpublications"

# cert-manager Certificate resources we create on the user's behalf.
CM_GROUP = "cert-manager.io"
CM_VERSION = "v1"
CM_PLURAL = "certificates"
# CertificateRequests are used by provisioners whose target host keeps its own
# private key: there is no keypair for cert-manager to generate, only a CSR for
# it to sign.
CM_CR_PLURAL = "certificaterequests"


class Kube:
    def __init__(self, *, reporter: str = "cert-publisher") -> None:
        try:
            kube_config.load_incluster_config()
        except kube_config.ConfigException:
            kube_config.load_kube_config()
        self.custom = client.CustomObjectsApi()
        self.core = client.CoreV1Api()
        # Names this process in the Events it emits.
        self.reporter = reporter
        self.instance = os.environ.get("POD_NAME") or reporter

    def get_publication(self, namespace: str, name: str) -> dict | None:
        """Read one publication, or None if it has been deleted.

        The controller works from keys rather than from the objects in watch
        events, and re-reads here, so a reconcile always acts on the current
        spec rather than on whichever event happened to wake it.
        """
        try:
            return self.custom.get_namespaced_custom_object(
                GROUP, VERSION, namespace, PLURAL, name
            )
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise

    def get_certificate(self, namespace: str, name: str) -> dict | None:
        try:
            return self.custom.get_namespaced_custom_object(
                CM_GROUP, CM_VERSION, namespace, CM_PLURAL, name
            )
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise

    def create_certificate(self, namespace: str, body: dict) -> dict:
        return self.custom.create_namespaced_custom_object(
            CM_GROUP, CM_VERSION, namespace, CM_PLURAL, body
        )

    def patch_certificate(self, namespace: str, name: str, spec: dict) -> dict:
        # Merge patch the managed spec fields into the existing Certificate so
        # cert-manager reissues for the updated publication.
        return self.custom.patch_namespaced_custom_object(
            CM_GROUP, CM_VERSION, namespace, CM_PLURAL, name, {"spec": spec}
        )

    def get_certificate_request(self, namespace: str, name: str) -> dict | None:
        try:
            return self.custom.get_namespaced_custom_object(
                CM_GROUP, CM_VERSION, namespace, CM_CR_PLURAL, name
            )
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise

    def create_certificate_request(self, namespace: str, body: dict) -> dict:
        # Defensive: the reconciler records the request name on .status before
        # creating it, so a duplicate create is not an expected path. Adopting
        # on 409 keeps an unexpected one from wedging the publication forever.
        try:
            return self.custom.create_namespaced_custom_object(
                CM_GROUP, CM_VERSION, namespace, CM_CR_PLURAL, body
            )
        except ApiException as exc:
            if exc.status != 409:
                raise
            name = body["metadata"]["name"]
            log.info("adopting existing CertificateRequest %s/%s", namespace, name)
            return self.custom.get_namespaced_custom_object(
                CM_GROUP, CM_VERSION, namespace, CM_CR_PLURAL, name
            )

    def delete_certificate_request(self, namespace: str, name: str) -> None:
        # A spent or rejected request is deleted so the next reconcile can
        # create a fresh one: a CertificateRequest's spec is immutable, so it
        # can never be retried in place.
        try:
            self.custom.delete_namespaced_custom_object(
                CM_GROUP, CM_VERSION, namespace, CM_CR_PLURAL, name
            )
        except ApiException as exc:
            if exc.status != 404:
                raise

    def patch_publication_status(self, namespace: str, name: str, status: dict) -> None:
        # Merge patch against the /status subresource: omitted fields are
        # preserved, so callers only set what changed.
        self.custom.patch_namespaced_custom_object_status(
            GROUP, VERSION, namespace, PLURAL, name, {"status": status}
        )

    def get_secret(self, namespace: str, name: str):
        try:
            return self.core.read_namespaced_secret(name, namespace)
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise

    @staticmethod
    def secret_data(secret) -> dict[str, bytes]:
        """Decode a V1Secret's ``data`` map to raw bytes."""
        return {k: base64.b64decode(v) for k, v in (secret.data or {}).items()}

    def record_event(self, pub: dict, event_type: str, reason: str, message: str) -> None:
        """Attach an Event to a publication, so ``kubectl describe`` shows it.

        Best-effort in the strictest sense: an operator that cannot write an
        Event has still done its job, and the same outcome is already on
        ``.status`` and in the logs. Events are also the one write here that a
        namespace ResourceQuota can legitimately refuse.
        """
        meta = pub["metadata"]
        namespace = meta["namespace"]
        stamp = now_rfc3339()
        body = {
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": {
                # generateName rather than a name we compose: two transitions
                # in the same second, or an old pod and its replacement, must
                # not collide on it.
                "generateName": f"{meta['name']}.",
                "namespace": namespace,
            },
            "involvedObject": {
                "apiVersion": f"{GROUP}/{VERSION}",
                "kind": KIND,
                "name": meta["name"],
                "namespace": namespace,
                "uid": meta.get("uid"),
                "resourceVersion": meta.get("resourceVersion"),
            },
            "type": event_type,
            "reason": reason,
            # The apiserver caps this; a provisioner traceback can exceed it.
            "message": message[:1024],
            # The legacy timestamp fields, deliberately: setting eventTime
            # switches the apiserver to validating this as a v1beta1-style
            # event, which then requires fields this one has no use for.
            "firstTimestamp": stamp,
            "lastTimestamp": stamp,
            "count": 1,
            "source": {"component": self.reporter},
            "reportingComponent": self.reporter,
            "reportingInstance": self.instance,
        }
        try:
            self.core.create_namespaced_event(namespace, body)
        except Exception:
            log.debug("could not record event for %s/%s", namespace, meta["name"],
                      exc_info=True)
