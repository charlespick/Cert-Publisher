"""Thin wrapper around the Kubernetes API for the resources we touch."""

from __future__ import annotations

import base64
import logging

from kubernetes import client
from kubernetes import config as kube_config
from kubernetes.client.rest import ApiException

log = logging.getLogger("cert-publisher.kube")

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
    def __init__(self) -> None:
        try:
            kube_config.load_incluster_config()
        except kube_config.ConfigException:
            kube_config.load_kube_config()
        self.custom = client.CustomObjectsApi()
        self.core = client.CoreV1Api()

    def list_publications(self, namespace: str | None = None) -> list[dict]:
        if namespace:
            resp = self.custom.list_namespaced_custom_object(GROUP, VERSION, namespace, PLURAL)
        else:
            resp = self.custom.list_cluster_custom_object(GROUP, VERSION, PLURAL)
        return resp.get("items", [])

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
