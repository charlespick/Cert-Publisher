"""CronJob entrypoint: scan CertPublications and reconcile each one."""

from __future__ import annotations

import logging
import os
import sys

from .kube import Kube
from .reconcile import reconcile_publication
from .status import ERROR, set_status


def _setup_logging() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def main() -> int:
    _setup_logging()
    log = logging.getLogger("cert-publisher")

    kube = Kube()
    # Empty/unset WATCH_NAMESPACE reconciles across the whole cluster.
    namespace = os.environ.get("WATCH_NAMESPACE") or None

    publications = kube.list_publications(namespace)
    log.info("found %d CertPublication(s)", len(publications))

    failures = 0
    for pub in publications:
        ref = f"{pub['metadata']['namespace']}/{pub['metadata']['name']}"
        try:
            reconcile_publication(kube, pub)
        except Exception as exc:  # keep going; one bad host shouldn't block the rest
            log.exception("[%s] reconcile failed", ref)
            set_status(kube, pub, ERROR, str(exc))
            failures += 1

    if failures:
        log.error("%d/%d publication(s) failed", failures, len(publications))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
