"""Liveness and readiness endpoints for the operator pod.

A CronJob's health was its exit code. A long-running pod has no exit code to report,
so the same information has to be reachable over HTTP:

``/healthz``
    Is this process still doing its job? It answers no when a watch has gone
    silent -- a connection that is neither delivering events nor failing, which
    no amount of waiting fixes -- so the kubelet restarts the pod and it
    relists.

``/readyz``
    Has this process reached the apiserver with working credentials and RBAC?
    It turns ready once the first list of CertPublications succeeds, so a pod
    that cannot do its job does not report that it can.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("cert-publisher.health")


class HealthServer:
    """A tiny HTTP server exposing ``/healthz`` and ``/readyz``."""

    def __init__(self, port: int, address: str = "0.0.0.0") -> None:
        self._port = port
        self._address = address
        self._live_checks: list[Callable[[], bool]] = []
        self._ready_checks: list[Callable[[], bool]] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- state -------------------------------------------------------------

    def add_liveness_check(self, check: Callable[[], bool]) -> None:
        self._live_checks.append(check)

    def add_readiness_check(self, check: Callable[[], bool]) -> None:
        self._ready_checks.append(check)

    @staticmethod
    def _passes(checks: list[Callable[[], bool]], what: str) -> bool:
        for check in checks:
            try:
                if not check():
                    return False
            except Exception:
                log.exception("%s check raised; reporting failure", what)
                return False
        return True

    def _alive(self) -> bool:
        return self._passes(self._live_checks, "liveness")

    def _ready(self) -> bool:
        # Not ready until something has said what ready means.
        return bool(self._ready_checks) and self._passes(self._ready_checks, "readiness")

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # http.server's spelling, not ours
                path = self.path.split("?", 1)[0].rstrip("/") or "/"
                if path == "/healthz":
                    ok = outer._alive()
                    body = b"ok\n" if ok else b"unhealthy\n"
                elif path == "/readyz":
                    ok = outer._ready()
                    body = b"ok\n" if ok else b"starting\n"
                else:
                    ok, body = False, b"not found\n"
                    self._respond(404, body)
                    return
                self._respond(200 if ok else 503, body)

            def _respond(self, code: int, body: bytes) -> None:
                self.send_response(code)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args) -> None:
                # Probes hit this every few seconds; the default handler would
                # write a line to stderr for each one.
                return

        self._server = ThreadingHTTPServer((self._address, self._port), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="health", daemon=True
        )
        self._thread.start()
        log.info("health endpoints listening on %s:%d", self._address, self._port)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
