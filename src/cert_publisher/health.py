"""Liveness and readiness endpoints for the operator Deployment.

A CronJob's health was its exit code. A Deployment has no exit code to report,
so the same information has to be reachable over HTTP:

``/healthz``
    Is this process still doing its job? It answers no when a watch has gone
    silent -- a connection that is neither delivering events nor failing, which
    no amount of waiting fixes -- so the kubelet restarts the pod and it
    relists.

``/readyz``
    Is this process wired up and campaigning for the lease? Deliberately *not*
    "is it the leader": a rolling update replaces pods one at a time and waits
    for each to become ready, so a readiness gate that only the leader can pass
    deadlocks the moment there is more than one replica -- the new pod waits
    for the lease the old pod is holding, and the old pod waits to be replaced.

``/leader``
    Is this replica the one reconciling? The honest answer to that question,
    kept out of the probes for the reason above, and worth scraping or curling
    when you want to know which pod to read the logs of.
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
        self._ready = threading.Event()
        self._leading = threading.Event()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- state -------------------------------------------------------------

    def add_liveness_check(self, check: Callable[[], bool]) -> None:
        self._live_checks.append(check)

    def set_ready(self, ready: bool) -> None:
        if ready:
            self._ready.set()
        else:
            self._ready.clear()

    def set_leading(self, leading: bool) -> None:
        if leading:
            self._leading.set()
        else:
            self._leading.clear()

    def _alive(self) -> bool:
        for check in self._live_checks:
            try:
                if not check():
                    return False
            except Exception:
                log.exception("liveness check raised; reporting unhealthy")
                return False
        return True

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # http.server's spelling, not ours
                path = self.path.split("?", 1)[0].rstrip("/") or "/"
                if path == "/healthz":
                    ok, body = outer._alive(), b"ok\n"
                elif path == "/readyz":
                    ok = outer._ready.is_set()
                    body = b"ok\n" if ok else b"starting\n"
                elif path == "/leader":
                    ok = outer._leading.is_set()
                    body = b"leading\n" if ok else b"standby\n"
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
