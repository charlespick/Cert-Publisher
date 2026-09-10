"""Probes are how a Deployment says what an exit code used to."""

import socket
import urllib.error
import urllib.request

import pytest

from cert_publisher.health import HealthServer


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def server():
    health = HealthServer(_free_port(), address="127.0.0.1")
    health.start()
    yield health
    health.stop()


def _get(server, path):
    url = f"http://127.0.0.1:{server._port}{path}"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def test_a_fresh_process_is_alive_but_not_yet_ready(server):
    assert _get(server, "/healthz") == 200
    assert _get(server, "/readyz") == 503


def test_readiness_is_not_gated_on_leadership(server):
    """A readiness gate only the leader can pass deadlocks a rolling update."""
    server.set_ready(True)
    assert _get(server, "/readyz") == 200
    assert _get(server, "/leader") == 503, "a standby claimed to be the leader"

    server.set_leading(True)
    assert _get(server, "/leader") == 200


def test_a_failing_check_fails_liveness(server):
    server.add_liveness_check(lambda: False)
    assert _get(server, "/healthz") == 503


def test_a_check_that_raises_fails_liveness_rather_than_the_probe(server):
    server.add_liveness_check(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert _get(server, "/healthz") == 503


def test_unknown_paths_are_not_found(server):
    assert _get(server, "/metrics") == 404
