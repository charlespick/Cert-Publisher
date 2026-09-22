"""Probes are how a long-running pod says what an exit code used to."""

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
    return _fetch(server, path)[0]


def _fetch(server, path):
    url = f"http://127.0.0.1:{server._port}{path}"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def test_a_fresh_process_is_alive_but_not_yet_ready(server):
    assert _get(server, "/healthz") == 200
    assert _get(server, "/readyz") == 503


def test_readiness_follows_its_checks(server):
    ready = [False]
    server.add_readiness_check(lambda: ready[0])
    assert _get(server, "/readyz") == 503
    ready[0] = True
    assert _get(server, "/readyz") == 200


def test_a_readiness_check_that_raises_is_not_ready(server):
    server.add_readiness_check(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert _get(server, "/readyz") == 503


def test_there_is_no_leader_endpoint_any_more(server):
    assert _get(server, "/leader") == 404


def test_a_failing_check_fails_liveness(server):
    server.add_liveness_check(lambda: False)
    status, body = _fetch(server, "/healthz")
    assert status == 503
    # Anyone curling this while chasing a restart loop reads the body.
    assert body == b"unhealthy\n"


def test_a_check_that_raises_fails_liveness_rather_than_the_probe(server):
    server.add_liveness_check(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert _get(server, "/healthz") == 503


def test_unknown_paths_are_not_found(server):
    assert _get(server, "/metrics") == 404
