import socket

import pytest

from cert_publisher.retry import with_retries


def test_returns_on_first_success(monkeypatch):
    slept = []
    monkeypatch.setattr("cert_publisher.retry.time.sleep", slept.append)

    calls = []

    def ok():
        calls.append(1)
        return "value"

    assert with_retries(ok, description="op", attempts=3) == "value"
    assert len(calls) == 1
    assert slept == []  # no backoff when the first attempt succeeds


def test_retries_transient_then_succeeds(monkeypatch):
    slept = []
    monkeypatch.setattr("cert_publisher.retry.time.sleep", slept.append)

    attempts = {"n": 0}

    def flaky():
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise TimeoutError("timed out")
        return "ok"

    assert with_retries(flaky, description="op", attempts=3, base_delay=1.0) == "ok"
    assert attempts["n"] == 3
    # Exponential backoff between the two failed attempts: 1.0s then 2.0s.
    assert slept == [1.0, 2.0]


def test_exhaustion_raises_clear_connection_error(monkeypatch):
    monkeypatch.setattr("cert_publisher.retry.time.sleep", lambda _: None)

    def always_timeout():
        raise TimeoutError("timed out")

    with pytest.raises(ConnectionError) as excinfo:
        with_retries(
            always_timeout,
            description="WinRM endpoint check for colodc01:5986",
            attempts=3,
        )
    msg = str(excinfo.value)
    assert "WinRM endpoint check for colodc01:5986" in msg
    assert "3 attempt(s)" in msg
    assert "timed out" in msg
    assert isinstance(excinfo.value.__cause__, TimeoutError)


def test_non_retryable_propagates_immediately(monkeypatch):
    slept = []
    monkeypatch.setattr("cert_publisher.retry.time.sleep", slept.append)

    calls = []

    def bad_thumbprint():
        calls.append(1)
        raise RuntimeError("thumbprint mismatch")

    with pytest.raises(RuntimeError, match="thumbprint mismatch"):
        with_retries(bad_thumbprint, description="op", attempts=3)
    assert len(calls) == 1  # not retried
    assert slept == []


def test_socket_errors_are_retryable(monkeypatch):
    monkeypatch.setattr("cert_publisher.retry.time.sleep", lambda _: None)

    attempts = {"n": 0}

    def refused():
        attempts["n"] += 1
        if attempts["n"] < 2:
            raise socket.gaierror("name resolution failed")
        return "ok"

    assert with_retries(refused, description="op", attempts=2) == "ok"
    assert attempts["n"] == 2


def test_attempts_from_env(monkeypatch):
    monkeypatch.setattr("cert_publisher.retry.time.sleep", lambda _: None)
    monkeypatch.setenv("RETRY_ATTEMPTS", "5")

    attempts = {"n": 0}

    def always_fail():
        attempts["n"] += 1
        raise ConnectionError("nope")

    with pytest.raises(ConnectionError):
        with_retries(always_fail, description="op")
    assert attempts["n"] == 5
