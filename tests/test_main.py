"""The entrypoint's exit codes: what a pod's termination state says happened."""

import pytest

from cert_publisher import main as main_mod


class _FakeHealth:
    def __init__(self, port):
        self.readiness = []

    def add_liveness_check(self, check):
        pass

    def add_readiness_check(self, check):
        self.readiness.append(check)

    def start(self):
        pass

    def stop(self):
        pass


def _run_main(monkeypatch, *, drained):
    class _FakeController:
        def __init__(self, kube, config):
            pass

        def healthy(self):
            return True

        def ready(self):
            return True

        def start(self):
            pass

        def stop(self):
            return drained

    class _AlreadySignalled:
        """SIGTERM arrived as soon as the controller was up."""

        def wait(self, timeout=None):
            return True

        def set(self):
            pass

    monkeypatch.setattr(main_mod, "Kube", lambda: object())
    monkeypatch.setattr(main_mod, "Controller", _FakeController)
    monkeypatch.setattr(main_mod, "HealthServer", _FakeHealth)
    monkeypatch.setattr(main_mod.threading, "Event", _AlreadySignalled)
    monkeypatch.setattr(main_mod.signal, "signal", lambda *a: None)
    return main_mod.main()


def test_a_clean_shutdown_exits_zero(monkeypatch):
    assert _run_main(monkeypatch, drained=True) == 0


def test_a_shutdown_that_cut_off_a_host_write_exits_non_zero(monkeypatch):
    """The pod is going away regardless; the exit code is how the interrupted
    write shows up in its last termination state and not only in its logs."""
    assert _run_main(monkeypatch, drained=False) == 1


@pytest.fixture(autouse=True)
def _no_logging_shutdown(monkeypatch):
    # main() calls logging.shutdown() on the way out, which would close
    # pytest's own capture handlers for every test after this one.
    monkeypatch.setattr(main_mod.logging, "shutdown", lambda: None)
    monkeypatch.setattr(main_mod, "_setup_logging", lambda: None)
