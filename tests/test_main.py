"""The entrypoint's exit codes: what a pod's termination state says happened."""

import pytest

from cert_publisher import main as main_mod


class _FakeHealth:
    def __init__(self, port):
        pass

    def add_liveness_check(self, check):
        pass

    def start(self):
        pass

    def stop(self):
        pass

    def set_ready(self, ready):
        pass

    def set_leading(self, leading):
        pass


class _FakeElector:
    """Wins at once, then shuts down as a SIGTERM would."""

    def __init__(self, *args, **kwargs):
        pass

    def run(self, *, on_started_leading, on_stopped_leading, stop_event,
            on_reachable=None):
        on_started_leading()
        on_stopped_leading()


def _run_main(monkeypatch, *, drained):
    class _FakeController:
        def __init__(self, kube, config):
            pass

        def healthy(self):
            return True

        def start(self):
            pass

        def stop(self):
            return drained

    monkeypatch.setattr(main_mod, "Kube", lambda: type("K", (), {"coordination": None})())
    monkeypatch.setattr(main_mod, "Controller", _FakeController)
    monkeypatch.setattr(main_mod, "HealthServer", _FakeHealth)
    monkeypatch.setattr(main_mod, "LeaderElector", _FakeElector)
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
