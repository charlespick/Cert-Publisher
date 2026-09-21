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
            on_reachable=None, on_lost_leading=None):
        on_started_leading()
        on_stopped_leading()


class _LosingElector(_FakeElector):
    """Wins, then loses the lease while a worker is busy."""

    def run(self, *, on_started_leading, on_stopped_leading, stop_event,
            on_reachable=None, on_lost_leading=None):
        on_started_leading()
        on_lost_leading(main_mod.LeadershipLost("renewal failed"))
        raise main_mod.LeadershipLost("renewal failed")


class _HardExit(Exception):
    def __init__(self, code):
        self.code = code


def _run_main(monkeypatch, *, drained, elector=_FakeElector):
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
    monkeypatch.setattr(main_mod, "LeaderElector", elector)
    monkeypatch.setattr(main_mod.signal, "signal", lambda *a: None)

    def _hard_exit(code):
        raise _HardExit(code)

    monkeypatch.setattr(main_mod, "_hard_exit", _hard_exit)
    try:
        return main_mod.main()
    except _HardExit as exc:
        return ("hard exit", exc.code)


def test_a_clean_shutdown_exits_zero(monkeypatch):
    assert _run_main(monkeypatch, drained=True) == 0


def test_a_shutdown_that_cut_off_a_host_write_exits_at_once_non_zero(monkeypatch):
    """The lease was kept, not released, and stops being renewed now, so the
    worker has to die before it expires -- not whenever interpreter shutdown
    gets to it. The non-zero code puts the interruption on the pod's last
    termination state."""
    assert _run_main(monkeypatch, drained=False) == ("hard exit", 1)


def test_a_lost_lease_exits_at_once_without_draining(monkeypatch):
    """A standby may already be leading; a worker left running would race it."""
    assert _run_main(monkeypatch, drained=True, elector=_LosingElector) == (
        "hard exit", 1,
    )


@pytest.fixture(autouse=True)
def _no_logging_shutdown(monkeypatch):
    # main() calls logging.shutdown() on the way out, which would close
    # pytest's own capture handlers for every test after this one.
    monkeypatch.setattr(main_mod.logging, "shutdown", lambda: None)
    monkeypatch.setattr(main_mod, "_setup_logging", lambda: None)
