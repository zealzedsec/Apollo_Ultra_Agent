"""The orchestrator must not run a tool command when the safety gate says no."""
import pytest

import orchestrator
from apollo_core.authorization import EngagementContext


@pytest.fixture(autouse=True)
def _no_db(monkeypatch):
    # The gate decisions happen before any KB write; stub the logger so the test
    # never touches a database.
    monkeypatch.setattr(orchestrator, "log_command", lambda *a, **k: None)


def test_shell_unsafe_target_is_blocked():
    res = orchestrator.execute_step("naabu", "10.0.0.5; rm -rf /", pid=1, context={})
    assert res["exit_code"] == 126
    assert res.get("blocked") is True


def test_dry_run_does_not_execute(set_flags, monkeypatch):
    # If a command were ever built/run, _run_cmd would be called; make it fail
    # loudly so the test proves the dry-run path short-circuits before it.
    monkeypatch.setattr(orchestrator, "_run_cmd",
                        lambda *a, **k: pytest.fail("command executed during dry-run"))
    set_flags(APOLLO_DRY_RUN="1")
    res = orchestrator.execute_step("naabu", "10.0.0.5", pid=1, context={})
    assert res["exit_code"] == 0
    assert res.get("dry_run") is True


def test_out_of_scope_target_is_blocked(set_flags, monkeypatch):
    EngagementContext(engagement_id="O", authorized=True,
                      scope_allow=["10.0.0.0/24"]).save()
    set_flags(APOLLO_ENFORCE_SCOPE="1")
    monkeypatch.setattr(orchestrator, "_run_cmd",
                        lambda *a, **k: pytest.fail("command executed for blocked target"))
    res = orchestrator.execute_step("nmap", "1.1.1.1", pid=1, context={})
    assert res["exit_code"] == 126
    assert res.get("blocked") is True
