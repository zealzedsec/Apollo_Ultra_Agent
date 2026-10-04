"""Tests for the safety gate: preflight + guarded_action decorator."""
import pytest

from apollo_core.errors import SafetyError
from apollo_core.models import ActionResult
from apollo_core.safety import guarded_action, preflight


def test_preflight_allows_unenforced():
    gate = preflight("scan", target="8.8.8.8")
    assert gate.allowed
    assert gate.dry_run is False


def test_preflight_blocks_out_of_scope(set_flags):
    # Configure an engagement with a tight scope, then enforce it.
    from apollo_core.authorization import EngagementContext
    EngagementContext(engagement_id="S", authorized=True,
                      scope_allow=["10.0.0.0/24"]).save()
    set_flags(APOLLO_ENFORCE_SCOPE="1")
    assert preflight("scan", target="10.0.0.5").allowed
    assert not preflight("scan", target="1.1.1.1").allowed


def test_preflight_writes_audit_entry():
    from apollo_core.logging import get_audit_log
    preflight("scan", target="10.0.0.9")
    entries = get_audit_log().read_all()
    assert entries
    assert entries[-1]["action"] == "scan"
    assert entries[-1]["target"] == "10.0.0.9"


def test_preflight_dry_run(set_flags):
    set_flags(APOLLO_DRY_RUN="1")
    gate = preflight("scan", target="10.0.0.9")
    assert gate.allowed
    assert gate.dry_run is True


def test_guarded_action_runs_when_allowed():
    @guarded_action(action="probe")
    def probe(target):
        return f"ran against {target}"

    assert probe("10.0.0.5") == "ran against 10.0.0.5"


def test_guarded_action_dry_run_skips_body(set_flags):
    set_flags(APOLLO_DRY_RUN="1")
    calls = []

    @guarded_action(action="probe")
    def probe(target):
        calls.append(target)
        return "executed"

    result = probe("10.0.0.5")
    assert isinstance(result, ActionResult)
    assert result.status == "dry_run"
    assert calls == []  # body never ran


def test_guarded_action_blocks_and_raises(set_flags):
    from apollo_core.authorization import EngagementContext
    EngagementContext(engagement_id="B", authorized=True,
                      scope_allow=["10.0.0.0/24"]).save()
    set_flags(APOLLO_ENFORCE_SCOPE="1")

    @guarded_action(action="exploit", intrusive=True)
    def exploit(target):
        return "pwned"

    with pytest.raises(SafetyError):
        exploit("1.1.1.1")


def test_guarded_action_block_returns_result_when_configured(set_flags):
    from apollo_core.authorization import EngagementContext
    EngagementContext(engagement_id="B", authorized=True,
                      scope_allow=["10.0.0.0/24"]).save()
    set_flags(APOLLO_ENFORCE_SCOPE="1")

    @guarded_action(action="exploit", raise_on_block=False)
    def exploit(target):
        return "pwned"

    result = exploit("1.1.1.1")
    assert isinstance(result, ActionResult)
    assert result.status == "blocked"
    assert result.allowed is False
