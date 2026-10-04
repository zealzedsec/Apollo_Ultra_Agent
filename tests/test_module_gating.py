"""The active modules must not execute when the safety gate blocks or dry-runs.

These tests monkeypatch every executor (and the KB accessors/loggers) so nothing
touches the network, a real tool, or the database — they assert only that the
gate short-circuits before any command runs.
"""
import pytest

import auto_pwn
import c2_commander
import cred_vault
from apollo_core.authorization import EngagementContext


# --------------------------------------------------------------------------
# cred_vault
# --------------------------------------------------------------------------
def test_cred_crack_dry_run(set_flags, monkeypatch):
    monkeypatch.setattr(cred_vault, "_run_cmd",
                        lambda *a, **k: pytest.fail("cracked during dry-run"))
    set_flags(APOLLO_DRY_RUN="1")
    res = cred_vault.execute_crack("5f4dcc3b5aa765d61d8327deb882cf99")  # md5
    assert res.get("dry_run") is True


def test_cred_spray_dry_run(set_flags, monkeypatch):
    monkeypatch.setattr(cred_vault, "get_credentials",
                        lambda pid: [{"username": "u", "password": "p"}])
    monkeypatch.setattr(cred_vault, "get_hosts", lambda pid: [{"ip": "10.0.0.5"}])
    monkeypatch.setattr(cred_vault, "create_event", lambda *a, **k: None)
    monkeypatch.setattr(cred_vault, "_run_cmd",
                        lambda *a, **k: pytest.fail("sprayed during dry-run"))
    set_flags(APOLLO_DRY_RUN="1")
    res = cred_vault.execute_spray(1, target_ip="10.0.0.5")
    assert res["results"][0]["dry_run"] is True
    assert res["success_count"] == 0


def test_cred_spray_blocked_out_of_scope(set_flags, monkeypatch):
    EngagementContext(engagement_id="S", authorized=True,
                      scope_allow=["10.0.0.0/24"]).save()
    monkeypatch.setattr(cred_vault, "get_credentials",
                        lambda pid: [{"username": "u", "password": "p"}])
    monkeypatch.setattr(cred_vault, "get_hosts", lambda pid: [{"ip": "1.1.1.1"}])
    monkeypatch.setattr(cred_vault, "create_event", lambda *a, **k: None)
    monkeypatch.setattr(cred_vault, "_run_cmd",
                        lambda *a, **k: pytest.fail("sprayed a blocked target"))
    set_flags(APOLLO_ENFORCE_SCOPE="1")
    res = cred_vault.execute_spray(1, target_ip="1.1.1.1")
    assert res["results"][0]["blocked"] is True


# --------------------------------------------------------------------------
# auto_pwn
# --------------------------------------------------------------------------
def test_auto_pwn_blocked_out_of_scope(set_flags, monkeypatch):
    EngagementContext(engagement_id="A", authorized=True,
                      scope_allow=["10.0.0.0/24"]).save()
    monkeypatch.setattr(auto_pwn.subprocess, "run",
                        lambda *a, **k: pytest.fail("exploit ran against blocked target"))
    set_flags(APOLLO_ENFORCE_SCOPE="1")
    entry = {"name": "t", "id": "t", "check_cmd": "echo {ip}"}
    res = auto_pwn.attempt_exploit_rpc({"exploit": entry, "ip": "1.1.1.1"}, dry_run=False)
    assert res["blocked"] is True


def test_auto_pwn_global_dry_run_forces_check_only(set_flags, monkeypatch):
    captured = {}

    class _Proc:
        returncode = 0
        stdout = b""
        stderr = b""

    def _fake_run(cmd, *a, **k):
        captured["cmd"] = cmd
        return _Proc()

    monkeypatch.setattr(auto_pwn.subprocess, "run", _fake_run)
    monkeypatch.setattr(auto_pwn, "_record_and_log", lambda *a, **k: None)
    set_flags(APOLLO_DRY_RUN="1")
    entry = {"name": "t", "id": "t", "check_cmd": "check {ip}", "exploit_cmd": "pwn {ip}"}
    # Caller asks to really run, but global dry-run must downgrade to check-only.
    res = auto_pwn.attempt_exploit_rpc({"exploit": entry, "ip": "10.0.0.5"},
                                       lhost="10.0.0.9", dry_run=False)
    assert res["dry_run"] is True
    assert captured["cmd"] == "check 10.0.0.5"


def test_auto_pwn_rejects_shell_unsafe_target(monkeypatch):
    monkeypatch.setattr(auto_pwn.subprocess, "run",
                        lambda *a, **k: pytest.fail("ran with unsafe target"))
    entry = {"name": "t", "id": "t", "check_cmd": "echo {ip}"}
    res = auto_pwn.attempt_exploit_rpc({"exploit": entry, "ip": "10.0.0.5; id"}, dry_run=True)
    assert res["blocked"] is True


# --------------------------------------------------------------------------
# c2_commander
# --------------------------------------------------------------------------
def test_c2_deploy_agent_dry_run(set_flags, monkeypatch):
    monkeypatch.setattr(c2_commander, "_run_local",
                        lambda *a, **k: pytest.fail("msfvenom ran during dry-run"))
    set_flags(APOLLO_DRY_RUN="1")
    res = c2_commander.deploy_agent(lhost="10.0.0.9", lport=4444, platform="linux")
    assert res["dry_run"] is True


def test_c2_setup_listener_dry_run(set_flags, monkeypatch):
    monkeypatch.setattr(c2_commander, "_run_local",
                        lambda *a, **k: pytest.fail("listener ran during dry-run"))
    monkeypatch.setattr(c2_commander, "_get_msf",
                        lambda: pytest.fail("msf used during dry-run"))
    set_flags(APOLLO_DRY_RUN="1")
    res = c2_commander.setup_listener("10.0.0.9", 4444)
    assert res["dry_run"] is True


def test_c2_run_command_blocked_requires_auth(set_flags, monkeypatch):
    EngagementContext(engagement_id="C", authorized=False).save()
    monkeypatch.setattr(c2_commander, "_run_local",
                        lambda *a, **k: pytest.fail("command ran when blocked"))
    monkeypatch.setattr(c2_commander, "_get_msf",
                        lambda: pytest.fail("msf used when blocked"))
    set_flags(APOLLO_REQUIRE_AUTH="1")
    res = c2_commander.run_command_on_session("1", "whoami")
    assert res["blocked"] is True
