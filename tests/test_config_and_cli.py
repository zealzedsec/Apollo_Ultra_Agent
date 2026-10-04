"""Tests for config resolution and the unified `apollo` CLI."""
import json

from apollo_core.cli import main
from apollo_core.config import get_config


def test_config_defaults_under_home(isolated_home):
    cfg = get_config(reload=True)
    assert str(isolated_home) in cfg.db_path
    assert str(isolated_home) in cfg.audit_log_path
    assert cfg.audit_enabled is True
    assert cfg.dry_run is False


def test_config_bool_parsing(set_flags):
    set_flags(APOLLO_DRY_RUN="yes", APOLLO_ENFORCE_SCOPE="0")
    cfg = get_config()
    assert cfg.dry_run is True
    assert cfg.enforce_scope is False


def test_config_file_overrides_defaults(isolated_home):
    cfg_file = isolated_home / "apollo.config.json"
    cfg_file.write_text(json.dumps({"log_level": "DEBUG", "enforce_scope": True}))
    cfg = get_config(reload=True)
    assert cfg.log_level == "DEBUG"
    assert cfg.enforce_scope is True


def test_env_beats_config_file(isolated_home, monkeypatch):
    (isolated_home / "apollo.config.json").write_text(json.dumps({"log_level": "DEBUG"}))
    monkeypatch.setenv("APOLLO_LOG_LEVEL", "WARNING")
    cfg = get_config(reload=True)
    assert cfg.log_level == "WARNING"


def test_cli_version(capsys):
    assert main(["version"]) == 0
    out = capsys.readouterr().out
    assert "apollo_core" in out


def test_cli_selftest(capsys):
    assert main(["selftest"]) == 0
    assert "ok" in capsys.readouterr().out


def test_cli_scope_check_exit_codes(capsys):
    assert main(["scope", "check", "8.8.8.8"]) == 0  # unenforced -> allowed


def test_cli_engagement_init_and_show(capsys):
    rc = main(["engagement", "init", "--id", "CLI-1", "--allow", "10.0.0.0/24",
               "--operator", "jane", "--authorized"])
    assert rc == 0
    capsys.readouterr()
    assert main(["engagement", "show"]) == 0
    out = capsys.readouterr().out
    assert "CLI-1" in out


def test_cli_audit_verify(capsys):
    from apollo_core.logging import get_audit_log
    get_audit_log(reload=True).append("scan", target="10.0.0.1")
    assert main(["audit", "verify"]) == 0
    assert '"ok": true' in capsys.readouterr().out.lower()
