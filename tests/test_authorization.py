"""Tests for engagement authorization (rules of engagement)."""
from datetime import datetime, timedelta, timezone

from apollo_core.authorization import EngagementContext, get_engagement


def _mk(**kw):
    base = dict(
        engagement_id="T-1", operator="tester", authorized=True,
        scope_allow=["10.0.0.0/24"], intrusive_allowed=False,
    )
    base.update(kw)
    return EngagementContext(**base)


def test_unenforced_mode_allows_everything(set_flags):
    set_flags(APOLLO_ENFORCE_SCOPE="0", APOLLO_REQUIRE_AUTH="0")
    ctx = _mk()
    d = ctx.authorize("scan", target="8.8.8.8")
    assert d.allowed
    assert "unenforced" in d.reason


def test_enforce_scope_blocks_out_of_scope(set_flags):
    set_flags(APOLLO_ENFORCE_SCOPE="1")
    ctx = _mk()
    assert ctx.authorize("scan", target="10.0.0.5").allowed
    blocked = ctx.authorize("scan", target="8.8.8.8")
    assert not blocked.allowed
    assert "scope" in blocked.reason


def test_require_auth_blocks_unauthorized(set_flags):
    set_flags(APOLLO_REQUIRE_AUTH="1")
    ctx = _mk(authorized=False)
    d = ctx.authorize("scan", target="10.0.0.5")
    assert not d.allowed
    assert "not marked authorized" in d.reason


def test_require_auth_intrusive_gating(set_flags):
    set_flags(APOLLO_REQUIRE_AUTH="1")
    ctx = _mk(authorized=True, intrusive_allowed=False)
    assert ctx.authorize("recon", target="10.0.0.5", intrusive=False).allowed
    blocked = ctx.authorize("exploit", target="10.0.0.5", intrusive=True)
    assert not blocked.allowed
    assert "intrusive" in blocked.reason

    ctx2 = _mk(authorized=True, intrusive_allowed=True)
    assert ctx2.authorize("exploit", target="10.0.0.5", intrusive=True).allowed


def test_window_enforcement(set_flags):
    set_flags(APOLLO_REQUIRE_AUTH="1")
    past = datetime.now(timezone.utc) - timedelta(days=2)
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    ctx = _mk(window_start=past, window_end=yesterday)
    d = ctx.authorize("scan", target="10.0.0.5")
    assert not d.allowed
    assert "window" in d.reason


def test_save_and_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("APOLLO_HOME", str(tmp_path))
    from apollo_core import config
    config.get_config(reload=True)
    ctx = _mk(engagement_id="ROUNDTRIP", scope_deny=["10.0.0.1"])
    path = ctx.save()
    loaded = get_engagement(reload=True)
    assert loaded.engagement_id == "ROUNDTRIP"
    assert "10.0.0.1" in loaded.scope_deny
    assert path.endswith("engagement.json")
