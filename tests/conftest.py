"""Shared pytest fixtures for Apollo Ultra.

Every test runs against an isolated ``APOLLO_HOME`` under a temp directory so no
test ever reads or writes the operator's real config, database, or audit log.
The core singletons (config / engagement / audit) are reset before each test.
"""
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Env flags that influence the safety posture; cleared before each test.
_FLAG_VARS = [
    "APOLLO_DRY_RUN", "APOLLO_AUDIT", "APOLLO_ENFORCE_SCOPE",
    "APOLLO_REQUIRE_AUTH", "APOLLO_LOG_LEVEL", "APOLLO_OPERATOR",
    "APOLLO_KB_PATH", "APOLLO_AUDIT_LOG", "APOLLO_ENGAGEMENT_FILE",
    "APOLLO_SCOPE_FILE",
]


def reload_core():
    """Re-read config and rebuild the engagement/audit singletons."""
    from apollo_core import authorization, config
    from apollo_core import logging as alog

    config.get_config(reload=True)
    authorization.get_engagement(reload=True)
    alog.get_audit_log(reload=True)


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("APOLLO_HOME", str(tmp_path))
    for var in _FLAG_VARS:
        monkeypatch.delenv(var, raising=False)
    reload_core()
    yield tmp_path


@pytest.fixture
def set_flags(monkeypatch):
    """Return a setter that applies env flags and reloads core singletons."""

    def _apply(**flags):
        for key, value in flags.items():
            monkeypatch.setenv(key, str(value))
        reload_core()

    return _apply
