#!/usr/bin/env python3
"""
APOLLO Core - Centralized configuration.

Before this module, every engine read ``os.environ`` ad hoc and hard-coded
``~/.config/opencode/apollo-engine`` paths in a dozen places. This resolves all
paths and feature flags in one place, honoring the pre-existing environment
variables (``APOLLO_KB_PATH``, ``APOLLO_ENCRYPTION_KEY``) so nothing regresses,
and layering an optional JSON config file under the Apollo home directory.

Resolution order (lowest to highest precedence):
    1. Built-in defaults
    2. ``<APOLLO_HOME>/apollo.config.json`` (if present)
    3. Environment variables

Feature flags default to the *safe* setting. In particular ``dry_run`` defaults
to the value of ``APOLLO_DRY_RUN`` and the audit log is enabled by default.
"""
import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict

from .errors import ConfigError

_TRUE = {"1", "true", "yes", "on", "y", "t"}
_FALSE = {"0", "false", "no", "off", "n", "f", ""}


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def default_home() -> str:
    return os.environ.get("APOLLO_HOME") or os.path.expanduser(
        "~/.config/opencode/apollo-engine"
    )


@dataclass
class ApolloConfig:
    """Resolved Apollo runtime configuration."""

    home: str
    db_path: str
    audit_log_path: str
    engagement_path: str
    scope_path: str
    reports_dir: str
    cache_dir: str
    active_project_file: str

    # Feature flags / safety posture
    dry_run: bool = False
    audit_enabled: bool = True
    enforce_scope: bool = False
    require_authorization: bool = False
    log_level: str = "INFO"

    # Raw merged values kept for introspection / `config show`
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, home: str = None) -> "ApolloConfig":
        home = home or default_home()
        file_cfg: Dict[str, Any] = {}
        cfg_file = os.path.join(home, "apollo.config.json")
        if os.path.exists(cfg_file):
            try:
                with open(cfg_file, "r", encoding="utf-8") as fh:
                    file_cfg = json.load(fh) or {}
            except (OSError, json.JSONDecodeError) as exc:
                raise ConfigError(f"Failed to read config {cfg_file}: {exc}") from exc

        def pick(env_key: str, file_key: str, fallback: Any) -> Any:
            if env_key in os.environ:
                return os.environ[env_key]
            if file_key in file_cfg:
                return file_cfg[file_key]
            return fallback

        db_path = pick("APOLLO_KB_PATH", "db_path", os.path.join(home, "apollo.db"))
        audit_log_path = pick(
            "APOLLO_AUDIT_LOG", "audit_log_path", os.path.join(home, "audit.log.jsonl")
        )
        engagement_path = pick(
            "APOLLO_ENGAGEMENT_FILE", "engagement_path",
            os.path.join(home, "engagement.json"),
        )
        scope_path = pick(
            "APOLLO_SCOPE_FILE", "scope_path", os.path.join(home, "scope.txt")
        )
        reports_dir = pick("APOLLO_REPORTS_DIR", "reports_dir", os.path.join(home, "reports"))
        cache_dir = pick("APOLLO_CACHE_DIR", "cache_dir", os.path.join(home, "cache"))
        active_project_file = pick(
            "APOLLO_ACTIVE_PROJECT_FILE", "active_project_file",
            os.path.join(home, ".active_project"),
        )

        cfg = cls(
            home=home,
            db_path=db_path,
            audit_log_path=audit_log_path,
            engagement_path=engagement_path,
            scope_path=scope_path,
            reports_dir=reports_dir,
            cache_dir=cache_dir,
            active_project_file=active_project_file,
            dry_run=_as_bool(pick("APOLLO_DRY_RUN", "dry_run", False)),
            audit_enabled=_as_bool(pick("APOLLO_AUDIT", "audit_enabled", True), True),
            enforce_scope=_as_bool(pick("APOLLO_ENFORCE_SCOPE", "enforce_scope", False)),
            require_authorization=_as_bool(
                pick("APOLLO_REQUIRE_AUTH", "require_authorization", False)
            ),
            log_level=str(pick("APOLLO_LOG_LEVEL", "log_level", "INFO")).upper(),
        )
        cfg.raw = {**file_cfg}
        return cfg

    def ensure_dirs(self) -> None:
        """Create the directories Apollo writes to (idempotent)."""
        for path in (
            self.home,
            self.reports_dir,
            self.cache_dir,
            os.path.dirname(self.db_path),
            os.path.dirname(self.audit_log_path),
        ):
            if path:
                os.makedirs(path, exist_ok=True)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("raw", None)
        return d


_CONFIG: ApolloConfig = None


def get_config(reload: bool = False, home: str = None) -> ApolloConfig:
    """Return the process-wide config, loading it on first use.

    Pass ``reload=True`` (used by tests) to re-read the environment and file.
    """
    global _CONFIG
    if _CONFIG is None or reload or home is not None:
        _CONFIG = ApolloConfig.load(home=home)
    return _CONFIG


__all__ = ["ApolloConfig", "get_config", "default_home"]
