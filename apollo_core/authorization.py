#!/usr/bin/env python3
"""
APOLLO Core - Engagement authorization (rules of engagement).

An authorized assessment has boundaries: which targets, during which window, run
by whom, and whether intrusive/exploitative actions are permitted at all. This
module turns those boundaries into a machine-checked :class:`EngagementContext`
loaded from ``engagement.json`` (or environment overrides), so the framework can
refuse to act outside them instead of trusting the operator to remember.

Example ``engagement.json``::

    {
      "engagement_id": "ACME-2026-Q1",
      "operator": "jane.doe",
      "client": "ACME Corp",
      "authorized": true,
      "scope_allow": ["10.0.0.0/24", "*.acme-lab.example"],
      "scope_deny": ["10.0.0.1"],
      "window_start": "2026-10-01T00:00:00Z",
      "window_end": "2026-10-31T23:59:59Z",
      "intrusive_allowed": true,
      "notes": "Internal network pentest, production DB excluded."
    }

Nothing here grants new capability; it only ever *withholds* it.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from .config import get_config
from .errors import ConfigError
from .scope import ScopeDecision, ScopeEngine


def _parse_dt(value) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        s = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


@dataclass
class Decision:
    allowed: bool
    reason: str

    def __bool__(self) -> bool:
        return self.allowed


@dataclass
class EngagementContext:
    engagement_id: str = ""
    operator: str = ""
    client: str = ""
    authorized: bool = False
    scope_allow: List[str] = field(default_factory=list)
    scope_deny: List[str] = field(default_factory=list)
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    intrusive_allowed: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        self._scope = ScopeEngine(self.scope_allow, self.scope_deny)

    @property
    def scope(self) -> ScopeEngine:
        return self._scope

    def is_within_window(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        if self.window_start and now < self.window_start:
            return False
        if self.window_end and now > self.window_end:
            return False
        return True

    # -- the core gate ------------------------------------------------------
    def authorize(
        self, action: str, target: str = "", intrusive: bool = False,
        now: Optional[datetime] = None,
    ) -> Decision:
        """Decide whether ``action`` against ``target`` is permitted.

        Enforcement depends on config flags:
          * ``require_authorization`` gates on an authorized, in-window
            engagement (and on ``intrusive_allowed`` for intrusive actions).
          * ``enforce_scope`` gates ``target`` against the engagement scope.
        When both flags are off the framework runs unenforced (dev mode) but the
        decision string says so, and the caller still records it to the audit
        log.
        """
        cfg = get_config()

        if cfg.enforce_scope and target:
            sd: ScopeDecision = self._scope.check_target(target)
            if not sd.allowed:
                return Decision(False, f"scope: {sd.reason}")

        if cfg.require_authorization:
            if not self.authorized:
                return Decision(False, "engagement not marked authorized")
            if not self.is_within_window(now):
                return Decision(False, "outside authorized engagement window")
            if intrusive and not self.intrusive_allowed:
                return Decision(
                    False, f"intrusive action '{action}' not permitted by engagement"
                )
            return Decision(True, f"authorized by engagement {self.engagement_id or '(unnamed)'}")

        if cfg.enforce_scope and target:
            return Decision(True, "in scope (authorization not enforced)")
        return Decision(True, "unenforced (no authorization/scope gate configured)")

    def to_dict(self) -> dict:
        return {
            "engagement_id": self.engagement_id,
            "operator": self.operator,
            "client": self.client,
            "authorized": self.authorized,
            "scope_allow": self.scope_allow,
            "scope_deny": self.scope_deny,
            "window_start": self.window_start.isoformat() if self.window_start else None,
            "window_end": self.window_end.isoformat() if self.window_end else None,
            "intrusive_allowed": self.intrusive_allowed,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EngagementContext":
        return cls(
            engagement_id=data.get("engagement_id", ""),
            operator=data.get("operator", "") or os.environ.get("APOLLO_OPERATOR", ""),
            client=data.get("client", ""),
            authorized=bool(data.get("authorized", False)),
            scope_allow=list(data.get("scope_allow", []) or []),
            scope_deny=list(data.get("scope_deny", []) or []),
            window_start=_parse_dt(data.get("window_start")),
            window_end=_parse_dt(data.get("window_end")),
            intrusive_allowed=bool(data.get("intrusive_allowed", False)),
            notes=data.get("notes", ""),
        )

    @classmethod
    def load(cls, path: Optional[str] = None) -> "EngagementContext":
        cfg = get_config()
        path = path or cfg.engagement_path
        data: dict = {}
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh) or {}
            except (OSError, json.JSONDecodeError) as exc:
                raise ConfigError(f"Invalid engagement file {path}: {exc}") from exc
        # If a scope.txt exists but the manifest has no allow-list, fold it in.
        if not data.get("scope_allow") and cfg.scope_path and os.path.exists(cfg.scope_path):
            from .scope import load_scope

            data = {**data, "scope_allow": load_scope(cfg.scope_path)}
        return cls.from_dict(data)

    def save(self, path: Optional[str] = None) -> str:
        path = path or get_config().engagement_path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)
        return path


_ENGAGEMENT: Optional[EngagementContext] = None


def get_engagement(reload: bool = False) -> EngagementContext:
    global _ENGAGEMENT
    if _ENGAGEMENT is None or reload:
        _ENGAGEMENT = EngagementContext.load()
    return _ENGAGEMENT


__all__ = ["EngagementContext", "Decision", "get_engagement"]
