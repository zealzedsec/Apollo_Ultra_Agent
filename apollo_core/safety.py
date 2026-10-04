#!/usr/bin/env python3
"""
APOLLO Core - Safety gate.

The single entry point every active operation should pass through before it
touches a target. It composes the other core pieces into one decision:

    scope + engagement authorization + dry-run posture  ->  GateResult
    (and every decision is written to the tamper-evident audit log)

Two ways to use it:

  * :func:`preflight` - imperative, returns a :class:`GateResult`. Used by the
    orchestrator before building/running a tool command.
  * :func:`guarded_action` - a decorator for functions that perform an active
    action, so the gate is enforced automatically and a blocked/dry-run call
    short-circuits with an :class:`~apollo_core.models.ActionResult` instead of
    executing.

``dry_run`` is honored globally (``APOLLO_DRY_RUN``) and per call. A blocked
action raises :class:`~apollo_core.errors.SafetyError`; the decorator can be
told to return a result object instead of raising.
"""
from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Callable, Optional

from .authorization import get_engagement
from .config import get_config
from .errors import SafetyError
from .logging import audit, get_logger
from .models import ActionResult

_log = get_logger("apollo.safety")


@dataclass
class GateResult:
    allowed: bool
    dry_run: bool
    reason: str
    action: str
    target: str = ""
    intrusive: bool = False

    def __bool__(self) -> bool:
        return self.allowed


def preflight(
    action: str,
    target: str = "",
    intrusive: bool = False,
    actor: str = "",
    detail: Optional[dict] = None,
) -> GateResult:
    """Evaluate the gate for one action and record the decision.

    Never executes anything itself; the caller inspects the result.
    """
    cfg = get_config()
    engagement = get_engagement()
    decision = engagement.authorize(action, target=target, intrusive=intrusive)
    dry = cfg.dry_run
    result = GateResult(
        allowed=decision.allowed,
        dry_run=dry,
        reason=decision.reason,
        action=action,
        target=target,
        intrusive=intrusive,
    )
    verdict = "allow" if decision.allowed else "deny"
    if decision.allowed and dry:
        verdict = "dry_run"
    audit(
        action,
        target=target,
        decision=verdict,
        actor=actor or engagement.operator,
        intrusive=intrusive,
        dry_run=dry,
        detail={"reason": decision.reason, **(detail or {})},
    )
    if not decision.allowed:
        _log.warning("BLOCKED %s against %s: %s", action, target, decision.reason)
    return result


def guarded_action(
    action: Optional[str] = None,
    target_arg: str = "target",
    intrusive: bool = False,
    raise_on_block: bool = True,
) -> Callable:
    """Decorator enforcing the safety gate around an active function.

    The target is read from the ``target_arg`` keyword (falling back to the
    first positional argument). On block: raise :class:`SafetyError` (default) or
    return a blocked :class:`ActionResult`. On dry-run: skip the call and return
    a dry-run :class:`ActionResult`.
    """

    def decorator(func: Callable) -> Callable:
        act = action or func.__name__

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            target = kwargs.get(target_arg)
            if target is None and args:
                target = args[0]
            target = str(target) if target is not None else ""
            gate = preflight(act, target=target, intrusive=intrusive)
            if not gate.allowed:
                if raise_on_block:
                    raise SafetyError(f"{act} blocked: {gate.reason}")
                return ActionResult(
                    action=act, target=target, status="blocked",
                    allowed=False, reason=gate.reason,
                )
            if gate.dry_run:
                _log.info("DRY-RUN %s against %s (not executed)", act, target)
                return ActionResult(
                    action=act, target=target, status="dry_run",
                    allowed=True, dry_run=True,
                    reason="dry-run: action not executed",
                )
            return func(*args, **kwargs)

        wrapper.__apollo_guarded__ = True  # type: ignore[attr-defined]
        return wrapper

    return decorator


__all__ = ["GateResult", "preflight", "guarded_action", "SafetyError", "ActionResult"]
