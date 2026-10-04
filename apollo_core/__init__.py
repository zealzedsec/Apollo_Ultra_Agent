#!/usr/bin/env python3
"""
APOLLO Core - the safety, authorization, and engineering foundation shared by
every Apollo engine module.

Importing from here gives you the whole contract::

    from apollo_core import (
        get_config, get_logger, get_audit_log, audit,
        ScopeEngine, EngagementContext, get_engagement,
        preflight, guarded_action,
        Finding, Severity, normalize_severity, severity_from_cvss, risk_score,
    )
"""
from .authorization import Decision, EngagementContext, get_engagement
from .config import ApolloConfig, default_home, get_config
from .errors import (
    ApolloError,
    AuditError,
    AuthorizationError,
    ConfigError,
    SafetyError,
    ScopeError,
)
from .logging import AuditLog, audit, get_audit_log, get_logger
from .models import (
    ActionResult,
    Finding,
    Severity,
    normalize_severity,
    risk_score,
    severity_from_cvss,
)
from .safety import GateResult, guarded_action, preflight
from .scope import (
    ScopeDecision,
    ScopeEngine,
    extract_targets,
    is_safe_shell_token,
    normalize_target,
)

__version__ = "4.1.0"

__all__ = [
    "__version__",
    # errors
    "ApolloError", "ConfigError", "ScopeError", "AuthorizationError",
    "SafetyError", "AuditError",
    # config
    "ApolloConfig", "get_config", "default_home",
    # logging / audit
    "get_logger", "AuditLog", "get_audit_log", "audit",
    # models
    "Severity", "normalize_severity", "severity_from_cvss", "Finding",
    "risk_score", "ActionResult",
    # scope
    "ScopeEngine", "ScopeDecision", "extract_targets", "normalize_target",
    "is_safe_shell_token",
    # authorization
    "EngagementContext", "Decision", "get_engagement",
    # safety
    "preflight", "guarded_action", "GateResult",
]
