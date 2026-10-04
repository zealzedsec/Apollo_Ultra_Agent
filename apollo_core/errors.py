#!/usr/bin/env python3
"""
APOLLO Core - Exception hierarchy.

A single, shared error taxonomy so every engine module can raise and catch
Apollo-specific failures consistently instead of leaking bare ``Exception``s.
"""


class ApolloError(Exception):
    """Base class for every Apollo framework error."""


class ConfigError(ApolloError):
    """Raised when configuration is missing, malformed, or inconsistent."""


class ScopeError(ApolloError):
    """Raised when a target cannot be parsed or validated against scope."""


class AuthorizationError(ApolloError):
    """Raised when an action is not authorized by the engagement context."""


class SafetyError(ApolloError):
    """Raised when a guarded action is blocked by the safety gate."""


class AuditError(ApolloError):
    """Raised when the tamper-evident audit log fails to append or verify."""


__all__ = [
    "ApolloError",
    "ConfigError",
    "ScopeError",
    "AuthorizationError",
    "SafetyError",
    "AuditError",
]
