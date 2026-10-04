#!/usr/bin/env python3
"""
APOLLO Core - Scope engine (authorization boundary for targets).

This replaces the original ``scope_validator`` matching logic, which had several
correctness bugs that are dangerous in a tool that attacks whatever it is
pointed at:

  * ``ip_pattern.match`` is anchored at the start, so ``10.0.0.1extra`` and
    embedded IPs were mis-handled; octets like ``999.1.1.1`` were accepted.
  * wildcard ``*.example.com`` used ``target.endswith("example.com")`` with no
    dot boundary, so ``notexample.com`` and ``evil-example.com`` matched.
  * IPv6 was unsupported, and there was no concept of an explicit *deny* list.

The engine here supports allow and deny rules (deny always wins), IPv4/IPv6
addresses, CIDR, ranges, exact hostnames, boundary-correct wildcard domains, and
URLs. It also provides :func:`is_safe_shell_token`, used before a target is ever
interpolated into a shell command.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple
from urllib.parse import urlparse

# Validated IPv4 (0-255 octets) and a conservative hostname matcher.
_IPV4 = re.compile(
    r"^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$"
)
_IPV4_SEARCH = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"
)
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
# Trailing labels that indicate a local file/path, not a target host, so
# ``-oN out.txt`` and friends are not mistaken for in-scope domains.
_FILE_EXTS = {
    "txt", "json", "xml", "html", "htm", "log", "csv", "md", "py", "sh",
    "conf", "cfg", "yaml", "yml", "out", "tmp", "pcap", "db", "pem", "key",
    "crt", "cer", "pdf", "zip", "gz", "tar", "ini", "bak", "lst",
}
# Characters that must never reach a shell when a target is interpolated.
_SHELL_META = re.compile(r"[;&|`$><(){}\[\]!\\\"'\s*?~\n\r]")


class RuleType(str, Enum):
    CIDR = "cidr"
    RANGE = "range"
    IP = "ip"
    WILDCARD = "wildcard"
    HOST = "host"


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    matched: str = ""
    rule_type: str = ""

    def __bool__(self) -> bool:
        return self.allowed


def is_safe_shell_token(token: str) -> bool:
    """True if ``token`` is safe to interpolate into a shell command string."""
    if not token or len(token) > 255:
        return False
    return _SHELL_META.search(token) is None


def normalize_target(target: str) -> str:
    """Strip a URL/scheme/port down to a bare host or IP for scope matching."""
    target = (target or "").strip()
    if not target:
        return ""
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or ""
        return host
    # bare host:port (but not IPv6 which has many colons)
    if target.count(":") == 1:
        host, _, _ = target.partition(":")
        return host
    return target


class ScopeEntry:
    """A single parsed scope rule."""

    def __init__(self, raw: str):
        self.raw = raw.strip()
        self.rule_type: Optional[RuleType] = None
        self._net = None
        self._range: Optional[Tuple] = None
        self._value: str = ""
        self._parse()

    def _parse(self) -> None:
        entry = self.raw
        if not entry or entry.startswith("#"):
            return
        if "/" in entry:
            try:
                self._net = ipaddress.ip_network(entry, strict=False)
                self.rule_type = RuleType.CIDR
                return
            except ValueError:
                pass
        if entry.count("-") == 1 and ("." in entry or ":" in entry):
            start_s, _, end_s = entry.partition("-")
            try:
                start = ipaddress.ip_address(start_s.strip())
                end = ipaddress.ip_address(end_s.strip())
                if start.version == end.version:
                    self._range = (start, end)
                    self.rule_type = RuleType.RANGE
                    return
            except ValueError:
                pass
        if entry.startswith("*."):
            self._value = entry[2:].lower()
            self.rule_type = RuleType.WILDCARD
            return
        try:
            ipaddress.ip_address(entry)
            self._value = entry
            self.rule_type = RuleType.IP
            return
        except ValueError:
            pass
        self._value = entry.lower()
        self.rule_type = RuleType.HOST

    def matches(self, target: str) -> Tuple[bool, str]:
        if self.rule_type is None:
            return False, ""
        host = normalize_target(target)
        if self.rule_type in (RuleType.CIDR, RuleType.RANGE, RuleType.IP):
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                return False, ""
            if self.rule_type == RuleType.CIDR and ip in self._net:
                return True, f"{host} in {self.raw}"
            if self.rule_type == RuleType.RANGE:
                lo, hi = self._range
                if lo.version == ip.version and lo <= ip <= hi:
                    return True, f"{host} in range {self.raw}"
            if self.rule_type == RuleType.IP:
                try:
                    if ip == ipaddress.ip_address(self._value):
                        return True, f"{host} matches {self.raw}"
                except ValueError:
                    return False, ""
            return False, ""
        hl = host.lower()
        if self.rule_type == RuleType.WILDCARD:
            # boundary-correct: apex and any subdomain, never a suffix collision
            if hl == self._value or hl.endswith("." + self._value):
                return True, f"{host} matches wildcard {self.raw}"
            return False, ""
        if self.rule_type == RuleType.HOST and hl == self._value:
            return True, f"{host} matches {self.raw}"
        return False, ""


class ScopeEngine:
    """Allow/deny scope evaluator. Deny rules always take precedence."""

    def __init__(self, allow: List[str] = None, deny: List[str] = None):
        self.allow = [ScopeEntry(e) for e in (allow or []) if e and not e.strip().startswith("#")]
        self.deny = [ScopeEntry(e) for e in (deny or []) if e and not e.strip().startswith("#")]

    @property
    def configured(self) -> bool:
        return bool(self.allow or self.deny)

    def check_target(self, target: str) -> ScopeDecision:
        host = normalize_target(target)
        if not host:
            return ScopeDecision(False, f"{target!r} is not a resolvable target")
        for entry in self.deny:
            ok, msg = entry.matches(host)
            if ok:
                return ScopeDecision(False, f"DENY: {msg}", entry.raw, entry.rule_type.value)
        if not self.allow:
            # No allow-list configured: permissive, but say so explicitly.
            return ScopeDecision(True, "No allow-list defined - all non-denied targets allowed")
        for entry in self.allow:
            ok, msg = entry.matches(host)
            if ok:
                return ScopeDecision(True, msg, entry.raw, entry.rule_type.value)
        return ScopeDecision(False, f"{host} NOT in scope")

    @classmethod
    def from_file(cls, scope_file: str) -> "ScopeEngine":
        allow, deny = [], []
        if scope_file:
            try:
                with open(scope_file, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("!") or line.lower().startswith("deny "):
                            deny.append(line.lstrip("!").split(" ", 1)[-1].strip())
                        else:
                            allow.append(line)
            except OSError:
                pass
        return cls(allow=allow, deny=deny)


def extract_targets(command: str) -> List[str]:
    """Pull candidate targets (IPs, domains, URLs) out of a command string."""
    found: List[str] = []
    for word in (command or "").split():
        w = word.strip().strip(",")
        if w.startswith("-"):
            continue
        if "://" in w:
            host = normalize_target(w)
            if host:
                found.append(host)
            continue
        m = _IPV4_SEARCH.search(w)
        if m:
            found.append(m.group(0))
            continue
        if _HOSTNAME.match(w) and not w.startswith("/") and "." in w:
            if w.rsplit(".", 1)[-1].lower() in _FILE_EXTS:
                continue  # looks like a filename, not a target host
            found.append(w)
    # de-dupe preserving order
    seen, out = set(), []
    for t in found:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


# --------------------------------------------------------------------------
# Backwards-compatible shims for the original scope_validator.py API.
# --------------------------------------------------------------------------
def load_scope(scope_file: str) -> List[str]:
    import os

    if not scope_file or not os.path.exists(scope_file):
        return []
    entries = []
    with open(scope_file, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                entries.append(line)
    return entries


def target_in_scope(target: str, scope_entries: List[str]) -> Tuple[bool, str]:
    engine = ScopeEngine(allow=scope_entries)
    decision = engine.check_target(target)
    return decision.allowed, decision.reason


def check_command(command: str, scope_file: str) -> Tuple[str, str]:
    entries = load_scope(scope_file)
    if not entries:
        return "OK", "No scope file defined - all targets allowed"
    engine = ScopeEngine(allow=entries)
    for target in extract_targets(command):
        decision = engine.check_target(target)
        if not decision.allowed:
            return "VIOLATION", decision.reason
    return "OK", "All targets in scope"


__all__ = [
    "ScopeEngine",
    "ScopeEntry",
    "ScopeDecision",
    "RuleType",
    "extract_targets",
    "normalize_target",
    "is_safe_shell_token",
    "load_scope",
    "target_in_scope",
    "check_command",
]
