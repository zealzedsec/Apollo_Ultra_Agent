#!/usr/bin/env python3
"""
APOLLO Core - Shared data models and scoring.

Severity strings used to be compared with an ad-hoc ``SEVERITY_WEIGHTS`` dict
copied into several modules, and CVSS-to-severity mapping did not exist. This
centralizes:

  * a canonical :class:`Severity` ordering,
  * normalization of the many severity spellings tools emit,
  * CVSS v3 band -> severity conversion,
  * a typed :class:`Finding` with a stable dedup key, and
  * a typed :class:`ActionResult` for guarded operations.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return _SEVERITY_WEIGHT[self]

    @property
    def rank(self) -> int:
        """0 = most severe, higher = less severe (handy for sorting)."""
        return _SEVERITY_RANK[self]

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight < other.weight


_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# Many scanners spell severities differently; map them all to the canon.
_SEVERITY_ALIASES = {
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "c": Severity.CRITICAL,
    "high": Severity.HIGH,
    "hi": Severity.HIGH,
    "h": Severity.HIGH,
    "important": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "m": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "low": Severity.LOW,
    "lo": Severity.LOW,
    "l": Severity.LOW,
    "minor": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "information": Severity.INFO,
    "none": Severity.INFO,
    "unknown": Severity.INFO,
    "": Severity.INFO,
}


def normalize_severity(value: Any, default: Severity = Severity.INFO) -> Severity:
    """Coerce any tool's severity label into a canonical :class:`Severity`."""
    if isinstance(value, Severity):
        return value
    if value is None:
        return default
    return _SEVERITY_ALIASES.get(str(value).strip().lower(), default)


def severity_from_cvss(score: Any) -> Severity:
    """Map a CVSS v3.x base score to a qualitative severity band."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return Severity.INFO
    if s >= 9.0:
        return Severity.CRITICAL
    if s >= 7.0:
        return Severity.HIGH
    if s >= 4.0:
        return Severity.MEDIUM
    if s > 0.0:
        return Severity.LOW
    return Severity.INFO


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    """A single normalized security finding, tool-agnostic."""

    name: str
    severity: Severity = Severity.INFO
    host: str = ""
    port: Optional[int] = None
    service: str = ""
    cve_id: str = ""
    cvss: Optional[float] = None
    mitre_id: str = ""
    description: str = ""
    evidence: str = ""
    source: str = ""
    discovered: str = field(default_factory=_now_iso)

    def __post_init__(self) -> None:
        # Accept raw strings/numbers from parsers and normalize on construction.
        sev = self.severity
        if not isinstance(sev, Severity):
            sev = normalize_severity(sev)
        # When severity is unset/info but a CVSS score is present, the numeric
        # score is the more precise signal, so derive the band from it.
        if sev is Severity.INFO and self.cvss is not None:
            sev = severity_from_cvss(self.cvss)
        self.severity = sev

    def dedup_key(self) -> str:
        """Stable identity for de-duplicating findings across tool runs.

        Two findings collide when they describe the same issue on the same
        host/port. CVE id is preferred; otherwise a normalized name is used.
        """
        ident = self.cve_id.strip().upper() or self.name.strip().lower()
        raw = f"{self.host.strip().lower()}|{self.port or ''}|{ident}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()  # noqa: S324 (non-crypto id)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


def risk_score(findings) -> Dict[str, Any]:
    """Aggregate a list of :class:`Finding` (or dicts) into a 0-100 risk score.

    The score is a saturating sum of severity weights so that one critical does
    not get lost among many lows, but a wall of lows still registers.
    """
    counts = {s: 0 for s in Severity}
    weighted = 0
    total = 0
    for f in findings or []:
        sev = f.severity if isinstance(f, Finding) else normalize_severity(
            (f or {}).get("severity")
        )
        counts[sev] += 1
        weighted += sev.weight
        total += 1
    # Saturating curve: 100 * (1 - 0.95 ** weighted) keeps it in [0, 100].
    score = round(100 * (1 - (0.95 ** weighted)), 1) if weighted else 0.0
    if counts[Severity.CRITICAL]:
        label = "critical"
    elif counts[Severity.HIGH]:
        label = "high"
    elif counts[Severity.MEDIUM]:
        label = "medium"
    elif counts[Severity.LOW]:
        label = "low"
    else:
        label = "info"
    return {
        "score": score,
        "label": label,
        "total": total,
        "counts": {s.value: counts[s] for s in Severity},
    }


@dataclass
class ActionResult:
    """Uniform return type for guarded / active operations."""

    action: str
    target: str = ""
    status: str = "ok"          # ok | blocked | dry_run | error
    allowed: bool = True
    dry_run: bool = False
    reason: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


__all__ = [
    "Severity",
    "normalize_severity",
    "severity_from_cvss",
    "Finding",
    "risk_score",
    "ActionResult",
]
