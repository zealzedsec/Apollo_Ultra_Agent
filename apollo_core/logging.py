#!/usr/bin/env python3
"""
APOLLO Core - Structured logging and a tamper-evident audit trail.

Two things live here:

``get_logger(name)``
    A configured ``logging.Logger`` writing to stderr at the level from config,
    so every module logs consistently instead of calling ``print`` / writing to
    ``sys.stderr`` by hand.

``AuditLog``
    An append-only, hash-chained JSONL record of every security-relevant
    decision (scope checks, authorization grants/denials, active actions). Each
    entry embeds the SHA-256 of the previous entry, so removing or editing any
    line breaks the chain and :meth:`AuditLog.verify` will report exactly where.
    This gives an authorized engagement a defensible, after-the-fact proof of
    what was run, when, by whom, and whether it was permitted.

The chain is advisory integrity (detects tampering by anyone without the full
history); it is not a substitute for shipping logs to append-only remote
storage, and that trade-off is documented in docs/SAFETY.md.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .config import get_config
from .errors import AuditError

GENESIS_HASH = "0" * 64

_LOGGERS: Dict[str, logging.Logger] = {}
_LOG_LOCK = threading.Lock()


def get_logger(name: str = "apollo") -> logging.Logger:
    """Return a configured logger, creating it once per name."""
    with _LOG_LOCK:
        if name in _LOGGERS:
            return _LOGGERS[name]
        logger = logging.getLogger(name)
        level = getattr(logging, get_config().log_level, logging.INFO)
        logger.setLevel(level)
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(
                logging.Formatter("[%(asctime)s] %(name)s %(levelname)s: %(message)s")
            )
            logger.addHandler(handler)
        logger.propagate = False
        _LOGGERS[name] = logger
        return logger


def _canonical(record: Dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _hash_entry(prev_hash: str, record: Dict[str, Any]) -> str:
    payload = prev_hash + _canonical(record)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only, hash-chained JSONL audit log."""

    def __init__(self, path: Optional[str] = None):
        self.path = path or get_config().audit_log_path
        self._lock = threading.Lock()

    # -- internal file locking (best effort, POSIX) -------------------------
    def _open_locked(self, mode: str):
        fh = open(self.path, mode, encoding="utf-8")
        try:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        except (ImportError, OSError):
            pass  # non-POSIX or lock unsupported; in-process lock still holds
        return fh

    def _last_record(self) -> Optional[Dict[str, Any]]:
        if not os.path.exists(self.path):
            return None
        last = None
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
        if not last:
            return None
        try:
            return json.loads(last)
        except json.JSONDecodeError as exc:
            raise AuditError(f"Audit log tail is not valid JSON: {exc}") from exc

    def append(
        self,
        action: str,
        target: str = "",
        decision: str = "allow",
        actor: str = "",
        intrusive: bool = False,
        dry_run: bool = False,
        detail: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Append one chained entry and return it."""
        cfg = get_config()
        if not cfg.audit_enabled:
            return {}
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        actor = actor or os.environ.get("APOLLO_OPERATOR") or os.environ.get("USER") or "unknown"
        with self._lock:
            prev = self._last_record()
            prev_hash = prev["hash"] if prev else GENESIS_HASH
            seq = (prev["seq"] + 1) if prev else 1
            record = {
                "seq": seq,
                "ts": datetime.now(timezone.utc).isoformat(),
                "actor": actor,
                "action": action,
                "target": target,
                "decision": decision,
                "intrusive": bool(intrusive),
                "dry_run": bool(dry_run),
                "detail": detail or {},
                "prev_hash": prev_hash,
            }
            record["hash"] = _hash_entry(prev_hash, record)
            try:
                with self._open_locked("a") as fh:
                    fh.write(json.dumps(record, default=str) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError as exc:
                raise AuditError(f"Failed to append audit entry: {exc}") from exc
            return record

    def read_all(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        out: List[Dict[str, Any]] = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise AuditError(f"Corrupt audit line {i}: {exc}") from exc
        return out

    def tail(self, n: int = 20) -> List[Dict[str, Any]]:
        return self.read_all()[-n:]

    def verify(self) -> Tuple[bool, List[str]]:
        """Recompute the chain. Returns ``(ok, problems)``.

        Detects: broken hash linkage, altered content, and out-of-order or
        missing sequence numbers — i.e. any insertion, deletion, or edit.
        """
        problems: List[str] = []
        prev_hash = GENESIS_HASH
        expected_seq = 1
        for rec in self.read_all():
            stored = rec.get("hash")
            body = {k: v for k, v in rec.items() if k != "hash"}
            if rec.get("prev_hash") != prev_hash:
                problems.append(
                    f"seq {rec.get('seq')}: prev_hash mismatch "
                    f"(expected {prev_hash[:12]}..., got {str(rec.get('prev_hash'))[:12]}...)"
                )
            if _hash_entry(rec.get("prev_hash", ""), body) != stored:
                problems.append(f"seq {rec.get('seq')}: content hash mismatch (tampered)")
            if rec.get("seq") != expected_seq:
                problems.append(
                    f"sequence gap: expected {expected_seq}, got {rec.get('seq')}"
                )
            prev_hash = stored or prev_hash
            expected_seq = (rec.get("seq") or expected_seq) + 1
        return (len(problems) == 0, problems)


_AUDIT: Optional[AuditLog] = None


def get_audit_log(reload: bool = False) -> AuditLog:
    global _AUDIT
    if _AUDIT is None or reload:
        _AUDIT = AuditLog()
    return _AUDIT


def audit(action: str, **kwargs) -> Dict[str, Any]:
    """Convenience wrapper: append one entry to the default audit log."""
    return get_audit_log().append(action, **kwargs)


__all__ = ["get_logger", "AuditLog", "get_audit_log", "audit", "GENESIS_HASH"]
