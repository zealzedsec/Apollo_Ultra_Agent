"""Tests for the tamper-evident, hash-chained audit log."""
import json

from apollo_core.logging import GENESIS_HASH, AuditLog, get_audit_log


def test_append_and_chain_links():
    log = get_audit_log(reload=True)
    r1 = log.append("scan", target="10.0.0.1", decision="allow")
    r2 = log.append("exploit", target="10.0.0.2", decision="deny")
    assert r1["seq"] == 1 and r2["seq"] == 2
    assert r1["prev_hash"] == GENESIS_HASH
    assert r2["prev_hash"] == r1["hash"]


def test_verify_clean_chain():
    log = get_audit_log(reload=True)
    for i in range(5):
        log.append("step", target=f"10.0.0.{i}", decision="allow")
    ok, problems = log.verify()
    assert ok is True
    assert problems == []


def test_verify_detects_content_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    log.append("scan", target="10.0.0.1", decision="allow")
    log.append("scan", target="10.0.0.2", decision="allow")

    # Tamper: flip a decision in-place without recomputing the hash.
    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["decision"] = "deny"
    lines[0] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")

    ok, problems = AuditLog(str(path)).verify()
    assert ok is False
    assert any("tampered" in p or "mismatch" in p for p in problems)


def test_verify_detects_deletion(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    for i in range(4):
        log.append("step", target=str(i), decision="allow")

    # Delete the second entry: breaks both the hash link and the sequence.
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")

    ok, problems = AuditLog(str(path)).verify()
    assert ok is False
    assert problems


def test_audit_disabled_is_noop(set_flags, tmp_path):
    set_flags(APOLLO_AUDIT="0")
    log = get_audit_log(reload=True)
    result = log.append("scan", target="x")
    assert result == {}
    assert log.read_all() == []


def test_tail_limits():
    log = get_audit_log(reload=True)
    for i in range(10):
        log.append("step", target=str(i))
    assert len(log.tail(3)) == 3
    assert log.tail(3)[-1]["target"] == "9"
