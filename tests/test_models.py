"""Tests for apollo_core.models - severity normalization, scoring, findings."""
from apollo_core.models import (
    Finding,
    Severity,
    normalize_severity,
    risk_score,
    severity_from_cvss,
)


def test_normalize_severity_aliases():
    assert normalize_severity("CRITICAL") is Severity.CRITICAL
    assert normalize_severity("Crit") is Severity.CRITICAL
    assert normalize_severity("hi") is Severity.HIGH
    assert normalize_severity("moderate") is Severity.MEDIUM
    assert normalize_severity("informational") is Severity.INFO
    assert normalize_severity(None) is Severity.INFO
    assert normalize_severity("nonsense") is Severity.INFO


def test_severity_ordering():
    assert Severity.CRITICAL.weight > Severity.HIGH.weight > Severity.LOW.weight
    assert Severity.LOW < Severity.CRITICAL
    ordered = sorted([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM],
                     key=lambda s: s.rank)
    assert ordered[0] is Severity.CRITICAL


def test_severity_from_cvss_bands():
    assert severity_from_cvss(9.8) is Severity.CRITICAL
    assert severity_from_cvss(7.5) is Severity.HIGH
    assert severity_from_cvss(5.0) is Severity.MEDIUM
    assert severity_from_cvss(0.1) is Severity.LOW
    assert severity_from_cvss(0.0) is Severity.INFO
    assert severity_from_cvss("not-a-number") is Severity.INFO


def test_finding_infers_severity_from_cvss():
    f = Finding(name="CVE thing", cvss=9.1)
    assert f.severity is Severity.CRITICAL


def test_finding_dedup_key_stability():
    a = Finding(name="SQLi", host="10.0.0.1", port=443, cve_id="CVE-2024-1")
    b = Finding(name="different text", host="10.0.0.1", port=443, cve_id="cve-2024-1")
    # Same CVE + host + port => same identity regardless of name/case.
    assert a.dedup_key() == b.dedup_key()
    c = Finding(name="SQLi", host="10.0.0.2", port=443, cve_id="CVE-2024-1")
    assert a.dedup_key() != c.dedup_key()


def test_risk_score_prioritizes_critical():
    rs = risk_score([Finding("a", severity="low"), Finding("b", severity="critical")])
    assert rs["label"] == "critical"
    assert 0 < rs["score"] <= 100
    assert rs["counts"]["critical"] == 1


def test_risk_score_empty():
    rs = risk_score([])
    assert rs["score"] == 0.0
    assert rs["label"] == "info"
    assert rs["total"] == 0


def test_risk_score_accepts_dicts():
    rs = risk_score([{"severity": "high"}, {"severity": "HIGH"}])
    assert rs["counts"]["high"] == 2
    assert rs["label"] == "high"
