"""Tests for apollo_core.scope - including regressions for the original bugs."""

from apollo_core.scope import (
    ScopeEngine,
    check_command,
    extract_targets,
    is_safe_shell_token,
    normalize_target,
    target_in_scope,
)


def test_cidr_match():
    eng = ScopeEngine(allow=["10.0.0.0/24"])
    assert eng.check_target("10.0.0.50").allowed
    assert not eng.check_target("10.0.1.50").allowed


def test_exact_ip_and_octet_validation():
    eng = ScopeEngine(allow=["192.0.2.10"])
    assert eng.check_target("192.0.2.10").allowed
    # 999 is not a valid octet; must not be treated as an in-scope IP.
    assert not eng.check_target("999.0.2.10").allowed


def test_ipv4_range():
    eng = ScopeEngine(allow=["10.0.0.5-10.0.0.10"])
    assert eng.check_target("10.0.0.7").allowed
    assert not eng.check_target("10.0.0.11").allowed


def test_ipv6_cidr():
    eng = ScopeEngine(allow=["2001:db8::/32"])
    assert eng.check_target("2001:db8::1").allowed
    assert not eng.check_target("2001:dead::1").allowed


def test_wildcard_apex_and_subdomain():
    eng = ScopeEngine(allow=["*.example.com"])
    assert eng.check_target("example.com").allowed
    assert eng.check_target("api.example.com").allowed
    assert eng.check_target("a.b.example.com").allowed


def test_wildcard_boundary_regression():
    """Original bug: endswith('example.com') matched notexample.com."""
    eng = ScopeEngine(allow=["*.example.com"])
    assert not eng.check_target("notexample.com").allowed
    assert not eng.check_target("evil-example.com").allowed
    assert not eng.check_target("example.com.evil.net").allowed


def test_deny_precedence():
    eng = ScopeEngine(allow=["10.0.0.0/24"], deny=["10.0.0.1"])
    assert not eng.check_target("10.0.0.1").allowed
    assert eng.check_target("10.0.0.2").allowed


def test_no_allowlist_is_permissive_but_deny_still_applies():
    eng = ScopeEngine(deny=["10.0.0.1"])
    assert eng.check_target("8.8.8.8").allowed
    assert not eng.check_target("10.0.0.1").allowed


def test_url_normalization():
    assert normalize_target("https://api.example.com:8443/v1") == "api.example.com"
    assert normalize_target("10.0.0.5:8080") == "10.0.0.5"
    eng = ScopeEngine(allow=["*.example.com"])
    assert eng.check_target("https://api.example.com/login").allowed


def test_extract_targets():
    cmd = "nmap -sV 10.0.0.5 api.example.com https://x.example.com -oN out.txt"
    targets = extract_targets(cmd)
    assert "10.0.0.5" in targets
    assert "api.example.com" in targets
    assert "x.example.com" in targets
    assert "out.txt" not in targets  # flags/files excluded


def test_is_safe_shell_token():
    assert is_safe_shell_token("10.0.0.5")
    assert is_safe_shell_token("api.example.com")
    assert is_safe_shell_token("https://example.com/path")
    assert not is_safe_shell_token("10.0.0.5; rm -rf /")
    assert not is_safe_shell_token("$(whoami)")
    assert not is_safe_shell_token("a`b`")
    assert not is_safe_shell_token("x && y")


def test_backward_compatible_check_command(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("10.0.0.0/24\n*.example.com\n")
    status, _ = check_command("nmap 10.0.0.9", str(scope_file))
    assert status == "OK"
    status, _ = check_command("nmap 8.8.8.8", str(scope_file))
    assert status == "VIOLATION"


def test_backward_compatible_no_scope_file():
    status, msg = check_command("nmap 8.8.8.8", "")
    assert status == "OK"
    assert "No scope file" in msg


def test_target_in_scope_tuple_contract():
    ok, msg = target_in_scope("10.0.0.5", ["10.0.0.0/24"])
    assert ok is True and "10.0.0.5" in msg
