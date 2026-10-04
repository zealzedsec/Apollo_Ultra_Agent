#!/usr/bin/env python3
"""
APOLLO Scope Validator - Validate targets against a scope file.

As of v4.1 the matching logic lives in :mod:`apollo_core.scope`, which fixes
several correctness bugs in the original matcher (unanchored IP regex, missing
octet validation, and wildcard suffix collisions such as ``notexample.com``
matching ``*.example.com``) and adds IPv6, CIDR, ranges, deny rules, and URL
normalization. This module keeps its original CLI and function contract so
existing callers and the ``opencode.jsonc`` hook keep working unchanged.

Usage:
    scope_validator.py <command> <scope_file>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from apollo_core.scope import load_scope, target_in_scope, check_command
except Exception:  # pragma: no cover - standalone fallback if core is unavailable
    import ipaddress

    def load_scope(scope_file):
        if not scope_file or not os.path.exists(scope_file):
            return []
        entries = []
        with open(scope_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.append(line)
        return entries

    def target_in_scope(target, scope_entries):
        target = (target or "").strip()
        for entry in scope_entries:
            entry = entry.strip()
            try:
                if "/" in entry:
                    net = ipaddress.ip_network(entry, strict=False)
                    try:
                        if ipaddress.ip_address(target) in net:
                            return True, f"{target} in {entry}"
                    except ValueError:
                        continue
                elif entry.startswith("*."):
                    dom = entry[2:].lower()
                    tl = target.lower()
                    if tl == dom or tl.endswith("." + dom):
                        return True, f"{target} matches wildcard {entry}"
                elif target.lower() == entry.lower():
                    return True, f"{target} matches {entry}"
            except ValueError:
                continue
        return False, f"{target} NOT in scope"

    def check_command(command, scope_file):
        entries = load_scope(scope_file)
        if not entries:
            return "OK", "No scope file defined - all targets allowed"
        import re

        ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        for word in command.split():
            if ip_re.match(word) or ("." in word and not word.startswith("/")):
                ok, msg = target_in_scope(word, entries)
                if not ok:
                    return "VIOLATION", msg
        return "OK", "All targets in scope"


if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = " ".join(sys.argv[1:-1]) if len(sys.argv) > 2 else sys.argv[1]
        scope_file = sys.argv[-1] if len(sys.argv) > 2 else ""
        status, msg = check_command(command, scope_file)
        print(f"{status}: {msg}")
    else:
        print("Usage: scope_validator.py <command> <scope_file>")
