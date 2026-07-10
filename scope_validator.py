#!/usr/bin/env python3
"""
APOLLO Scope Validator - Validate targets against scope file.
Supports CIDR ranges, IP ranges, hostnames, and domain patterns.
"""
import sys
import os
import ipaddress
import re

def load_scope(scope_file):
    if not scope_file or not os.path.exists(scope_file):
        return []
    entries = []
    with open(scope_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                entries.append(line)
    return entries

def target_in_scope(target, scope_entries):
    target = target.strip()
    for entry in scope_entries:
        entry = entry.strip()
        try:
            if '/' in entry:
                network = ipaddress.ip_network(entry, strict=False)
                try:
                    ip = ipaddress.ip_address(target)
                    if ip in network:
                        return True, f"{target} in {entry}"
                except ValueError:
                    continue
            elif '-' in entry:
                parts = entry.split('-')
                if len(parts) == 2:
                    start = ipaddress.ip_address(parts[0].strip())
                    end = ipaddress.ip_address(parts[1].strip())
                    try:
                        ip = ipaddress.ip_address(target)
                        if start <= ip <= end:
                            return True, f"{target} in range {entry}"
                    except ValueError:
                        continue
            else:
                if target == entry:
                    return True, f"{target} matches {entry}"
                if entry.startswith('*.'):
                    domain = entry[2:]
                    if target.endswith(domain):
                        return True, f"{target} matches wildcard {entry}"
                try:
                    ip = ipaddress.ip_address(target)
                    single = ipaddress.ip_address(entry)
                    if ip == single:
                        return True, f"{target} matches {entry}"
                except ValueError:
                    if target.lower() == entry.lower():
                        return True, f"{target} matches {entry}"
        except ValueError:
            continue
    return False, f"{target} NOT in scope"

def check_command(command, scope_file):
    scope_entries = load_scope(scope_file)
    if not scope_entries:
        return "OK", "No scope file defined - all targets allowed"
    
    words = command.split()
    targets_found = []
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    domain_pattern = re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b')
    
    for word in words:
        if ip_pattern.match(word):
            targets_found.append(word)
        elif domain_pattern.match(word) and '.' in word and not word.startswith('/'):
            targets_found.append(word)
    
    for target in targets_found:
        in_scope, msg = target_in_scope(target, scope_entries)
        if not in_scope:
            return "VIOLATION", msg
    
    return "OK", f"All targets in scope"

if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = ' '.join(sys.argv[1:-1]) if len(sys.argv) > 2 else sys.argv[1]
        scope_file = sys.argv[-1] if len(sys.argv) > 2 else ""
        status, msg = check_command(command, scope_file)
        print(f"{status}: {msg}")
    else:
        print("Usage: scope_validator.py <command> <scope_file>")
