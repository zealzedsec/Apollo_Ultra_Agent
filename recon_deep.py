#!/usr/bin/env python3
"""
APOLLO Recon Deep v1 - Unified Deep Reconnaissance Orchestrator
Chains: domain -> [subfinder+dnsx] -> [httpx] -> [naabu] -> [nuclei] -> KB
"""
import sys, os, json, subprocess, threading, time
from datetime import datetime
from typing import Dict, List, Optional
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tool_registry import get_binary, is_available, run_tool, detect_tools
from kb_manager import get_active_project, create_event, add_host, add_port, add_vulnerability

try:
    from naabu_wrapper import run_port_scan, inject_naabu_results, classify_ports, port_exploit_map, attack_surface_summary
    NAABU_AVAILABLE = True
except:
    NAABU_AVAILABLE = False

try:
    from subfinder_wrapper import discover_subdomains, verify_and_enrich, detect_takeovers, inject_to_kb
    SUBFINDER_AVAILABLE = True
except:
    SUBFINDER_AVAILABLE = False

try:
    from dnsx_wrapper import enum_dns_records, wildcard_detection, zone_transfer_attempt, full_dns_recon, dns_attack_surface
    DNSX_AVAILABLE = True
except:
    DNSX_AVAILABLE = False


def recon_deep(project_id: int, target: str, depth: str = "normal", scope: str = "domain") -> Dict:
    """
    Full deep recon pipeline: DNS -> subdomains -> port scan -> vuln scan.
    target: domain or IP/CIDR
    depth: "quick" (top-100 ports, no recursion), "normal" (top-1000, rec depth 1), "deep" (full ports, rec depth 2)
    scope: "domain" or "ip" (determines which tools to use)
    Returns comprehensive summary dict.
    """
    start_time = time.time()
    results = {
        "target": target, "depth": depth, "scope": scope,
        "started": datetime.now().isoformat(),
        "domain_recon": {}, "subdomain_enum": {},
        "port_scan": {}, "vuln_scan": {},
        "attack_surface": {}, "summary": {}
    }

    # Phase 1: DNS & Subdomain Recon (only for domain scope)
    if scope == "domain":
        if DNSX_AVAILABLE:
            print(f"[*] Phase 1a: DNS recon for {target}")
            results["domain_recon"] = full_dns_recon(project_id, target)
            asurface = dns_attack_surface(project_id, target)
            if asurface:
                results["domain_recon"]["attack_surface"] = asurface

        if SUBFINDER_AVAILABLE:
            rec_depth = 0 if depth == "quick" else (2 if depth == "deep" else 1)
            print(f"[*] Phase 1b: Subdomain enumeration for {target} (depth={rec_depth})")
            results["subdomain_enum"] = discover_subdomains(target, recursive=rec_depth > 0, depth=rec_depth)

    # Phase 2: Port Scanning
    scan_targets = [target]
    if scope == "domain" and results.get("subdomain_enum", {}).get("subdomains"):
        alive = verify_and_enrich(results["subdomain_enum"]["subdomains"])
        if alive:
            results["subdomain_enum"]["verified"] = alive
            scan_targets = list(set([a["domain"] for a in alive if a.get("alive")]))
            print(f"[*] {len(scan_targets)} alive hosts from subdomain enum")

    if NAABU_AVAILABLE:
        port_spec = {"quick": "top-100", "normal": "top-1000", "deep": "1-65535"}.get(depth, "top-1000")
        rate = {"quick": 3000, "normal": 1000, "deep": 500}.get(depth, 1000)
        all_ports = []

        for starget in scan_targets[:10]:
            print(f"[*] Phase 2: Port scan {starget} (ports={port_spec})")
            scan_result = run_port_scan(starget, ports=port_spec, rate=rate)
            if scan_result.get("success") and scan_result.get("results"):
                added = inject_naabu_results(project_id, scan_result["results"])
                all_ports.extend(scan_result["results"])
                print(f"  [+] {added['ports_added']} ports found on {added['hosts_added']} hosts")

        results["port_scan"] = {
            "targets_scanned": len(scan_targets[:10]),
            "total_ports_found": len(all_ports),
            "ports": all_ports[:100],
            "categories": classify_ports([(p.get("port"), p.get("protocol", "tcp")) for p in all_ports])
        }

    # Phase 3: Vulnerability Scanning with nuclei
    if is_available("nuclei") and results.get("port_scan", {}).get("total_ports_found", 0) > 0:
        print(f"[*] Phase 3: Vulnerability scanning with nuclei")
        web_targets = [t for t in scan_targets[:5] if t]
        vuln_results = []
        for wt in web_targets:
            r = run_tool("nuclei", f"-u https://{wt} -json -severity critical,high,medium 2>/dev/null", timeout=120)
            if r.get("success") and r.get("output"):
                for line in r["output"].strip().split("\n"):
                    try:
                        v = json.loads(line)
                        vuln_results.append(v)
                        add_vulnerability(project_id, v.get("info", {}).get("name", "Unknown"),
                                          v.get("info", {}).get("severity", "medium"),
                                          description=v.get("info", {}).get("description", ""),
                                          cve_id=v.get("info", {}).get("classification", {}).get("cve_id", ""),
                                          mitre_id=v.get("info", {}).get("classification", {}).get("mitre_id", ""))
                    except:
                        pass

        results["vuln_scan"] = {
            "targets_scanned": len(web_targets),
            "total_vulnerabilities": len(vuln_results),
            "findings": vuln_results[:50]
        }

    # Phase 4: Attack Surface Summary
    try:
        results["attack_surface"] = attack_surface_summary(project_id)
    except:
        pass

    elapsed = time.time() - start_time
    results["summary"] = {
        "elapsed_seconds": round(elapsed, 1),
        "total_hosts_discovered": len(results.get("port_scan", {}).get("ports", [])),
        "total_vulnerabilities": results.get("vuln_scan", {}).get("total_vulnerabilities", 0),
        "depth": depth,
        "tools_used": []
    }
    if NAABU_AVAILABLE: results["summary"]["tools_used"].append("naabu")
    if SUBFINDER_AVAILABLE: results["summary"]["tools_used"].append("subfinder")
    if DNSX_AVAILABLE: results["summary"]["tools_used"].append("dnsx")
    if is_available("nuclei"): results["summary"]["tools_used"].append("nuclei")
    if is_available("httpx"): results["summary"]["tools_used"].append("httpx")

    create_event(project_id, "recon_deep", "recon_deep",
                 f"Deep recon completed for {target} in {elapsed:.0f}s",
                 data={"depth": depth, "summary": results["summary"]})

    return results


def recon_auto(project_id: int, targets: List[str]) -> Dict:
    """Auto-detect scope type for each target and run appropriate recon."""
    import re
    results = {}
    for target in targets:
        is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target)
        scope = "ip" if is_ip else "domain"
        print(f"[*] Auto-recon: {target} (detected scope: {scope})")
        results[target] = recon_deep(project_id, target, scope=scope)
        create_event(project_id, "recon_auto", "recon_deep",
                     f"Auto-recon completed for {target}",
                     data={"scope": scope})
    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="APOLLO Recon Deep - Full recon pipeline")
    parser.add_argument("target", help="Target domain or IP/CIDR")
    parser.add_argument("--depth", choices=["quick", "normal", "deep"], default="normal")
    parser.add_argument("--project", help="Project name (default: active project)")
    parser.add_argument("--output", "-o", help="Save results to JSON file")
    args = parser.parse_args()

    from kb_manager import get_active_project, create_project, set_active_project
    pid = get_active_project()
    if args.project:
        pid = create_project(args.project)
        set_active_project(args.project)

    if not pid:
        print("[!] No active project. Use --project or set one via /kb project")
        sys.exit(1)

    results = recon_deep(pid, args.target, depth=args.depth)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"[+] Results saved to {args.output}")

    s = results["summary"]
    print(f"\n{'='*60}")
    print(f"RECON DEEP COMPLETE: {args.target}")
    print(f"{'='*60}")
    print(f"  Duration:    {s['elapsed_seconds']}s")
    print(f"  Tools used:  {', '.join(s['tools_used'])}")
    print(f"  Vulns found: {s['total_vulnerabilities']}")
    print(f"\n  Attack surface:")
    a = results.get("attack_surface", {})
    cats = a.get("categories", {})
    for cat, info in cats.items():
        if info.get("ports"): print(f"    {cat}: {len(info['ports'])} ports")
    if a.get("high_value_targets"):
        print(f"  High-value targets: {len(a['high_value_targets'])}")
        for hvt in a["high_value_targets"][:5]:
            print(f"    {hvt}")
    print(f"{'='*60}")
