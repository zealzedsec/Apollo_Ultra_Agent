#!/usr/bin/env python3
"""
APOLLO Recon Tools v1 - Unified CLI for naabu, subfinder, dnsx wrappers
Usage: python3 recon_tools.py <command> [args]

Commands:
  scan <target> [depth]       Port scan (naabu + nmap service detection)
  enum <domain> [recursive]   Subdomain enumeration (subfinder + httpx)
  dns <domain>                Full DNS recon (dnsx all records)
  deep <target>               Full deep recon (all tools chained)
  surface [project]           Attack surface summary from KB
  auto <target1> [target2]... Auto-detect scope, run deep recon
  tools                       Show available recon tools
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import get_active_project, init_db, create_project, set_active_project

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    cmd = sys.argv[1]
    init_db()
    pid = get_active_project()
    if not pid:
        pid = create_project("default")
        set_active_project("default")
        pid = get_active_project()

    if cmd == "tools":
        from tool_registry import detect_tools, detect_python_modules
        tools = detect_tools(force=True)
        recon_tools = {k: v for k, v in tools.items() if k in ("naabu","subfinder","dnsx","httpx","nuclei","nmap","masscan","amass","theHarvester","gobuster")}
        print("\nAPOLLO Recon Tools:")
        for t, avail in recon_tools.items():
            print(f"  {'OK' if avail else 'MISSING'} {t}")
        print(f"\nPython wrappers:")
        for mod in ["naabu_wrapper", "subfinder_wrapper", "dnsx_wrapper", "recon_deep"]:
            try:
                __import__(mod)
                print(f"  OK {mod}")
            except: print(f"  MISSING {mod}")

    elif cmd == "scan":
        if len(sys.argv) < 3: print("Usage: recon_tools.py scan <target> [depth]"); sys.exit(1)
        from naabu_wrapper import smart_scan
        target = sys.argv[2]; depth = sys.argv[3] if len(sys.argv) > 3 else "normal"
        print(f"[*] Port scan: {target} (depth={depth})")
        result = smart_scan(pid, target, depth)
        print(json.dumps(result, indent=2, default=str)[:3000])

    elif cmd == "enum":
        if len(sys.argv) < 3: print("Usage: recon_tools.py enum <domain> [recursive]"); sys.exit(1)
        from subfinder_wrapper import full_subdomain_enum
        domain = sys.argv[2]; rec = "recursive" in sys.argv or "-r" in sys.argv
        print(f"[*] Subdomain enum: {domain} (recursive={rec})")
        result = full_subdomain_enum(pid, domain, rec)
        print(json.dumps(result, indent=2, default=str)[:3000])

    elif cmd == "dns":
        if len(sys.argv) < 3: print("Usage: recon_tools.py dns <domain>"); sys.exit(1)
        from dnsx_wrapper import full_dns_recon, dns_attack_surface
        domain = sys.argv[2]
        print(f"[*] DNS recon: {domain}")
        result = full_dns_recon(pid, domain)
        print(json.dumps(result, indent=2, default=str)[:2000])
        asurface = dns_attack_surface(pid, domain)
        if asurface:
            print(f"\n[*] Attack surface analysis:")
            print(json.dumps(asurface, indent=2, default=str)[:2000])

    elif cmd == "deep":
        if len(sys.argv) < 3: print("Usage: recon_tools.py deep <target> [depth]"); sys.exit(1)
        from recon_deep import recon_deep
        target = sys.argv[2]; depth = sys.argv[3] if len(sys.argv) > 3 else "normal"
        print(f"[*] Deep recon: {target} (depth={depth})")
        result = recon_deep(pid, target, depth)
        s = result.get("summary", {})
        print(f"\n{'='*50}")
        print(f"RECON DEEP COMPLETE: {target}")
        print(f"  Duration: {s.get('elapsed_seconds',0)}s")
        print(f"  Tools: {', '.join(s.get('tools_used',[]))}")
        print(f"  Vulns: {s.get('total_vulnerabilities',0)}")
        if result.get("attack_surface",{}).get("high_value_targets"):
            print(f"  High-value targets: {len(result['attack_surface']['high_value_targets'])}")
        print(f"{'='*50}")

    elif cmd == "surface":
        from naabu_wrapper import attack_surface_summary
        print(f"[*] Attack surface for project {pid}")
        result = attack_surface_summary(pid)
        print(json.dumps(result, indent=2, default=str)[:3000])

    elif cmd == "auto":
        if len(sys.argv) < 3: print("Usage: recon_tools.py auto <target1> [target2]..."); sys.exit(1)
        from recon_deep import recon_auto
        targets = sys.argv[2:]
        print(f"[*] Auto recon for {len(targets)} targets")
        results = recon_auto(pid, targets)
        for t, r in results.items():
            s = r.get("summary", {})
            print(f"  {t}: {s.get('elapsed_seconds',0)}s, {s.get('total_vulnerabilities',0)} vulns")

    else:
        print(f"Unknown command: {cmd}\n{__doc__}")

if __name__ == "__main__":
    main()
