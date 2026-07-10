#!/usr/bin/env python3
"""
APOLLO Subfinder Wrapper - Autonomous subdomain enumeration,
verification, takeover detection, and KB injection.
"""
import sys, os, json, socket, subprocess, re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tool_registry import get_binary, is_available, run_tool
from kb_manager import get_active_project, create_event, add_host

TAKEOVER_SIGNATURES = {
    "AWS S3": [
        "NoSuchBucket", "The specified bucket does not exist",
        "404 Not Found"
    ],
    "Azure": [
        "The resource you are looking for has been removed",
        "404 - Web Page not found"
    ],
    "CloudFront": [
        "To get started with CloudFront", "BadRequest",
        "The request could not be satisfied"
    ],
    "GitHub Pages": [
        "There isn't a GitHub Pages site here",
        "404: Not Found"
    ],
    "Heroku": [
        "No such app", "Heroku | No such app"
    ],
    "Shopify": [
        "Sorry, this shop is currently unavailable",
        "Only one step left"
    ],
    "Pantheon": [
        "The gods are angry", "404 error unknown site"
    ],
    "Fastly": [
        "Fastly error: unknown domain"
    ],
    "Tumblr": [
        "There's nothing here", "Whatever you were looking for"
    ],
}

def discover_subdomains(domain, recursive=False, depth=2, sources=None, output_file=None):
    if not is_available("subfinder"):
        return ["[ERROR] subfinder not installed"]
    sources_arg = f"-s {','.join(sources)}" if sources else ""
    result = run_tool("subfinder", f"-d {domain} -silent {sources_arg}", timeout=120)
    if not result["success"]:
        return []
    subs = [s.strip() for s in result["output"].splitlines() if s.strip() and not s.strip().startswith("[")]
    if output_file:
        with open(output_file, 'w') as f:
            f.write("\n".join(subs))
    if recursive and depth > 1:
        for sub in subs[:]:
            deeper = discover_subdomains(sub, recursive=True, depth=depth - 1, sources=sources)
            for d in deeper:
                if d not in subs:
                    subs.append(d)
    return sorted(set(subs))

def verify_and_enrich(subdomains):
    if not subdomains:
        return []
    if not is_available("httpx"):
        return [{"domain": s, "alive": False} for s in subdomains]
    input_data = "\n".join(subdomains)
    try:
        binary = get_binary("httpx")
        cmd = f"{binary} -silent -status-code -title -web-server -content-length -tech-detect"
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=120, input=input_data.encode())
        out = r.stdout.decode("utf-8", errors="ignore")
    except Exception:
        return [{"domain": s, "alive": False} for s in subdomains]
    enriched = {}
    for line in out.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        url = parts[0]
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        entry = {"domain": domain, "alive": True, "status_code": None, "title": None,
                 "webserver": None, "content_length": None, "tech": []}
        for part in parts[1:]:
            if part.startswith("[") and part.endswith("]"):
                raw = part[1:-1]
                if raw.isdigit():
                    entry["status_code"] = int(raw)
                elif re.match(r'^\d+[KMG]?$', raw, re.I):
                    entry["content_length"] = raw
                elif "," in raw:
                    entry["tech"] = [t.strip() for t in raw.split(",")]
                else:
                    if not entry["title"]:
                        if len(raw) > 2 and not raw.startswith("http"):
                            entry["title"] = raw
        if "Server:" in line:
            m = re.search(r'Server:\s*(\S+)', line)
            if m:
                entry["webserver"] = m.group(1)
        enriched[domain] = entry
    for sub in subdomains:
        if sub not in enriched:
            enriched[sub] = {"domain": sub, "alive": False, "status_code": None,
                             "title": None, "webserver": None, "content_length": None, "tech": []}
    return list(enriched.values())

def _resolve_cname(domain):
    try:
        import dns.resolver
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            return str(answers[0].target).rstrip('.')
        except Exception:
            return None
    except ImportError:
        r = subprocess.run(f"dig +short CNAME {domain}", shell=True,
                          capture_output=True, timeout=10)
        out = r.stdout.decode().strip()
        return out if out else None

def _check_takeover(domain, cname):
    if not cname:
        return None
    cname_lower = cname.lower()
    try:
        r = subprocess.run(f"curl -sL -m 10 https://{domain} 2>&1 || curl -sL -m 10 http://{domain} 2>&1",
                          shell=True, capture_output=True, timeout=15)
        body = r.stdout.decode("utf-8", errors="ignore")
    except Exception:
        body = ""
    for service, signatures in TAKEOVER_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in body.lower():
                return {"domain": domain, "cname": cname, "vulnerable": True, "service": service}
    if any(domain.replace(".", "-") in cname_lower or
           cname_lower.endswith(x) for x in [".s3.amazonaws.com", ".cloudfront.net",
                                               ".azureedge.net", ".trafficmanager.net",
                                               ".herokudns.com", ".github.io",
                                               ".myshopify.com"]):
        return {"domain": domain, "cname": cname, "vulnerable": True, "service": "possible_takeover"}
    return {"domain": domain, "cname": cname, "vulnerable": False, "service": None}

def detect_takeovers(subdomains):
    results = []
    for sub in subdomains:
        cname = _resolve_cname(sub)
        if cname:
            result = _check_takeover(sub, cname)
            if result:
                results.append(result)
    return results

def inject_to_kb(project_id, results):
    hosts_added = 0
    events_created = 0
    for r in results:
        if not r.get("alive"):
            continue
        domain = r["domain"]
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            ip = domain
        tags = []
        if r.get("webserver"):
            tags.append(f"webserver:{r['webserver']}")
        if r.get("tech"):
            tags.append(f"tech:{','.join(r['tech'][:5])}")
        status = r.get("status_code")
        if status:
            tags.append(f"http:{status}")
        add_host(project_id, ip, hostname=domain, status="up", tags=";".join(tags))
        hosts_added += 1
        if r.get("title"):
            create_event(project_id, "subdomain", "subfinder_wrapper",
                         f"Subdomain {domain} ({r.get('title','')}) - HTTP {status}",
                         {"domain": domain, "ip": ip, "title": r["title"]},
                         "info" if (status or 0) < 400 else "medium")
            events_created += 1
    create_event(project_id, "injection", "subfinder_wrapper",
                 f"KB injection complete: {hosts_added} hosts, {events_created} events",
                 {"hosts_added": hosts_added, "events_created": events_created})
    return {"hosts_added": hosts_added, "events_created": events_created}

def full_subdomain_enum(project_id, domain, recursive=False):
    subs = discover_subdomains(domain, recursive=recursive)
    if not subs or subs[0].startswith("[ERROR]"):
        create_event(project_id, "enum_error", "subfinder_wrapper",
                     f"Subdomain enumeration failed for {domain}", severity="high")
        return {"domain": domain, "total_subdomains": 0, "alive": 0, "takeovers": 0, "hosts_added": 0}
    create_event(project_id, "enumeration", "subfinder_wrapper",
                 f"Found {len(subs)} subdomains for {domain}",
                 {"domain": domain, "count": len(subs)})
    enriched = verify_and_enrich(subs)
    alive = [e for e in enriched if e.get("alive")]
    takeovers = detect_takeovers([e["domain"] for e in alive])
    vuln_takeovers = [t for t in takeovers if t.get("vulnerable")]
    injected = inject_to_kb(project_id, enriched)
    summary_data = {
        "domain": domain,
        "total_subdomains": len(subs),
        "alive": len(alive),
        "takeovers": len(vuln_takeovers),
        "hosts_added": injected["hosts_added"],
    }
    create_event(project_id, "enum_summary", "subfinder_wrapper",
                 f"Enum complete: {len(subs)} subs, {len(alive)} alive, "
                 f"{len(vuln_takeovers)} takeovers, {injected['hosts_added']} hosts added",
                 summary_data)
    return summary_data

def scope_expansion(project_id, domain):
    subs = discover_subdomains(domain, recursive=False)
    if not subs or subs[0].startswith("[ERROR]"):
        return {"new_ranges": [], "new_hosts": [], "expansion_suggestions": []}
    enriched = verify_and_enrich(subs)
    alive = [e for e in enriched if e.get("alive")]
    new_ranges = set()
    new_hosts = []
    from kb_manager import get_hosts
    existing = get_hosts(project_id)
    existing_ips = {h["ip"] for h in existing}
    for e in alive:
        domain = e["domain"]
        try:
            ips = socket.gethostbyname_ex(domain)[2]
        except Exception:
            ips = []
        for ip in ips:
            if ip not in existing_ips:
                new_hosts.append({"domain": domain, "ip": ip})
                parts = ip.split(".")
                new_ranges.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
    suggestions = []
    for r in sorted(new_ranges):
        suggestions.append(f"Consider adding {r} to project scope")
    create_event(project_id, "scope_expansion", "subfinder_wrapper",
                 f"Scope expansion: {len(new_ranges)} new ranges, {len(new_hosts)} new hosts",
                 {"new_ranges": list(new_ranges), "new_hosts": new_hosts})
    return {
        "new_ranges": sorted(new_ranges),
        "new_hosts": new_hosts,
        "expansion_suggestions": suggestions,
    }

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python3 subfinder_wrapper.py enum <domain> [recursive]")
        print("  python3 subfinder_wrapper.py scope <domain>")
        sys.exit(1)
    cmd = sys.argv[1]
    domain = sys.argv[2]
    pid = None
    try:
        from kb_manager import get_project_id
        pid = get_project_id()
    except Exception:
        pid = 1
    if cmd == "enum":
        recursive = len(sys.argv) > 3 and sys.argv[3].lower() in ("recursive", "true", "1", "yes")
        result = full_subdomain_enum(pid, domain, recursive=recursive)
        print(json.dumps(result, indent=2))
    elif cmd == "scope":
        result = scope_expansion(pid, domain)
        print(json.dumps(result, indent=2))
    else:
        print(f"Unknown command: {cmd}")
