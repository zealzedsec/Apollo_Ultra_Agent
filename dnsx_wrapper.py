#!/usr/bin/env python3
"""
APOLLO DNSx Wrapper v1 - Sophisticated DNS reconnaissance engine.
Enumerates DNS records, detects wildcards, attempts zone transfers,
brute-forces subdomains, and maps attack surface.
"""
import sys, os, json, subprocess, random, string

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tool_registry import get_binary, is_available
from kb_manager import get_active_project, create_event

ALL_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV", "PTR", "NAPTR"]

DNSX_FLAG_MAP = {
    "A": "-a", "AAAA": "-aaaa", "CNAME": "-cname", "MX": "-mx",
    "NS": "-ns", "TXT": "-txt", "SOA": "-soa",
}

COMMON_SUBDOMAINS = [
    "admin", "mail", "www", "app", "api", "blog", "cdn", "dev", "docs",
    "ftp", "git", "help", "intranet", "portal", "server", "ssh", "staging",
    "support", "test", "vpn", "webmail", "autodiscover", "beta", "calendar",
    "chat", "cloud", "cms", "config", "contact", "corp", "db", "demo",
    "download", "dns", "email", "en", "exchange", "forum", "gateway",
    "host", "hostmaster", "imap", "internal", "jenkins", "kb", "login",
    "manager", "media", "mobile", "monitor", "mx", "my", "owa", "panel",
    "partner", "partnerportal", "pay", "phpmyadmin", "pop", "proxy",
    "radius", "remote", "repo", "report", "request", "router", "sandbox",
    "secure", "services", "shop", "signup", "smtp", "sso", "static",
    "status", "store", "sub", "svn", "syslog", "tracking", "uploads",
    "user", "video", "web", "webdisk", "webmail", "wiki", "www2", "www3",
    "xmlrpc", "zabbix", "zeitgeist", "zone",
]


def _run_dnsx(domain, extra_args=None):
    binary = get_binary("dnsx")
    if not binary:
        return None
    cmd = [binary, "-json", "-silent"]
    if extra_args:
        cmd.extend(extra_args)
    try:
        r = subprocess.run(cmd, input=domain + "\n", capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return None
        lines = r.stdout.strip().splitlines()
        return [json.loads(l) for l in lines if l.strip()]
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return None


def _build_type_flags(record_types):
    flags = []
    if not record_types:
        record_types = ALL_RECORD_TYPES
    for rt in record_types:
        f = DNSX_FLAG_MAP.get(rt.upper())
        if f:
            flags.append(f)
    return flags


TYPE_KEY_MAP = {
    "A": "a", "AAAA": "aaaa", "CNAME": "cname", "MX": "mx",
    "NS": "ns", "TXT": "txt", "SOA": "soa", "CAA": "caa",
    "SRV": "srv", "PTR": "ptr", "NAPTR": "naptr"
}

def enum_dns_records(domain, record_types=None):
    if record_types is None:
        record_types = ALL_RECORD_TYPES
    result = {rt: [] for rt in record_types}
    type_flags = _build_type_flags(record_types)
    if not type_flags:
        return result
    entries = _run_dnsx(domain, type_flags)
    if entries is None:
        return result
    for e in entries:
        for rt, key in TYPE_KEY_MAP.items():
            if rt in result and key in e:
                vals = e[key] if isinstance(e[key], list) else [e[key]]
                for v in vals:
                    if v and v not in result[rt]:
                        result[rt].append(v)
    return result


def wildcard_detection(domain):
    rand_subs = []
    for _ in range(3):
        r = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        rand_subs.append(f"{r}.{domain}")
    resolving_ips = []
    for sub in rand_subs:
        entries = _run_dnsx(sub, ["-a"])
        if entries:
            for e in entries:
                ip = e.get("a", "")
                if ip and ip not in resolving_ips:
                    resolving_ips.append(ip)
    return {
        "domain": domain,
        "wildcard": len(resolving_ips) > 0,
        "resolving_ips": resolving_ips,
        "random_subdomains_tested": rand_subs,
    }


def zone_transfer_attempt(domain, nameservers=None):
    result = {"domain": domain, "zone_transfer_possible": False, "records": [], "nameserver": ""}
    try:
        import dns.resolver, dns.query, dns.zone, dns.name
        if not nameservers:
            answers = dns.resolver.resolve(domain, "NS", lifetime=10)
            nameservers = [str(a) for a in answers]
        for ns in nameservers:
            try:
                ns = ns.rstrip(".")
                z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
                if z and z.nodes:
                    result["zone_transfer_possible"] = True
                    result["nameserver"] = ns
                    result["records"] = [str(n) for n in z.nodes.keys()]
                    break
            except Exception:
                continue
    except ImportError:
        if not nameservers:
            ns_entries = _run_dnsx(domain, ["-ns"])
            if ns_entries:
                nameservers = [e.get("ns", e.get("host", "")) for e in ns_entries if e.get("ns")]
        if not nameservers:
            return result
        for ns in nameservers[:3]:
            try:
                r = subprocess.run(
                    ["dig", "+short", f"@{ns}", domain, "axfr"],
                    capture_output=True, text=True, timeout=15
                )
                if r.returncode == 0 and r.stdout.strip():
                    lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
                    if lines:
                        result["zone_transfer_possible"] = True
                        result["nameserver"] = ns
                        result["records"] = lines
                        break
            except Exception:
                continue
    return result


def brute_force_subdomains(domain, wordlist=None):
    resolved = []
    if wordlist and os.path.isfile(wordlist):
        pass
    elif os.path.isfile("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"):
        wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    else:
        binary = get_binary("dnsx")
        if not binary:
            return resolved
        for sub in COMMON_SUBDOMAINS:
            entries = _run_dnsx(f"{sub}.{domain}", ["-a", "-cname"])
            if entries:
                for e in entries:
                    if e.get("a") or e.get("cname"):
                        fqdn = f"{sub}.{domain}"
                        if fqdn not in resolved:
                            resolved.append(fqdn)
        return resolved
    entries = _run_dnsx(domain, ["-w", wordlist])
    if entries is None:
        return resolved
    for e in entries:
        host = e.get("host", "")
        if host and host not in resolved:
            resolved.append(host)
    return resolved


def full_dns_recon(project_id, domain):
    records = enum_dns_records(domain)
    wc = wildcard_detection(domain)
    zt = zone_transfer_attempt(domain)
    bf = brute_force_subdomains(domain)
    event_data = {"domain": domain, "record_types_found": list(records.keys()),
                  "wildcard": wc["wildcard"], "zone_transfer": zt["zone_transfer_possible"],
                  "brute_force_count": len(bf)}
    create_event(project_id, "dns_recon", "dnsx_wrapper",
                 f"DNS recon completed for {domain}: wildcard={wc['wildcard']}, "
                 f"zone_transfer={zt['zone_transfer_possible']}, bf_found={len(bf)}",
                 event_data, severity="info")
    return {
        "domain": domain,
        "records": records,
        "wildcard": wc["wildcard"],
        "zone_transfer": zt["zone_transfer_possible"],
        "brute_force_finds": bf,
        "event_created": True,
    }


def dns_attack_surface(project_id, domain):
    records = enum_dns_records(domain)
    mail_servers = records.get("MX", [])
    ns_servers = records.get("NS", [])
    txt_records = records.get("TXT", [])
    cname_records = records.get("CNAME", [])
    spf_policy = "not found"
    dmarc_policy = "not found"
    for txt in txt_records:
        txt_u = txt.upper()
        if "V=SPF1" in txt_u:
            spf_policy = txt
        if "V=DMARC1" in txt_u:
            dmarc_policy = txt
    cname_takeover_candidates = []
    for cname in cname_records:
        cname_l = cname.lower().rstrip(".")
        for indicator in ["s3.amazonaws.com", "cloudfront.net", "azurewebsites.net",
                          "azureedge.net", "trafficmanager.net", "blob.core.windows.net",
                          "herokuapp.com", "herokudns.com", "github.io", "surge.sh",
                          "unbounce.com", "wordpress.com", "pantheonsite.io", "squarespace.com",
                          "firebaseapp.com", "appspot.com", "elb.amazonaws.com",
                          "myshopify.com", "cargocollective.com", "fly.io", "ngrok.io"]:
            if indicator in cname_l:
                cname_takeover_candidates.append(cname)
                break
    recommendations = []
    if spf_policy == "not found" or "~all" not in spf_policy and "-all" not in spf_policy:
        recommendations.append("SPF record missing or overly permissive - email spoofing risk")
    if dmarc_policy == "not found":
        recommendations.append("DMARC record missing - no email authentication enforcement")
    elif "p=reject" not in dmarc_policy.lower() and "p=quarantine" not in dmarc_policy.lower():
        recommendations.append("DMARC policy not set to reject/quarantine - spoofing possible")
    if cname_takeover_candidates:
        recommendations.append(f"Potential subdomain takeover: {', '.join(cname_takeover_candidates)}")
    if not ns_servers:
        recommendations.append("No NS records found - DNS resolution may be misconfigured")
    if mail_servers and not spf_policy or mail_servers and spf_policy == "not found":
        recommendations.append("Mail servers present but no SPF - email spoofing unprotected")
    event_data = {"domain": domain, "mail_servers": mail_servers,
                  "spf": spf_policy, "dmarc": dmarc_policy,
                  "ns_servers": ns_servers, "cname_takeovers": cname_takeover_candidates}
    create_event(project_id, "dns_attack_surface", "dnsx_wrapper",
                 f"DNS attack surface analyzed for {domain}: {len(mail_servers)} MX, "
                 f"SPF={'found' if 'SPF1' in str(spf_policy) else 'missing'}, "
                 f"DMARC={'found' if 'DMARC1' in str(dmarc_policy) else 'missing'}, "
                 f"{len(cname_takeover_candidates)} takeover candidates",
                 event_data, severity="info")
    return {
        "domain": domain,
        "mail_servers": mail_servers,
        "spf_policy": spf_policy,
        "dmarc_policy": dmarc_policy,
        "ns_servers": ns_servers,
        "cname_takeover_candidates": cname_takeover_candidates,
        "recommendations": recommendations,
    }


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] != "recon":
        print("Usage: python3 dnsx_wrapper.py recon <domain>")
        sys.exit(1)
    domain = sys.argv[2]
    pid = None
    try:
        pname = get_active_project()
        from kb_manager import get_project_id
        pid = get_project_id(pname)
    except Exception:
        pass
    if not pid:
        pid = 1
    print(f"[APOLLO DNSx] Starting reconnaissance for: {domain}")
    print(f"[APOLLO DNSx] Project ID: {pid}")
    recon = full_dns_recon(pid, domain)
    print(json.dumps(recon, indent=2))
    print("\n[APOLLO DNSx] Analyzing attack surface...")
    surface = dns_attack_surface(pid, domain)
    for rec in surface["recommendations"]:
        print(f"  [!] {rec}")
    print(json.dumps({k: v for k, v in surface.items() if k != "recommendations"}, indent=2))
