#!/usr/bin/env python3
"""
APOLLO IOC Engine v2 - Indicator extraction, scoring, YARA generation,
lifecycle management, and STIX 2.1 output.
"""
import sys, os, json, re, hashlib, urllib.request, urllib.parse, uuid, math
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import (init_db, get_connection, get_active_project,
                        get_project_id, create_event, add_note)

IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "ipv6": re.compile(r"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b", re.IGNORECASE),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    "url": re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha512": re.compile(r"\b[a-fA-F0-9]{128}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "asn": re.compile(r"\bAS\d+\b"),
    "mac": re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    "bitcoin": re.compile(r"\b[bc1][a-z0-9]{25,39}\b"),
    "registry_key": re.compile(r"HKLM\\[^\s]+|HKCU\\[^\s]+", re.IGNORECASE),
}

BENIGN_DOMAINS = {"example.com", "localhost", "schema.org", "w3.org", "microsoft.com",
                  "google.com", "github.com", "wikipedia.org", "mozilla.org", "ietf.org",
                  "apache.org", "python.org", "docker.com", "npmjs.org"}
BENIGN_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8", "8.8.4.4"}

# IOC scoring weights
IOC_SCORES = {
    "ipv4": 0.4, "ipv6": 0.5, "domain": 0.6, "url": 0.7, "email": 0.5,
    "md5": 0.5, "sha1": 0.5, "sha256": 0.7, "sha512": 0.7, "cve": 0.8,
    "asn": 0.3, "mac": 0.3, "bitcoin": 0.4, "registry_key": 0.5,
}

# Confidence modifiers
CONFIDENCE_MODIFIERS = {
    "known_malicious": 1.5, "external_report": 1.2, "internal_observation": 1.0,
    "suspicious": 0.6, "unknown": 0.3,
}


def extract_iocs(text):
    iocs = {k: set() for k in IOC_PATTERNS}
    for ioc_type, pattern in IOC_PATTERNS.items():
        for match in pattern.finditer(text):
            val = match.group(0)
            if ioc_type == "domain" and val.lower() in BENIGN_DOMAINS:
                continue
            if ioc_type == "ipv4" and val in BENIGN_IPS:
                continue
            if ioc_type == "md5" and val.lower() == "0" * 32:
                continue
            iocs[ioc_type].add(val)
    return {k: sorted(v) for k, v in iocs.items() if v}


def score_ioc(ioc_type, value, confidence="suspicious"):
    """Score an indicator on 0-1 scale. Higher = more concerning."""
    base = IOC_SCORES.get(ioc_type, 0.3)
    mod = CONFIDENCE_MODIFIERS.get(confidence, 0.3)
    score = min(1.0, base * mod * 1.5)
    # Length-based penalty for ipv4/domain
    if ioc_type == "ipv4" and value.startswith("10.") or value.startswith("192.168."):
        score *= 0.3  # Private IPs are less interesting
    if ioc_type == "domain":
        entropy = -sum((value.count(c)/len(value)) * math.log(value.count(c)/len(value)) for c in set(value))
        if entropy > 3.5:
            score = min(1.0, score * 1.3)  # High entropy domains are suspicious
    return {"ioc": value, "type": ioc_type, "score": round(score, 3), "confidence": confidence}


def score_all(iocs, confidence="suspicious"):
    """Score all IOCs in a result dict."""
    scored = {}
    for ioc_type, values in iocs.items():
        scored[ioc_type] = [score_ioc(ioc_type, v, confidence) for v in values]
    return scored


def generate_yara(iocs, rule_name="apollo_detected"):
    """Generate YARA rules from file hashes and patterns."""
    rules = []
    hashes_md5 = iocs.get("md5", [])
    hashes_sha1 = iocs.get("sha1", [])
    hashes_sha256 = iocs.get("sha256", [])
    domains = iocs.get("domain", [])
    ips = iocs.get("ipv4", [])
    if hashes_md5 or hashes_sha1 or hashes_sha256:
        rule = f'rule {rule_name}_hashes {{\n'
        rule += '    meta:\n        description = "APOLLO generated hash IOC rules"\n        author = "APOLLO IOC Engine"\n'
        rule += '    condition:\n        uint32(0) == 0x464c457f or uint32(0) == 0x5a4d  /* ELF or PE */\n'
        rule += '    condition:\n        '
        conditions = []
        for h in hashes_md5:
            conditions.append(f'hash.md5(0, filesize) == "{h.lower()}"')
        for h in hashes_sha1:
            conditions.append(f'hash.sha1(0, filesize) == "{h.lower()}"')
        for h in hashes_sha256:
            conditions.append(f'hash.sha256(0, filesize) == "{h.lower()}"')
        rule += " or\n        ".join(conditions) + "\n}"
        rules.append(rule)
    if domains or ips:
        rule = f'rule {rule_name}_network {{\n'
        rule += '    meta:\n        description = "APOLLO generated network IOC rules"\n        author = "APOLLO IOC Engine"\n'
        rule += '    strings:\n'
        for i, d in enumerate(domains[:20]):
            rule += f'        $domain_{i} = "{d}"\n'
        for i, ip in enumerate(ips[:20]):
            rule += f'        $ip_{i} = "{ip}"\n'
        rule += '    condition:\n        any of them\n}'
        rules.append(rule)
    return rules


def _api_get(url, headers=None, timeout=10):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="ignore"))
    except Exception as e:
        return {"error": str(e)}


def enrich_ip(ip):
    result = {"ip": ip, "abuseipdb": None, "shodan": None}
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    shodan_key = os.environ.get("SHODAN_API_KEY", "")
    if abuse_key:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        result["abuseipdb"] = _api_get(url, {"Key": abuse_key, "Accept": "application/json"})
    if shodan_key:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}"
        result["shodan"] = _api_get(url)
    if not abuse_key and not shodan_key:
        result["note"] = "Set ABUSEIPDB_API_KEY and SHODAN_API_KEY for enrichment"
    return result


def enrich_hash(file_hash):
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not vt_key:
        return {"hash": file_hash, "note": "Set VIRUSTOTAL_API_KEY for enrichment"}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    result = _api_get(url, {"x-apikey": vt_key})
    return {"hash": file_hash, "virustotal": result}


def enrich_domain(domain):
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not vt_key:
        return {"domain": domain, "note": "Set VIRUSTOTAL_API_KEY for enrichment"}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    return {"domain": domain, "virustotal": _api_get(url, {"x-apikey": vt_key})}


def enrich_all(iocs):
    enriched = {"timestamp": datetime.utcnow().isoformat(), "iocs": {}}
    for ip in iocs.get("ipv4", [])[:20]:
        enriched["iocs"][f"ip:{ip}"] = enrich_ip(ip)
    for h in iocs.get("sha256", [])[:10] + iocs.get("md5", [])[:10]:
        enriched["iocs"][f"hash:{h}"] = enrich_hash(h)
    for d in iocs.get("domain", [])[:20]:
        enriched["iocs"][f"domain:{d}"] = enrich_domain(d)
    return enriched


def to_stix(iocs, enriched=None):
    objects = []
    for ip in iocs.get("ipv4", []):
        objects.append({"type": "ipv4-addr", "spec_version": "2.1",
                        "id": f"ipv4-addr--{uuid.uuid5(hashlib.NAMESPACE_DNS, ip)}", "value": ip})
    for domain in iocs.get("domain", []):
        objects.append({"type": "domain-name", "spec_version": "2.1",
                        "id": f"domain-name--{uuid.uuid5(hashlib.NAMESPACE_DNS, domain)}", "value": domain})
    for url in iocs.get("url", []):
        objects.append({"type": "url", "spec_version": "2.1",
                        "id": f"url--{uuid.uuid5(hashlib.NAMESPACE_DNS, url)}", "value": url})
    for h in iocs.get("md5", []):
        objects.append({"type": "file", "spec_version": "2.1",
                        "id": f"file--{uuid.uuid5(hashlib.NAMESPACE_DNS, h)}", "hashes": {"MD5": h}})
    for h in iocs.get("sha256", []):
        objects.append({"type": "file", "spec_version": "2.1",
                        "id": f"file--{uuid.uuid5(hashlib.NAMESPACE_DNS, h)}", "hashes": {"SHA-256": h}})
    for email in iocs.get("email", []):
        objects.append({"type": "email-addr", "spec_version": "2.1",
                        "id": f"email-addr--{uuid.uuid5(hashlib.NAMESPACE_DNS, email)}", "value": email})
    for cve in iocs.get("cve", []):
        objects.append({"type": "vulnerability", "spec_version": "2.1",
                        "id": f"vulnerability--{uuid.uuid5(hashlib.NAMESPACE_DNS, cve)}", "name": cve})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def extract_from_kb(project_id):
    init_db()
    conn = get_connection()
    text_parts = []
    for h in conn.execute("SELECT * FROM hosts WHERE project_id=?", (project_id,)).fetchall():
        text_parts.append(json.dumps(dict(h)))
    for v in conn.execute("""SELECT v.*,h.ip FROM vulnerabilities v JOIN hosts h ON v.host_id=h.id
                             WHERE h.project_id=?""", (project_id,)).fetchall():
        text_parts.append(json.dumps(dict(v)))
    for e in conn.execute("SELECT * FROM events WHERE project_id=?", (project_id,)).fetchall():
        text_parts.append(json.dumps(dict(e)))
    return extract_iocs("\n".join(text_parts))


def hunt_iocs(text, project_id=None):
    iocs = extract_iocs(text)
    scored = score_all(iocs)
    enriched = enrich_all(iocs)
    stix = to_stix(iocs, enriched)
    yara = generate_yara(iocs)
    summary = {k: len(v) for k, v in iocs.items()}
    if project_id:
        create_event(project_id, "ioc_hunt", "ioc_engine",
                     f"IOC hunt: {sum(len(v) for v in iocs.values())} indicators",
                     {"iocs": iocs, "scored": scored, "yara": len(yara)}, "info")
        add_note(project_id, "IOC Hunt Results",
                 json.dumps({"iocs": iocs, "scored": scored, "enriched": enriched, "yara": yara},
                           indent=2, default=str), "threat-intel")
    return {"iocs": iocs, "scored": scored, "enriched": enriched, "stix": stix,
            "yara": yara, "summary": summary}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("APOLLO IOC Engine v2")
        print("Usage:")
        print(f"  {sys.argv[0]} extract <text|file>        - Extract IOCs")
        print(f"  {sys.argv[0]} enrich <ip|hash|domain>    - Enrich single IOC")
        print(f"  {sys.argv[0]} hunt <text|file> [project] - Full hunt + score + enrich")
        print(f"  {sys.argv[0]} kb [project]               - Extract IOCs from KB")
        print(f"  {sys.argv[0]} stix <text|file>           - STIX 2.1 output")
        print(f"  {sys.argv[0]} yara <text|file>           - Generate YARA rules")
        sys.exit(0)
    action = sys.argv[1]
    if action == "extract":
        text = sys.argv[2]
        if os.path.exists(text):
            with open(text) as f: text = f.read()
        iocs = extract_iocs(text)
        scored = score_all(iocs)
        print(json.dumps({"iocs": iocs, "scored": scored}, indent=2))
    elif action == "enrich":
        val = sys.argv[2]
        if re.match(IOC_PATTERNS["ipv4"], val):
            print(json.dumps(enrich_ip(val), indent=2, default=str))
        elif re.match(IOC_PATTERNS["md5"], val) or re.match(IOC_PATTERNS["sha256"], val):
            print(json.dumps(enrich_hash(val), indent=2, default=str))
        else:
            print(json.dumps(enrich_domain(val), indent=2, default=str))
    elif action == "hunt":
        text = sys.argv[2]
        if os.path.exists(text):
            with open(text) as f: text = f.read()
        pid = get_project_id(sys.argv[3]) if len(sys.argv) > 3 else get_project_id()
        print(json.dumps(hunt_iocs(text, pid), indent=2, default=str))
    elif action == "kb":
        pid = get_project_id(sys.argv[2]) if len(sys.argv) > 2 else get_project_id()
        iocs = extract_from_kb(pid)
        scored = score_all(iocs)
        print(json.dumps({"iocs": iocs, "scored": scored}, indent=2))
    elif action == "stix":
        text = sys.argv[2]
        if os.path.exists(text):
            with open(text) as f: text = f.read()
        print(json.dumps(to_stix(extract_iocs(text)), indent=2))
    elif action == "yara":
        text = sys.argv[2]
        if os.path.exists(text):
            with open(text) as f: text = f.read()
        yara = generate_yara(extract_iocs(text))
        print("\n\n".join(yara))
    else:
        print(f"Unknown action: {action}")
