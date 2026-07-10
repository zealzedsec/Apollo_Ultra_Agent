#!/usr/bin/env python3
"""
APOLLO NVD/CVE Enricher v2 - Fetches CVE data, CPE matching, CISA KEV,
EPSS scoring, and auto-KB enrichment.
"""
import sys, os, json, sqlite3, urllib.request, urllib.error, urllib.parse, time, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import (init_db, get_connection, get_active_project,
                        get_project_id, create_event, add_vulnerability,
                        get_hosts, get_vulnerabilities)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
CACHE_FILE = os.path.expanduser("~/.config/opencode/apollo-engine/.nvd_cache.json")
KEV_CACHE_FILE = os.path.expanduser("~/.config/opencode/apollo-engine/.kev_cache.json")
EPSS_API = "https://api.first.org/data/v1/epss"


def load_cache():
    try:
        with open(CACHE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_cache(cache):
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, indent=2)


def fetch_cve(cve_id, max_retries=3):
    cache = load_cache()
    if cve_id in cache:
        return cache[cve_id]
    url = f"{NVD_API_BASE}?cveId={cve_id}"
    for attempt in range(max_retries):
        try:
            time.sleep(0.35)
            req = urllib.request.Request(url, headers={"User-Agent": "APOLLO/3.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                if "vulnerabilities" in data and data["vulnerabilities"]:
                    vuln = data["vulnerabilities"][0]["cve"]
                    metrics = vuln.get("metrics", {})
                    cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
                    cvss_v3 = metrics.get("cvssMetricV3", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV3") else {}
                    cvss_data = cvss_v31 or cvss_v3
                    # Extract CPE matches for software identification
                    cpe_nodes = []
                    for conf in vuln.get("configurations", []):
                        for node in conf.get("nodes", []):
                            for cpe_match in node.get("cpeMatch", []):
                                criteria = cpe_match.get("criteria", "")
                                if criteria:
                                    cpe_nodes.append(criteria)
                    result = {
                        "id": cve_id,
                        "description": vuln.get("descriptions", [{}])[0].get("value", "") if vuln.get("descriptions") else "",
                        "cvss": cvss_data.get("baseScore"),
                        "severity": cvss_data.get("baseSeverity", "").lower(),
                        "vector": cvss_data.get("vectorString", ""),
                        "published": vuln.get("published", ""),
                        "lastModified": vuln.get("lastModified", ""),
                        "references": [r.get("url") for r in vuln.get("references", [])[:5]],
                        "weaknesses": [w.get("description", [{}])[0].get("value", "") for w in vuln.get("weaknesses", []) if w.get("description")],
                        "cpe_matches": list(set(cpe_nodes[:10])),
                    }
                    # Check CISA KEV
                    kev = load_kev()
                    result["in_kev"] = cve_id.upper() in kev
                    result["kev_data"] = kev.get(cve_id.upper(), {})
                    # Fetch EPSS
                    result["epss"] = fetch_epss(cve_id)
                    cache[cve_id] = result
                    save_cache(cache)
                    return result
                return {"id": cve_id, "error": "No data"}
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < max_retries - 1:
                backoff = 2 ** (attempt + 1)
                sys.stderr.write(f"[APOLLO] Rate limited on {cve_id}, retry in {backoff}s...\n")
                time.sleep(backoff)
                continue
            return {"id": cve_id, "error": f"HTTP {e.code}"}
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            return {"id": cve_id, "error": str(e)}
    return {"id": cve_id, "error": "Max retries"}


def load_kev():
    """Load CISA KEV catalog (from cache or fetch)."""
    try:
        with open(KEV_CACHE_FILE) as f:
            data = json.load(f)
            age = (time.time() - data.get("fetched", 0))
            if age < 86400:  # 24h cache
                return data.get("kev", {})
    except Exception:
        pass
    try:
        with urllib.request.urlopen(KEV_URL, timeout=15) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
        kev = {}
        for line in content.split("\n")[1:]:
            parts = line.split(",")
            if len(parts) >= 2:
                cve = parts[0].strip().upper()
                if cve.startswith("CVE-"):
                    kev[cve] = {
                        "vendor": parts[1].strip() if len(parts) > 1 else "",
                        "product": parts[2].strip() if len(parts) > 2 else "",
                        "action": parts[5].strip() if len(parts) > 5 else "",
                    }
        with open(KEV_CACHE_FILE, "w") as f:
            json.dump({"fetched": time.time(), "kev": kev}, f)
        return kev
    except Exception:
        return {}


def fetch_epss(cve_id):
    """Fetch EPSS (Exploit Prediction Scoring System) score."""
    try:
        url = f"{EPSS_API}?cve={cve_id}"
        req = urllib.request.Request(url, headers={"User-Agent": "APOLLO/3.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            epss_data = data.get("data", [{}])[0]
            return {"score": epss_data.get("epss"), "percentile": epss_data.get("percentile")}
    except Exception:
        return {"score": None, "percentile": None}


def auto_enrich_kb(project_id=None):
    """Auto-enrich all KB vulnerabilities with CVSS, CPE, KEV, EPSS."""
    project_id = project_id or get_project_id()
    vulns = get_vulnerabilities(project_id)
    enriched = 0
    for v in vulns:
        cve = v.get("cve_id", "")
        if not cve:
            continue
        data = fetch_cve(cve)
        if data and data.get("cvss") and not v.get("cvss"):
            conn = get_connection()
            conn.execute("UPDATE vulnerabilities SET cvss=?, description=? WHERE id=?",
                        (data["cvss"], (data.get("description", "") or "")[:500], v["id"]))
            conn.commit()
            if data.get("in_kev"):
                conn.execute("UPDATE vulnerabilities SET severity='critical' WHERE id=? AND severity NOT IN ('critical')",
                            (v["id"],))
                conn.commit()
            enriched += 1
    create_event(project_id, "cve_enrich", "nvd_enricher",
                 f"Enriched {enriched} CVEs", {"enriched": enriched}, "info")
    return {"enriched": enriched}


def search_cve(query, limit=10):
    """Search CVEs by keyword via NVD API."""
    url = f"{NVD_API_BASE}?keywordSearch={urllib.parse.quote(query)}&resultsPerPage={limit}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "APOLLO/3.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            results = []
            for v in data.get("vulnerabilities", []):
                cve = v.get("cve", {})
                cid = cve.get("id", "")
                desc = cve.get("descriptions", [{}])[0].get("value", "")[:200]
                metrics = cve.get("metrics", {})
                cvss = None
                for mtype in ["cvssMetricV31", "cvssMetricV3", "cvssMetricV2"]:
                    m = metrics.get(mtype, [])
                    if m:
                        cvss = m[0].get("cvssData", {}).get("baseScore")
                        break
                results.append({"id": cid, "description": desc, "cvss": cvss})
            return results
    except Exception as e:
        return [{"error": str(e)}]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("APOLLO NVD Enricher v2")
        print("Usage:")
        print(f"  {sys.argv[0]} fetch <CVE-ID>              - Fetch single CVE")
        print(f"  {sys.argv[0]} search <keyword> [limit]    - Search CVEs")
        print(f"  {sys.argv[0]} enrich-all [project]        - Enrich all KB CVEs")
        print(f"  {sys.argv[0]} kev                         - Sync CISA KEV catalog")
        sys.exit(0)
    action = sys.argv[1]
    if action == "fetch":
        print(json.dumps(fetch_cve(sys.argv[2]), indent=2, default=str))
    elif action == "search":
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 10
        print(json.dumps(search_cve(sys.argv[2], limit), indent=2))
    elif action == "enrich-all":
        pid = get_project_id(sys.argv[2]) if len(sys.argv) > 2 else get_project_id()
        print(json.dumps(auto_enrich_kb(pid), indent=2, default=str))
    elif action == "kev":
        kev = load_kev()
        print(f"CISA KEV catalog: {len(kev)} entries")
        for cve, info in list(kev.items())[:10]:
            print(f"  {cve}: {info.get('vendor')} / {info.get('product')}")
    else:
        print(f"Unknown action: {action}")
