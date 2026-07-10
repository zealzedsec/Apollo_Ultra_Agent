#!/usr/bin/env python3
"""
APOLLO Findings Correlator v2 - Cross-tool correlation, auto-triage, priority scoring.
Groups findings by host+service, scores attack priority, suggests next actions.
"""
import sys, os, json, re
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import *
from findings_parser import smart_parse

SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}

def auto_triage(project_id):
    """Analyze KB data, compute per-host priority scores, suggest next actions."""
    conn = get_connection()
    try:
        hosts = [dict(r) for r in conn.execute("SELECT * FROM hosts WHERE project_id=?", (project_id,))]
        vulns_all = [dict(r) for r in conn.execute("""
            SELECT v.*, h.ip FROM vulnerabilities v
            JOIN hosts h ON v.host_id = h.id WHERE h.project_id=?""", (project_id,))]
        creds_all = [dict(r) for r in get_credentials(project_id)]
        sessions = [dict(r) for r in conn.execute("""
            SELECT s.*, h.ip FROM c2_sessions s JOIN hosts h ON s.host_id=h.id
            WHERE h.project_id=? AND s.status='active'""", (project_id,))]
        paths = [dict(r) for r in conn.execute("""
            SELECT * FROM attack_paths WHERE project_id=?""", (project_id,))]
        ports_all = [dict(r) for r in conn.execute("""
            SELECT p.*, h.ip FROM ports p JOIN hosts h ON p.host_id=h.id
            WHERE h.project_id=?""", (project_id,))]

        host_analysis = []
        for h in hosts:
            ip = h["ip"]
            host_vulns = [v for v in vulns_all if v.get("ip") == ip]
            host_creds = [c for c in creds_all if c.get("ip") == ip]
            host_sessions = [s for s in sessions if s.get("ip") == ip]
            host_ports = [p for p in ports_all if p.get("ip") == ip]

            vuln_score = sum(SEVERITY_WEIGHTS.get(v.get("severity", "info").lower(), 0) for v in host_vulns)
            cred_score = len(host_creds) * 3
            session_score = len(host_sessions) * 5
            port_score = len(host_ports)
            has_high_value_port = any(p.get("port") in (445, 3389, 22, 5985, 5986, 1433, 3306, 5432, 6379, 9200, 27017)
                                      for p in host_ports)
            if has_high_value_port:
                port_score += 5

            priority = vuln_score + cred_score + session_score + port_score
            priority_label = "critical" if priority >= 15 else "high" if priority >= 10 else "medium" if priority >= 5 else "low"

            suggestions = []
            if host_vulns:
                top_vuln = max(host_vulns, key=lambda v: SEVERITY_WEIGHTS.get(v.get("severity", "info").lower(), 0))
                if top_vuln.get("cve_id"):
                    suggestions.append(f"Try auto_pwn against {ip} ({top_vuln['name']})")
            if host_creds and not host_sessions:
                suggestions.append(f"Use credentials on {ip} to establish C2 session")
            if host_sessions:
                suggestions.append(f"Active session on {ip} - run privesc/pivot")
            if not suggestions:
                if host_ports:
                    suggestions.append(f"Scan {ip} with nuclei for vuln discovery")
                else:
                    suggestions.append(f"Port-scan {ip} for service discovery")

            host_analysis.append({
                "ip": ip,
                "hostname": h.get("hostname", ""),
                "os": h.get("os", ""),
                "priority_score": priority,
                "priority_label": priority_label,
                "vuln_count": len(host_vulns),
                "cred_count": len(host_creds),
                "active_sessions": len(host_sessions),
                "port_count": len(host_ports),
                "has_high_value_ports": has_high_value_port,
                "suggestions": suggestions
            })

        host_analysis.sort(key=lambda x: x["priority_score"], reverse=True)

        global_suggestions = []
        active_ips = {s["ip"] for s in sessions}
        compromised = set()
        for s in sessions:
            compromised.add(s["ip"])
            for p in paths:
                if p.get("source_host") == s["ip"]:
                    compromised.add(p.get("target_host"))
        owned = len(compromised)
        total = len(hosts) or 1
        pct_owned = (owned / total) * 100

        if owned < total:
            next_targets = [h for h in host_analysis if h["ip"] not in compromised and h["priority_label"] in ("critical", "high")]
            if next_targets:
                global_suggestions.append(f"Priority targets to compromise: {', '.join(t['ip'] for t in next_targets[:3])}")
        if len(active_ips) > 0:
            global_suggestions.append(f"Lateral movement possible from {', '.join(active_ips)}")
        if pct_owned > 75:
            global_suggestions.append(f"Network is {pct_owned:.0f}% compromised - pivot to data exfiltration phase")

        high_priority = [h for h in host_analysis if h["priority_label"] in ("critical", "high")]

        return {
            "generated": datetime.now().isoformat(),
            "total_hosts": len(hosts),
            "total_vulns": len(vulns_all),
            "total_creds": len(creds_all),
            "active_sessions": len(sessions),
            "attack_paths": len(paths),
            "compromised_pct": round(pct_owned, 1),
            "global_suggestions": global_suggestions,
            "high_priority_targets": high_priority[:5],
            "all_hosts": host_analysis
        }
    finally:
        conn.close()


def correlate(project_id, nmap_files=None, nuclei_files=None):
    conn = get_connection()
    try:
        all_vulns = []
        all_ports = []
        if nmap_files:
            for f in nmap_files.split(','):
                f = f.strip()
                parsed = smart_parse(f, "nmap")
                for host in parsed.get("results", []):
                    hid = add_host(project_id, host["ip"], host.get("hostname", ""))
                    for p in host["ports"]:
                        pid_res = add_port(hid, p["port"], p.get("protocol", "tcp"), p["service"], p.get("version", ""))
                        if p["service"].lower() in ["http", "https", "ssl|http"]:
                            proto = "https" if "ssl" in p["service"].lower() or "https" in str(p.get("version", "")).lower() else "http"
                            url = f"{proto}://{host['ip']}:{p['port']}"
                            add_vulnerability(hid, f"Web service exposed: {url}", "info", description=f"Web service on port {p['port']}")
        if nuclei_files:
            for f in nuclei_files.split(','):
                f = f.strip()
                parsed = smart_parse(f, "nuclei")
                for v in parsed.get("results", []):
                    ip = re.search(r'[\d.]+', v.get("host", ""))
                    ip_val = ip.group(0) if ip else v.get("host", "")
                    if ip_val:
                        hid = add_host(project_id, ip_val)
                        add_vulnerability(hid, v.get("name", "Unknown"),
                                          v.get("severity", "medium"),
                                          evidence=str(v.get("extracted", [])))

        triage = auto_triage(project_id)
        create_event(project_id, "correlation", "correlator",
                     f"Correlated nmap+nuclei findings", triage, "info")
        return {"status": "correlated", "project_id": project_id, "triage": triage}
    finally:
        conn.close()


if __name__ == "__main__":
    import argparse
    init_db()
    parser = argparse.ArgumentParser(description="APOLLO Correlator v2")
    parser.add_argument("--project", default=get_active_project())
    parser.add_argument("--nmap", help="Comma-separated nmap output files")
    parser.add_argument("--nuclei", help="Comma-separated nuclei output files")
    parser.add_argument("--triage", action="store_true", help="Run auto-triage on existing KB data")
    args = parser.parse_args()
    pid = create_project(args.project)
    if args.triage:
        result = auto_triage(pid)
    else:
        result = correlate(pid, args.nmap, args.nuclei)
    print(json.dumps(result, indent=2, default=str))
