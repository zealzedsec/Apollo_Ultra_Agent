#!/usr/bin/env python3
"""
APOLLO Report Generator v2 - Markdown + PDF with exec summary, risk scoring, MITRE.
"""
import sys, os
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import *

try:
    from apollo_core.models import normalize_severity as _norm_sev
    _CORE_AVAILABLE = True
except Exception:  # pragma: no cover - report still renders without core
    _CORE_AVAILABLE = False


def _sev_key(sev):
    """Canonical severity key tolerant of any tool's spelling/casing."""
    if _CORE_AVAILABLE:
        return _norm_sev(sev).value
    return str(sev or "low").lower()

MITRE_MAPPING = {
    "recon": {"T1595": "Active Scanning", "T1592": "Gather Victim Host Information", "T1589": "Gather Victim Identity Information", "T1590": "Gather Victim Network Information"},
    "scan": {"T1046": "Network Service Discovery", "T1040": "Network Sniffing"},
    "exploit": {"T1190": "Exploit Public-Facing Application", "T1210": "Exploitation of Remote Services", "T1203": "Exploitation for Client Execution"},
    "credential": {"T1110": "Brute Force", "T1558": "Steal or Forge Kerberos Tickets", "T1003": "OS Credential Dumping"},
    "persist": {"T1543": "Create or Modify System Process", "T1053": "Scheduled Task/Job", "T1098": "Account Manipulation"},
    "privesc": {"T1548": "Abuse Elevation Control Mechanism", "T1068": "Exploitation for Privilege Escalation"},
    "c2": {"T1071": "Application Layer Protocol", "T1573": "Encrypted Channel", "T1090": "Proxy"},
    "exfil": {"T1041": "Exfiltration Over C2 Channel", "T1567": "Exfiltration Over Web Service"}
}

SEVERITY_COLORS = {"critical": "#FF0000", "high": "#FF6600", "medium": "#FFCC00", "low": "#33CC33", "info": "#3366FF"}

def _compute_risk_score(vulns):
    if not vulns:
        return 0, "None"
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
    total = sum(weights.get(_sev_key(v.get("severity", "low")), 0) for v in vulns)
    max_possible = len(vulns) * 10
    pct = (total / max_possible * 100) if max_possible else 0
    if pct >= 30: return round(pct, 1), "Critical"
    if pct >= 15: return round(pct, 1), "High"
    if pct >= 5: return round(pct, 1), "Medium"
    return round(pct, 1), "Low"

def _try_pdf_via_fpdf(report_md, output_path):
    try:
        from fpdf import FPDF
    except ImportError:
        try:
            os.system("pip install fpdf2 -q")
            from fpdf import FPDF
        except:
            return False
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Courier", size=7)
    # Extract plain text from markdown, render as monospace
    lines = report_md.split("\n")
    for line in lines:
        clean = line.replace("**", "").replace("__", "").replace("###", "").replace("##", "").replace("#", "").strip()
        if not clean:
            pdf.ln(2)
            continue
        try:
            pdf.cell(0, 4, clean, new_x="LMARGIN", new_y="NEXT")
        except:
            pass
    try:
        pdf.output(output_path.replace(".md", ".pdf"))
        return True
    except:
        return False

def generate_report(project_id, output_path=None, format="md"):
    init_db()
    conn = get_connection()
    try:
        proj = conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if not proj: return "Error: Project not found."
        proj = dict(proj)
        hosts = [dict(r) for r in conn.execute("SELECT * FROM hosts WHERE project_id=?", (project_id,))]
        vulns = [dict(r) for r in conn.execute("""SELECT v.*, h.ip, h.hostname, p.port, p.service
            FROM vulnerabilities v JOIN hosts h ON v.host_id = h.id
            LEFT JOIN ports p ON v.port_id = p.id WHERE h.project_id=? ORDER BY
            CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END""", (project_id,))]
        from kb_manager import get_credentials as _get_creds
        creds = _get_creds(project_id)
        sessions = [dict(r) for r in conn.execute("""SELECT c2.*, h.ip FROM c2_sessions c2 JOIN hosts h ON c2.host_id=h.id WHERE h.project_id=?""", (project_id,))]

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulns:
            s = v.get("severity", "medium").lower()
            if s in sev_counts: sev_counts[s] += 1

        risk_score, risk_level = _compute_risk_score(vulns)

        report = f"""# APOLLO ULTRA V4 - Penetration Test Report

**Project:** {proj['name']}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}
**Scope:** {proj.get('scope', 'Not specified')}
**Risk Score:** {risk_score}/100 ({risk_level})

---

## Executive Summary

A comprehensive security assessment was conducted against **{len(hosts)}** host(s) in project "{proj['name']}".
A total of **{len(vulns)}** vulnerabilities were identified with an overall risk rating of **{risk_level}** ({risk_score}/100).
"""
        for sev, cnt in sev_counts.items():
            if cnt > 0: report += f"- **{sev.upper()}**: {cnt}\n"

        report += f"\n**{len(sessions)}** C2 sessions were established during testing.\n"
        report += f"**{len(creds)}** credentials were discovered or cracked.\n"

        report += "\n## Scope\n\n**Targets:**\n"
        for h in hosts:
            report += f"- {h['ip']} ({h.get('hostname', 'unknown')}) - {h.get('os', 'unknown OS')} - Status: {h.get('status', 'unknown')}\n"

        report += "\n## Key Findings\n\n"
        crit_high = [v for v in vulns if v.get("severity", "").lower() in ("critical", "high")]
        if crit_high:
            report += "### Critical & High Severity\n\n"
            for v in crit_high:
                report += f"- **[!] {v['name']}** | Severity: **{v['severity'].upper()}** | Host: {v.get('ip', '')}\n"
                if v.get("port"): report += f"  - Port: {v['port']}/{v.get('service', '?')}\n"
                if v.get("cve_id"): report += f"  - CVE: {v['cve_id']}\n"
                if v.get("mitre_id"): report += f"  - MITRE: {v['mitre_id']}\n"
                if v.get("evidence"): report += f"  - Evidence: {v['evidence'][:300]}\n"
                report += "\n"

        med_low = [v for v in vulns if v.get("severity", "").lower() in ("medium", "low", "info")]
        if med_low:
            report += "### Medium & Low Severity\n\n"
            for v in med_low:
                report += f"- {v['name']} | {v['severity'].upper()} | {v.get('ip', '')}"
                if v.get("cve_id"): report += f" | {v['cve_id']}"
                report += "\n"

        if creds:
            report += "\n## Credentials Discovered\n\n"
            for c in creds:
                pw = c.get("password", "[hash]")[:30]
                report += f"- {c.get('ip', '')} | {c.get('service', '')} | {c.get('username', '')}:{pw}\n"

        if sessions:
            report += "\n## C2 Sessions\n\n"
            report += "| IP | Type | Privilege | Status |\n"
            report += "|----|------|-----------|--------|\n"
            for s in sessions:
                report += f"| {s.get('ip', '')} | {s.get('session_type', '')} | {s.get('privilege', '')} | {s.get('status', '')} |\n"

        report += "\n## MITRE ATT&CK Techniques\n\n"
        used_ttps = {}
        for v in vulns:
            mid = v.get("mitre_id", "")
            if mid: used_ttps[mid] = used_ttps.get(mid, 0) + 1
        for tid, count in sorted(used_ttps.items()):
            report += f"- {tid} - {count} finding(s)\n"
        if not used_ttps:
            report += "- No MITRE techniques mapped.\n"

        report += "\n## Attack Chain Timeline (Last 50 Commands)\n\n"
        logs = [dict(r) for r in conn.execute("""SELECT * FROM commands_log WHERE project_id=? ORDER BY executed_at DESC LIMIT 50""", (project_id,))]
        logs.reverse()
        for log in logs:
            cmd = log.get('command', '')[:80]
            report += f"- [{log.get('executed_at', '')}] {cmd}\n"

        report += "\n## Recommendations\n\n"
        if crit_high:
            report += "- Remediate the following critical and high severity findings as a priority:\n"
            for v in crit_high[:5]:
                report += f"  - {v['name']} on {v.get('ip', '')}\n"
            report += "- Conduct a deeper investigation of all critical findings\n"
        report += "- Rotate all compromised credentials immediately\n"
        report += "- Review network segmentation and access controls\n"
        report += "- Implement comprehensive logging and monitoring (SIEM)\n"
        report += "- Conduct regular vulnerability scanning and penetration testing\n"
        report += "- Enforce multi-factor authentication on all external services\n"

        report += "\n---\n*Report generated by APOLLO ULTRA V4 Red Team Engine*\n"

        if output_path:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, 'w') as f: f.write(report)
            print(f"Markdown report saved to: {output_path}")
            if format == "pdf":
                pdf_path = output_path.replace(".md", ".pdf")
                if _try_pdf_via_fpdf(report, output_path):
                    print(f"PDF report saved to: {pdf_path}")
                else:
                    print("PDF generation skipped (install fpdf2: pip install fpdf2)")
        else:
            print(report)
        return report
    finally:
        conn.close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="APOLLO Report Generator v2")
    parser.add_argument("project", help="Project name or ID")
    parser.add_argument("output", nargs="?", help="Output file path")
    parser.add_argument("--format", "-f", choices=["md", "pdf"], default="md", help="Output format")
    args = parser.parse_args()
    pid = int(args.project) if args.project.isdigit() else create_project(args.project)
    generate_report(pid, args.output, args.format)
