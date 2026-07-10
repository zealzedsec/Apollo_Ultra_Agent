#!/usr/bin/env python3
"""
APOLLO Attack Planner - Reads knowledge base and generates attack plans
using Cyber Kill Chain methodology with MITRE ATT&CK mapping.
"""
import sys
import os
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import *

KILL_CHAIN_PHASES = {
    1: {"name": "Reconnaissance", "actions": [
        "Enumerate subdomains with subfinder and amass",
        "Gather OSINT with theHarvester and crt.sh",
        "Identify live hosts with httpx",
        "Visual recon with gowitness"
    ]},
    2: {"name": "Weaponization", "actions": [
        "Search for relevant exploits with searchsploit",
        "Generate custom payloads with msfvenom",
        "Prepare phishing templates if email vector available"
    ]},
    3: {"name": "Delivery", "actions": [
        "Deploy payloads via web delivery or exploitation",
        "Use Metasploit exploits against vulnerable services",
        "Password spraying with crackmapexec if creds available"
    ]},
    4: {"name": "Exploitation", "actions": [
        "Execute exploit modules against vulnerable services",
        "SQL injection via sqlmap on web applications",
        "Upload webshells through vulnerable upload endpoints"
    ]},
    5: {"name": "Installation", "actions": [
        "Establish persistence via scheduled tasks or cron",
        "Install backdoor via WMI or SSH authorized_keys",
        "Deploy C2 agent (Sliver, Covenant, or Metasploit)"
    ]},
    6: {"name": "Command & Control", "actions": [
        "Establish C2 channel via DNS, HTTPS, or SMB",
        "Maintain persistent access with beaconing",
        "Pivot to internal networks through compromised hosts"
    ]},
    7: {"name": "Actions on Objectives", "actions": [
        "Dump credentials with impacket secretsdump",
        "Lateral movement with crackmapexec and wmiexec",
        "Exfiltrate sensitive data",
        "Cover tracks and clean up evidence"
    ]}
}

def analyze_kb(project_id):
    conn = get_connection()
    try:
        hosts = [dict(r) for r in conn.execute("SELECT * FROM hosts WHERE project_id=?", (project_id,))]
        vulns = [dict(r) for r in conn.execute("""SELECT v.*, h.ip FROM vulnerabilities v
            JOIN hosts h ON v.host_id = h.id WHERE h.project_id=?""", (project_id,))]
        creds = [dict(r) for r in conn.execute("""SELECT c.*, h.ip FROM credentials c
            JOIN hosts h ON c.host_id = h.id WHERE h.project_id=?""", (project_id,))]
        ports = []
        for h in hosts:
            hp = [dict(r) for r in conn.execute("SELECT * FROM ports WHERE host_id=?", (h['id'],))]
            ports.extend(hp)
        return hosts, vulns, creds, ports
    finally:
        conn.close()

def generate_plan(project_id):
    init_db()
    hosts, vulns, creds, ports = analyze_kb(project_id)
    
    plan = f"# APOLLO Attack Plan - {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
    plan += f"## Current Intelligence\n\n"
    plan += f"**Hosts:** {len(hosts)}\n"
    plan += f"**Vulnerabilities:** {len(vulns)}\n"
    plan += f"**Credentials:** {len(creds)}\n"
    plan += f"**Open Ports:** {len(ports)}\n\n"
    
    plan += "## Attack Path Analysis\n\n"
    if hosts:
        plan += f"### Priority Targets\n\n"
        sorted_vulns = sorted(vulns, key=lambda v: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(v.get("severity", "").lower(), 4))
        seen_ips = set()
        for v in sorted_vulns:
            ip = v.get("ip", "")
            if ip and ip not in seen_ips:
                host = next((h for h in hosts if h.get("ip") == ip), None)
                host_ports = [p for p in ports if p.get("host_id") == (host.get("id") if host else None)]
                vuln_count = len([x for x in vulns if x.get("ip") == ip])
                plan += f"- **{ip}** ({vuln_count} vulns, {len(host_ports)} open ports)\n"
                seen_ips.add(ip)
        plan += "\n"
    
    plan += f"## Cyber Kill Chain Plan\n\n"
    
    phase = max(1, min(7, 2 if hosts else 1, 3 if vulns else 2, 5 if creds else 3))
    
    for i in range(phase, 8):
        ph = KILL_CHAIN_PHASES[i]
        plan += f"### Phase {i}: {ph['name']}\n\n"
        for action in ph['actions']:
            plan += f"- [ ] {action}\n"
        plan += "\n"
    
    if creds:
        plan += f"## Credentials Available\n\n"
        for c in creds:
            plan += f"- {c.get('ip', '')} | {c.get('username', '')}:{c.get('password', '[hash]')}\n"
        plan += "\n"
    
    plan += "## Recommended First Action\n\n"
    if not hosts:
        plan += "Run `/recon <target>` to begin reconnaissance.\n"
    elif not vulns:
        plan += "Run `/scan <target>` to identify vulnerabilities.\n"
    elif not creds:
        plan += "Run `/exploit` or `/crack` to attempt exploitation.\n"
    else:
        plan += "Run `/c2` to establish persistence and `/exfil` to extract data.\n"
    
    return plan

if __name__ == "__main__":
    if len(sys.argv) > 1:
        pid = int(sys.argv[1]) if sys.argv[1].isdigit() else create_project(sys.argv[1])
        print(generate_plan(pid))
    else:
        p = get_active_project()
        pid = create_project(p)
        print(generate_plan(pid))
