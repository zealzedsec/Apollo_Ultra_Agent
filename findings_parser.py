#!/usr/bin/env python3
"""
APOLLO Findings Parser v4 - Parse tool outputs and inject into KB.
Supports: nmap, nuclei, naabu, subfinder, hashcat, nikto, sqlmap,
nessus, openvas, sslscan, wpscan, whatweb, crackmapexec, bloodhound.
"""
import re, json, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import *

def parse_nmap(filepath):
    results = []
    current_host = None
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            m = re.match(r'^Nmap scan report for (.+?) \(([\d.]+)\)', line)
            if not m:
                m = re.match(r'^Nmap scan report for ([\d.]+)', line)
                if m: current_host = {"ip": m.group(1), "hostname": "", "ports": []}
            else: current_host = {"ip": m.group(2), "hostname": m.group(1), "ports": []}
            m2 = re.match(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.+)$', line)
            if m2 and current_host:
                current_host["ports"].append({"port": int(m2.group(1)), "protocol": m2.group(2),
                    "service": m2.group(3), "version": m2.group(4).strip()})
            if current_host and line.strip() == "" and current_host["ports"]:
                results.append(current_host); current_host = {"ip": current_host["ip"], "hostname": current_host.get("hostname", ""), "ports": []}
    if current_host and current_host.get("ports"): results.append(current_host)
    return results

def parse_nuclei(filepath):
    results = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                results.append({"host": data.get("host", data.get("ip", "")),
                    "name": data.get("info", {}).get("name", data.get("template", "")),
                    "severity": data.get("info", {}).get("severity", "medium"),
                    "extracted": data.get("extracted-results", []),
                    "matched": data.get("matched-at", ""),
                    "curl": data.get("curl-command", "")})
            except json.JSONDecodeError:
                m = re.match(r'^\[(\w+)\]\s+\[(.+?)\]\s+(.+)', line)
                if m: results.append({"severity": m.group(1), "template": m.group(2), "host": m.group(3)})
    return results

def parse_naabu(filepath):
    results = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            m = re.match(r'^([\d.]+):(\d+)', line)
            if m: results.append({"ip": m.group(1), "port": int(m.group(2))})
    return results

def parse_hashcat(filepath):
    results = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if ":" in line and not line.startswith("#"):
                parts = line.split(":")
                if len(parts) >= 2: results.append({"hash": parts[0], "password": parts[1]})
    return results

def parse_subfinder(filepath):
    results = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"): results.append(s)
    return results

def parse_nessus(filepath):
    """Parse Nessus .nessus XML or CSV output."""
    results = []
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()
    for m in re.finditer(r'<ReportHost[^>]*name="([^"]+)"', content):
        ip = m.group(1)
        host_vulns = re.finditer(
            r'<ReportItem[^>]*port="(\d+)"[^>]*svc_name="([^"]*)"[^>]*pluginID="(\d+)"[^>]*pluginName="([^"]*)"[^>]*severity="(\d+)"[^>]*>',
            content[m.end():])
        for v in host_vulns:
            sev_map = {"4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info"}
            results.append({"ip": ip, "port": v.group(1), "service": v.group(2),
                "plugin_id": v.group(3), "name": v.group(4),
                "severity": sev_map.get(v.group(5), "info")})
    return results

def parse_sslscan(filepath):
    results = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            m = re.match(r'^\s*([\d.]+):(\d+)\s+([\w\s-]+)\s+([\w\s.]+)', line)
            if m: results.append({"ip": m.group(1), "port": m.group(2), "protocol": m.group(3).strip(), "cipher": m.group(4).strip()})
    return results

def parse_wpscan(filepath):
    results = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            m = re.search(r'\[(!|\+|\*)\]\s+(.+?)(?:\s*-\s*(.+))?$', line)
            if m: results.append({"type": m.group(1), "finding": m.group(2).strip(), "detail": m.group(3).strip() if m.group(3) else ""})
    return results

def parse_whatweb(filepath):
    results = []
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()
    for m in re.finditer(r'http[s]?://([\w./-]+)\s+\[([^\]]+)\]', content):
        results.append({"url": m.group(1), "technologies": m.group(2)})
    return results

def parse_crackmapexec(filepath):
    results = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            m = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+(\w+)\s+\(([^)]+)\)', line)
            if m: results.append({"ip": m.group(1), "status": m.group(2), "info": m.group(3)})
    return results

def parse_nikto(filepath):
    results = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            m = re.search(r'\+ (OSVDB-\d+: )?(.+)', line)
            if m: results.append({"finding": m.group(2).strip()})
    return results

def inject_into_kb(project_id, tool, parsed_data):
    pid = project_id if project_id else get_project_id()
    injected = {"hosts": 0, "ports": 0, "vulns": 0, "creds": 0}
    if tool == "nmap":
        for host in parsed_data:
            hid = add_host(pid, host["ip"], host.get("hostname", ""))
            injected["hosts"] += 1
            for p in host["ports"]:
                add_port(hid, p["port"], p.get("protocol", "tcp"), p["service"], p.get("version", ""))
                injected["ports"] += 1
    elif tool == "nuclei":
        for vuln in parsed_data:
            hostname = vuln.get("host", "")
            ip_match = re.search(r'[\d.]+', hostname)
            ip = ip_match.group(0) if ip_match else hostname
            hid = add_host(pid, ip, hostname)
            injected["hosts"] += 1
            sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}
            sev = sev_map.get(vuln.get("severity", "MEDIUM").upper(), vuln.get("severity", "medium").lower())
            add_vulnerability(hid, vuln.get("name", "Unknown"), sev, evidence=str(vuln.get("extracted", [])))
            injected["vulns"] += 1
    elif tool == "hashcat":
        for cred in parsed_data:
            add_credential(None, "hash", cred.get("hash", ""), cred.get("password", ""), source="hashcat")
            injected["creds"] += 1
    elif tool == "nessus":
        for v in parsed_data:
            hid = add_host(pid, v.get("ip", ""))
            injected["hosts"] += 1
            add_vulnerability(hid, v.get("name", "Nessus finding"), v.get("severity", "medium"),
                            description=f"Port {v.get('port', '')} ({v.get('service', '')}) Plugin ID: {v.get('plugin_id', '')}")
            injected["vulns"] += 1
    create_event(pid, "findings_inject", tool, f"Injected {injected} from {tool}", injected, "info")
    return injected

def parse_nmap_xml(filepath):
    """Parse nmap XML output using xml.etree."""
    import xml.etree.ElementTree as ET
    results = []
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        for host in root.findall('host'):
            ip_el = host.find(".//address[@addrtype='ipv4']")
            if ip_el is None:
                continue
            ip = ip_el.get('addr', '')
            hostname_el = host.find('.//hostname')
            hostname = hostname_el.get('name', '') if hostname_el is not None else ''
            ports = []
            for port in host.findall(".//port"):
                state_el = port.find('state')
                if state_el is not None and state_el.get('state') == 'open':
                    port_id = port.get('portid', '')
                    protocol = port.get('protocol', 'tcp')
                    service_el = port.find('service')
                    service = service_el.get('name', '') if service_el is not None else ''
                    version = service_el.get('version', '') if service_el is not None else ''
                    product = service_el.get('product', '') if service_el is not None else ''
                    banner = ''
                    script_el = port.find(".//script[@id='banner']")
                    if script_el is not None:
                        banner = script_el.get('output', '')
                    ports.append({"port": int(port_id), "protocol": protocol,
                                  "service": service, "version": f"{product} {version}".strip(),
                                  "banner": banner})
            results.append({"ip": ip, "hostname": hostname, "ports": ports})
    except Exception as e:
        return [{"error": str(e)}]
    return results


def smart_parse(filepath, tool_hint=""):
    if not os.path.exists(filepath):
        return {"tool": tool_hint, "error": f"File not found: {filepath}", "results": []}
    tool_hint_lower = tool_hint.lower()
    ext = os.path.splitext(filepath)[1].lower()
    if tool_hint_lower == "nmap" or "nmap" in filepath.lower():
        data = parse_nmap_xml(filepath) or parse_nmap(filepath)
    elif tool_hint_lower == "nuclei" or "nuclei" in filepath.lower():
        data = parse_nuclei(filepath)
    elif tool_hint_lower == "naabu" or "naabu" in filepath.lower():
        data = parse_naabu(filepath)
    elif tool_hint_lower == "hashcat" or "hashcat" in filepath.lower():
        data = parse_hashcat(filepath)
    elif tool_hint_lower == "subfinder" or "subfinder" in filepath.lower():
        data = parse_subfinder(filepath)
    elif tool_hint_lower == "nessus" or "nessus" in filepath.lower() or ext == ".nessus":
        data = parse_nessus(filepath)
    elif tool_hint_lower == "sslscan" or "sslscan" in filepath.lower():
        data = parse_sslscan(filepath)
    elif tool_hint_lower == "wpscan" or "wpscan" in filepath.lower():
        data = parse_wpscan(filepath)
    elif tool_hint_lower == "whatweb" or "whatweb" in filepath.lower():
        data = parse_whatweb(filepath)
    elif tool_hint_lower == "crackmapexec" or "crackmapexec" in filepath.lower():
        data = parse_crackmapexec(filepath)
    elif tool_hint_lower == "nikto" or "nikto" in filepath.lower():
        data = parse_nikto(filepath)
    else:
        data = parse_nmap_xml(filepath) or parse_nmap(filepath) or parse_nuclei(filepath) or []

    return {"tool": tool_hint, "results": data}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        tool = sys.argv[2] if len(sys.argv) > 2 else ""
        result = smart_parse(sys.argv[1], tool)
        print(json.dumps(result, indent=2, default=str))
    else:
        print("Usage: findings_parser.py <file> <tool_hint>")
        print("Tool hints: nmap, nuclei, naabu, hashcat, subfinder, nessus, sslscan, wpscan, whatweb, crackmapexec, nikto")
