#!/usr/bin/env python3
"""
APOLLO Naabu Wrapper v1 - Port scanning, KB injection, exploit mapping.
"""
import sys, os, json, subprocess, re
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tool_registry import get_binary, is_available
from kb_manager import get_active_project, get_project_id, add_host, add_port, create_event, add_vulnerability

PORT_EXPLOIT_MAP = {
    21:    ["Anonymous FTP", "FTP Brute Force"],
    22:    ["SSH Brute Force", "SSH Default Credentials"],
    23:    ["Telnet Brute Force", "Telnet Default Creds"],
    25:    ["SMTP User Enum", "SMTP Relay Check"],
    53:    ["DNS Zone Transfer", "DNS Cache Snooping"],
    80:    ["Web Recon", "Directory Bruteforce", "HTTP Methods"],
    110:   ["POP3 Brute Force"],
    111:   ["RPC Portmap Enum", "rpcinfo"],
    135:   ["MSRPC Enum", "MSRPC Exploit"],
    139:   ["SMB Null Session", "SMB Share Enum"],
    143:   ["IMAP Brute Force"],
    389:   ["LDAP Anonymous Bind", "LDAP Enum"],
    443:   ["SSL Scan", "Web Recon"],
    445:   ["SMB Enum", "EternalBlue MS17-010", "Zerologon"],
    465:   ["SMTP Relay Check"],
    500:   ["IKE Enum", "VPN Enum"],
    502:   ["Modbus Enum", "PLC Scan"],
    587:   ["SMTP Auth Bypass"],
    593:   ["MSRPC over HTTP Enum"],
    636:   ["LDAPS Enum"],
    993:   ["IMAPS Brute Force"],
    995:   ["POP3S Brute Force"],
    1433:  ["MSSQL Brute Force", "MSSQL Default Creds"],
    1521:  ["Oracle Default Creds", "Oracle TNS Poison"],
    2049:  ["NFS Enum", "NFS Mount"],
    2082:  ["cPanel Exploit"],
    2083:  ["cPanel Exploit"],
    2181:  ["ZooKeeper Enum"],
    2375:  ["Docker Remote API", "Docker Escape"],
    2376:  ["Docker Remote API TLS", "Docker Escape"],
    3260:  ["iSCSI Enum"],
    3306:  ["MySQL Brute Force", "MySQL Default Creds"],
    3389:  ["RDP Brute Force", "BlueKeep CVE-2019-0708"],
    3632:  ["distcc Remote Exec"],
    3690:  ["SVN Enum"],
    4000:  ["Web Recon"],
    4224:  ["Default Service Check"],
    4444:  ["Metasploit Payload Detection"],
    4560:  ["Default Service Check"],
    4646:  ["Default Service Check"],
    4786:  ["Cisco Smart Install Exploit"],
    4848:  ["GlassFish Admin Console"],
    5000:  ["Docker Registry Enum", "Flask Debug"],
    5037:  ["ADB Remote"],
    5060:  ["SIP Enum", "SIP Brute Force"],
    5222:  ["XMPP Enum"],
    5432:  ["PostgreSQL Brute Force", "PostgreSQL Default Creds"],
    5555:  ["ADB Remote"],
    5601:  ["Kibana Enum"],
    5632:  ["pcAnywhere Enum"],
    5800:  ["VNC Brute Force"],
    5900:  ["VNC Brute Force", "VNC Auth Bypass"],
    5985:  ["WinRM Brute Force", "WinRM Enum"],
    5986:  ["WinRM HTTPS Brute Force"],
    6000:  ["X11 No-Auth Access"],
    6379:  ["Redis Unauthenticated", "Redis Cron RCE"],
    6667:  ["IRC Enum"],
    7001:  ["WebLogic Console", "WebLogic RCE"],
    7002:  ["WebLogic Console SSL"],
    7070:  ["Web Recon"],
    7676:  ["Web Recon"],
    8000:  ["Web Recon", "Directory Bruteforce"],
    8009:  ["AJP Ghostcat", "AJP Enum"],
    8069:  ["Odoo Exploit"],
    8080:  ["Tomcat Manager", "Jenkins Enum", "Spring Actuator"],
    8081:  ["Proxy Enum"],
    8086:  ["InfluxDB Enum"],
    8089:  ["Splunk Enum"],
    8090:  ["Web Recon"],
    8443:  ["Tomcat SSL Admin"],
    8545:  ["Ethereum RPC"],
    8649:  ["Ganglia Enum"],
    8686:  ["Web Recon"],
    8787:  ["Web Recon"],
    8834:  ["Nessus Enum"],
    8888:  ["Web Recon"],
    8983:  ["Solr RCE"],
    9000:  ["Hadoop NameNode", "Web Recon"],
    9042:  ["Cassandra Enum"],
    9090:  ["Prometheus Enum"],
    9092:  ["Kafka Enum"],
    9100:  ["JetDirect Enum"],
    9200:  ["Elasticsearch Enum"],
    9300:  ["Elasticsearch Cluster"],
    9418:  ["Git Enum"],
    10000: ["Webmin Exploit", "Webmin RCE"],
    11211: ["Memcached Enum"],
    27017: ["MongoDB Enum", "MongoDB Unauthenticated"],
    50070: ["Hadoop NameNode WebUI"],
    50075: ["Hadoop DataNode"],
}

PORT_CATEGORIES = {
    "web":            {80, 443, 8000, 8080, 8443, 8090, 8888, 9000, 2082, 2083,
                       4848, 5000, 7001, 7002, 7070, 8069, 8081, 8089, 8545,
                       8834, 10000, 5601, 7676, 4000, 8686, 8787, 8983},
    "database":       {1433, 1521, 3306, 5432, 6379, 9042, 9200, 9300, 27017,
                       8086, 50070, 50075},
    "remote-access":  {22, 23, 3389, 5900, 5800, 5985, 5986, 5632, 6000, 5555,
                       5037, 593},
    "file-sharing":   {21, 139, 445, 2049, 3690, 9418, 3260},
    "message-queue":  {25, 465, 587, 110, 143, 993, 995, 5060, 5222, 6667,
                       9092, 11211},
    "container":      {2375, 2376},
    "iot":            {502, 4786},
    "blockchain":     {8545},
    "monitoring":     {8649, 9100, 9090, 2181, 161},
    "other":          set(),
}


def run_port_scan(targets: str, ports: str = "top-1000", rate: int = 1000,
                  exclude_ports: str = "22,23,53,111,135,139,445") -> List[Dict]:
    binary = get_binary("naabu")
    if not binary:
        return {"error": "naabu not found", "results": []}
    cmd = [binary, "-json", "-p", ports, "-rate", str(rate)]
    if exclude_ports:
        cmd += ["-exclude-ports", exclude_ports]
    if os.path.isfile(targets):
        cmd += ["-list", targets]
    else:
        cmd += [targets]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return {"error": "naabu timed out", "results": []}
    if r.returncode != 0 and not r.stdout.strip():
        return {"error": r.stderr.strip(), "results": []}
    results = []
    for line in r.stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            results.append(obj)
        except json.JSONDecodeError:
            continue
    return {"results": results, "raw_count": len(results)}


def inject_naabu_results(project_id: int, json_lines: List[Dict]) -> Dict:
    hosts_added = 0
    ports_added = 0
    seen_hosts = {}
    for entry in json_lines:
        ip = entry.get("ip", "")
        if not ip:
            continue
        if ip not in seen_hosts:
            hid = add_host(project_id, ip, status="up")
            seen_hosts[ip] = hid
            hosts_added += 1
        else:
            hid = seen_hosts[ip]
        port = entry.get("port", 0)
        protocol = entry.get("protocol", "tcp")
        add_port(hid, port, protocol=protocol, state="open")
        ports_added += 1
    return {"hosts_added": hosts_added, "ports_added": ports_added,
            "total_hosts": len(seen_hosts)}


def smart_scan(project_id: int, targets: str, depth: str = "fast") -> Dict:
    depth_config = {
        "fast":   {"ports": "top-100", "rate": 3000},
        "normal": {"ports": "top-1000", "rate": 1000},
        "full":   {"ports": "1-65535", "rate": 500},
    }
    cfg = depth_config.get(depth, depth_config["fast"])
    scan_result = run_port_scan(targets, ports=cfg["ports"], rate=cfg["rate"])
    if "error" in scan_result and not scan_result.get("results"):
        return {"status": "error", "message": scan_result["error"]}

    results = scan_result.get("results", [])
    inject = inject_naabu_results(project_id, results)

    open_ports = [(r["ip"], r["port"], r.get("protocol", "tcp")) for r in results
                  if r.get("port")]

    nmap_results = {}
    if is_available("nmap") and open_ports:
        nmap_targets = {}
        for ip, port, proto in open_ports:
            nmap_targets.setdefault(ip, []).append(port)
        for ip, ports in nmap_targets.items():
            port_str = ",".join(str(p) for p in ports)
            try:
                nmap_cmd = ["nmap", "-sV", "-p", port_str, ip]
                nr = subprocess.run(nmap_cmd, capture_output=True, text=True,
                                   timeout=600)
                nmap_results[ip] = parse_nmap_service_version(nr.stdout)
            except subprocess.TimeoutExpired:
                nmap_results[ip] = "timed out"

    return {
        "status": "complete",
        "depth": depth,
        "targets": targets,
        "ports_scanned": cfg["ports"],
        "rate": cfg["rate"],
        "open_ports_found": len(open_ports),
        "injection": inject,
        "nmap_service_scan": nmap_results,
    }


def parse_nmap_service_version(nmap_output: str) -> List[Dict]:
    services = []
    port_pattern = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.+)$")
    for line in nmap_output.split("\n"):
        m = port_pattern.match(line)
        if m:
            port = int(m.group(1))
            proto = m.group(2)
            svc = m.group(3)
            ver = m.group(4).strip() if m.group(4) else ""
            services.append({"port": port, "protocol": proto,
                            "service": svc, "version": ver})
    return services


def port_exploit_map(port: int, service: str = None) -> List[str]:
    if port in PORT_EXPLOIT_MAP:
        return PORT_EXPLOIT_MAP[port]
    if service:
        sl = service.lower()
        port_svc_map = {
            "http": [80, 443, 8080, 8443],
            "https": [443, 8443],
            "mysql": [3306],
            "postgresql": [5432],
            "mssql": [1433],
            "smb": [139, 445],
            "ssh": [22],
            "ftp": [21],
            "redis": [6379],
            "mongodb": [27017],
            "docker": [2375, 2376],
        }
        for svc_name, ports in port_svc_map.items():
            if svc_name in sl:
                return PORT_EXPLOIT_MAP.get(ports[0], [])
    return []


def classify_ports(ports_list: List[Tuple[int, str]]) -> Dict[str, List[int]]:
    classified = {cat: [] for cat in PORT_CATEGORIES}
    seen_ports = {cat: set() for cat in PORT_CATEGORIES}
    for port, protocol in ports_list:
        placed = False
        for cat, port_set in PORT_CATEGORIES.items():
            if port in port_set and port not in seen_ports[cat]:
                classified[cat].append(port)
                seen_ports[cat].add(port)
                placed = True
                break
        if not placed and port not in seen_ports["other"]:
            classified["other"].append(port)
            seen_ports["other"].add(port)
    return classified


def attack_surface_summary(project_id: int) -> Dict:
    from kb_manager import get_connection
    conn = get_connection()
    hosts = conn.execute(
        "SELECT h.id, h.ip, h.hostname, h.os FROM hosts h WHERE h.project_id=?",
        (project_id,)).fetchall()
    host_ids = [h["id"] for h in hosts]
    summary = {
        "total_hosts": len(hosts),
        "total_ports": 0,
        "categories": {},
        "high_value_targets": [],
        "exploit_opportunities": [],
    }
    high_value_cats = {"database", "container", "remote-access"}
    all_ports_raw = []
    host_port_map = {}
    host_ip_map = {h["id"]: h["ip"] for h in hosts}
    for hid in host_ids:
        rows = conn.execute(
            "SELECT port, protocol, service FROM ports WHERE host_id=?",
            (hid,)).fetchall()
        ports_for_host = []
        for r in rows:
            all_ports_raw.append((r["port"], r["protocol"]))
            ports_for_host.append((r["port"], r["protocol"], r["service"]))
        host_port_map[hid] = ports_for_host
    conn.close()

    classified = classify_ports([(p, proto) for p, proto, _ in
                                 [x for host_ports in host_port_map.values()
                                  for x in host_ports]])
    summary["categories"] = {
        cat: {"count": len(ports), "ports": sorted(ports)}
        for cat, ports in classified.items() if ports
    }
    summary["total_ports"] = len(all_ports_raw)

    for hid, ports in host_port_map.items():
        ip = host_ip_map.get(hid, "unknown")
        port_nums = [p for p, _, _ in ports]
        hvc = [c for c in high_value_cats
               if classified.get(c, []) and any(p in PORT_CATEGORIES[c]
                for p in port_nums)]
        if hvc:
            summary["high_value_targets"].append({
                "ip": ip, "host_id": hid,
                "high_value_categories": hvc,
                "ports": port_nums,
            })

    seen_opps = set()
    for hid, ports in host_port_map.items():
        ip = host_ip_map.get(hid, "unknown")
        for port, proto, service in ports:
            exploits = port_exploit_map(port, service)
            if exploits:
                key = (ip, port)
                if key not in seen_opps:
                    seen_opps.add(key)
                    summary["exploit_opportunities"].append({
                        "ip": ip,
                        "port": port,
                        "protocol": proto,
                        "service": service or "unknown",
                        "exploits": exploits,
                    })

    return summary


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 naabu_wrapper.py scan <target> [depth]")
        sys.exit(1)
    action = sys.argv[1]
    if action == "scan":
        target = sys.argv[2] if len(sys.argv) > 2 else None
        depth = sys.argv[3] if len(sys.argv) > 3 else "fast"
        if not target:
            print("Error: target required")
            sys.exit(1)
        project_name = get_active_project()
        pid = get_project_id(project_name)
        result = smart_scan(pid, target, depth)
        print(json.dumps(result, indent=2))
    else:
        print(f"Unknown action: {action}")
        sys.exit(1)
