#!/usr/bin/env python3
"""
APOLLO Recon Monitor v1 - Continuous monitoring daemon with diff detection.

Periodically re-scans targets and detects changes (new hosts, new ports,
new services, disappeared hosts). Alerts on changes via the notifications
module. Maintains a baseline snapshot in the KB for diffing.
"""
import sys, os, json, subprocess, time, threading, signal
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import (init_db, get_connection, get_active_project,
                        get_project_id, create_event, add_host, add_port,
                        get_hosts, add_note)
from notifications import alert

MONITOR_STATE_FILE = os.path.expanduser(
    "~/.config/opencode/apollo-engine/.monitor_state.json")
MONITOR_INTERVAL = int(os.environ.get("APOLLO_MONITOR_INTERVAL", "300"))  # 5 min


def _run_cmd(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout, executable="/bin/bash")
        return r.stdout.decode("utf-8", errors="ignore")
    except Exception as e:
        return str(e)


def scan_baseline(target, scan_type="quick"):
    """Run a scan and return a structured snapshot."""
    snapshot = {"target": target, "timestamp": datetime.utcnow().isoformat(),
                "hosts": {}, "scan_type": scan_type, "vulns": []}

    if scan_type == "quick":
        out = _run_cmd(f"nmap -sn {target} -oG - 2>/dev/null", timeout=120)
        for line in out.split("\n"):
            if "Up" in line:
                parts = line.split()
                for p in parts:
                    if p.count(".") == 3 and p.replace(".", "").isdigit():
                        snapshot["hosts"][p] = {"ports": {}}
    elif scan_type == "ports":
        out = _run_cmd(f"nmap -sV -T4 {target} -oG - 2>/dev/null", timeout=300)
        current_ip = None
        for line in out.split("\n"):
            if "Host:" in line:
                parts = line.split()
                for p in parts:
                    if p.count(".") == 3:
                        current_ip = p
                        snapshot["hosts"][current_ip] = {"ports": {}}
            elif current_ip and "Ports:" in line:
                ports_str = line.split("Ports:")[1].strip() if "Ports:" in line else ""
                for port_info in ports_str.split(","):
                    port_info = port_info.strip()
                    if "/" in port_info:
                        fields = port_info.split("/")
                        if len(fields) >= 5:
                            port = fields[0].strip()
                            state = fields[1].strip()
                            service = fields[4].strip() if len(fields) > 4 else ""
                            if state == "open":
                                snapshot["hosts"][current_ip]["ports"][port] = {
                                    "service": service, "state": state}
    elif scan_type == "vuln":
        # Nuclei scan for vulnerability monitoring
        nuclei_out = _run_cmd(f"nuclei -target {target} -severity critical,high -o /tmp/apollo_monitor_nuclei.json -json 2>&1", timeout=300)
        for line in nuclei_out.split("\n"):
            try:
                data = json.loads(line.strip())
                host = data.get("host", "")
                sev = data.get("info", {}).get("severity", "medium")
                name = data.get("info", {}).get("name", "")
                ip_match = re.search(r'[\d.]+', host)
                ip = ip_match.group(0) if ip_match else host
                if ip not in snapshot["hosts"]:
                    snapshot["hosts"][ip] = {"ports": {}}
                snapshot["vulns"].append({"ip": ip, "name": name, "severity": sev})
            except json.JSONDecodeError:
                pass
        # Also port scan
        port_out = _run_cmd(f"nmap -sn {target} -oG - 2>/dev/null", timeout=120)
        for line in port_out.split("\n"):
            if "Up" in line:
                parts = line.split()
                for p in parts:
                    if p.count(".") == 3 and p.replace(".", "").isdigit():
                        if p not in snapshot["hosts"]:
                            snapshot["hosts"][p] = {"ports": {}}
    return snapshot


def load_state():
    """Load previous monitor state."""
    try:
        with open(MONITOR_STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state):
    """Save monitor state."""
    os.makedirs(os.path.dirname(MONITOR_STATE_FILE), exist_ok=True)
    with open(MONITOR_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2, default=str)


def diff_snapshots(old, new):
    """Compare two snapshots and return changes."""
    changes = {"new_hosts": [], "gone_hosts": [], "new_ports": [],
               "gone_ports": [], "service_changes": [], "new_vulns": [],
               "gone_vulns": []}

    old_hosts = set(old.get("hosts", {}).keys())
    new_hosts = set(new.get("hosts", {}).keys())
    changes["new_hosts"] = list(new_hosts - old_hosts)
    changes["gone_hosts"] = list(old_hosts - new_hosts)

    for ip in (old_hosts & new_hosts):
        old_ports = set(old["hosts"][ip].get("ports", {}).keys())
        new_ports = set(new["hosts"][ip].get("ports", {}).keys())
        for p in (new_ports - old_ports):
            changes["new_ports"].append({"ip": ip, "port": p,
                                         "service": new["hosts"][ip]["ports"][p].get("service", "")})
        for p in (old_ports - new_ports):
            changes["gone_ports"].append({"ip": ip, "port": p})
        for p in (old_ports & new_ports):
            old_svc = old["hosts"][ip]["ports"][p].get("service", "")
            new_svc = new["hosts"][ip]["ports"][p].get("service", "")
            if old_svc != new_svc:
                changes["service_changes"].append({"ip": ip, "port": p,
                                                    "old": old_svc, "new": new_svc})

    # Vuln diff
    old_vulns = {(v["ip"], v["name"]) for v in old.get("vulns", [])}
    new_vulns = {(v["ip"], v["name"]) for v in new.get("vulns", [])}
    for ip, name in (new_vulns - old_vulns):
        changes["new_vulns"].append({"ip": ip, "name": name})
    for ip, name in (old_vulns - new_vulns):
        changes["gone_vulns"].append({"ip": ip, "name": name})
    return changes


def monitor_once(target, project_id=None, scan_type="quick"):
    """Run a single monitoring cycle: scan, diff, alert, store."""
    snapshot = scan_baseline(target, scan_type)
    state = load_state()
    old = state.get(target, {})
    changes = diff_snapshots(old, snapshot) if old else {"new_hosts": list(snapshot["hosts"].keys()),
                                                          "gone_hosts": [], "new_ports": [],
                                                          "gone_ports": [], "service_changes": []}

    state[target] = snapshot
    save_state(state)

    # Inject new hosts into KB
    if project_id:
        for ip in changes["new_hosts"]:
            add_host(project_id, ip, status="up", tags="monitor-discovered")
        for np in changes["new_ports"]:
            # find host id
            conn = get_connection()
            h = conn.execute("SELECT id FROM hosts WHERE project_id=? AND ip=?",
                            (project_id, np["ip"])).fetchone()
            if h:
                add_port(h["id"], int(np["port"]), service=np.get("service", ""))
            conn.close()

    # Alert on changes
    change_count = sum(len(v) for v in changes.values())
    if change_count > 0:
        msg = f"[MONITOR] {change_count} changes on {target}: "
        msg += f"{len(changes['new_hosts'])} new hosts, {len(changes['new_ports'])} new ports"
        if project_id:
            create_event(project_id, "monitor_change", "recon_monitor", msg, changes, "high")
        try:
            alert(msg, "high")
        except Exception:
            pass

    return {"target": target, "changes": changes, "snapshot_hosts": len(snapshot["hosts"])}


def monitor_loop(target, project_id=None, scan_type="quick", interval=None):
    """Continuous monitoring loop. Runs until interrupted."""
    interval = interval or MONITOR_INTERVAL
    project_id = project_id or get_project_id()

    print(f"[*] Starting continuous monitor on {target} (interval={interval}s)")
    cycle = 0
    while True:
        cycle += 1
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Cycle {cycle}...")
        try:
            result = monitor_once(target, project_id, scan_type)
            changes = result["changes"]
            if sum(len(v) for v in changes.values()) > 0:
                print(f"  [!] Changes detected: {json.dumps({k: len(v) for k, v in changes.items()})}")
            else:
                print(f"  [.] No changes ({result['snapshot_hosts']} hosts)")
        except Exception as e:
            print(f"  [X] Error: {e}")
        time.sleep(interval)


def monitor_daemon(targets, project_id=None, scan_type="quick", interval=None):
    """Monitor multiple targets in background threads."""
    interval = interval or MONITOR_INTERVAL
    project_id = project_id or get_project_id()
    threads = []
    for t in targets:
        th = threading.Thread(target=monitor_loop, args=(t, project_id, scan_type, interval), daemon=True)
        th.start()
        threads.append(th)
    print(f"[*] Monitoring {len(targets)} targets with {len(threads)} threads")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping monitor...")


if __name__ == "__main__":
    prog = sys.argv[0]
    if len(sys.argv) < 2:
        print("APOLLO Recon Monitor")
        print("Usage:")
        print("  " + prog + " once <target> [quick|ports] [project]  - Single scan + diff")
        print("  " + prog + " loop <target> [interval] [project]     - Continuous monitoring")
        print("  " + prog + " state                                    - Show saved state")
        print("  " + prog + " reset                                    - Clear baseline")
        sys.exit(0)
    action = sys.argv[1]
    if action == "once":
        target = sys.argv[2]
        stype = sys.argv[3] if len(sys.argv) > 3 else "quick"
        pid = get_project_id(sys.argv[4]) if len(sys.argv) > 4 else get_project_id()
        print(json.dumps(monitor_once(target, pid, stype), indent=2, default=str))
    elif action == "loop":
        target = sys.argv[2]
        interval = int(sys.argv[3]) if len(sys.argv) > 3 else MONITOR_INTERVAL
        pid = get_project_id(sys.argv[4]) if len(sys.argv) > 4 else get_project_id()
        monitor_loop(target, pid, "quick", interval)
    elif action == "state":
        print(json.dumps(load_state(), indent=2, default=str))
    elif action == "reset":
        save_state({})
        print("Monitor state cleared.")
    else:
        print(f"Unknown action: {action}")
