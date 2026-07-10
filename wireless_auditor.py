#!/usr/bin/env python3
"""
APOLLO Wireless Security Auditor - WiFi network scanning,
WPA/WPA2 audit, handshake capture, deauth detection.
"""
import sys, os, json, subprocess, re, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import *

def check_tools():
    """Check if wireless tools are available."""
    tools = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "iwconfig", "iw"]
    available = {}
    for tool in tools:
        available[tool] = subprocess.run(["which", tool], capture_output=True).returncode == 0
    return available

def _check_sudo():
    """Check if running with sudo/root privileges."""
    if os.geteuid() != 0:
        return False, "Wireless operations require root. Run with: sudo python3 wireless_auditor.py"
    return True, ""

def scan_networks(interface="wlan0", timeout=15):
    """Scan for wireless networks."""
    has_sudo, msg = _check_sudo()
    if not has_sudo:
        return {"error": msg}
    temp_dir = tempfile.mkdtemp(prefix="apollo_wifi_")
    cleanup_done = False
    try:
        start_result = subprocess.run(["sudo", "airmon-ng", "start", interface],
                      capture_output=True, timeout=10)
        mon_if = f"{interface}mon"
        proc = subprocess.Popen(
            ["sudo", "airodump-ng", mon_if, "-w", os.path.join(temp_dir, "scan"), "--output-format", "csv"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        import time; time.sleep(timeout)
        proc.terminate()
        proc.wait(timeout=5)
        subprocess.run(["sudo", "airmon-ng", "stop", mon_if],
                      capture_output=True, timeout=10)
        csv_file = os.path.join(temp_dir, "scan-01.csv")
        networks = []
        if os.path.exists(csv_file):
            with open(csv_file, errors="ignore") as f:
                raw = f.read()
            lines = raw.split("\n")
            parsing = False
            for line in lines:
                if "BSSID" in line and "PWR" in raw[raw.find(line):raw.find(line)+100] if raw.find(line) >= 0 else False:
                    parsing = True; continue
                if parsing and line.strip().replace(",", "").strip() == "":
                    break
                if parsing and line.count(",") >= 14:
                    parts = line.split(",")
                    networks.append({
                        "bssid": parts[0].strip() if len(parts) > 0 else "",
                        "channel": parts[3].strip() if len(parts) > 3 else "",
                        "speed": parts[4].strip() if len(parts) > 4 else "",
                        "privacy": parts[5].strip() if len(parts) > 5 else "",
                        "cipher": parts[6].strip() if len(parts) > 6 else "",
                        "authentication": parts[7].strip() if len(parts) > 7 else "",
                        "power": parts[8].strip() if len(parts) > 8 else "",
                        "beacons": parts[9].strip() if len(parts) > 9 else "",
                        "essid": parts[13].strip() if len(parts) > 13 else "",
                    })
        subprocess.run(["rm", "-rf", temp_dir], capture_output=True)
        cleanup_done = True
        return networks
    except FileNotFoundError as e:
        return {"error": f"Required tool not found: {e}. Install aircrack-ng: sudo apt install aircrack-ng"}
    except subprocess.TimeoutExpired:
        return {"error": "Command timed out. Check interface name and wireless hardware."}
    except Exception as e:
        return {"error": str(e)}
    finally:
        if not cleanup_done:
            subprocess.run(["rm", "-rf", temp_dir], capture_output=True)

def audit_network_security(networks):
    """Analyze networks for security issues."""
    findings = []
    for net in networks:
        essid = net.get("essid", "")
        bssid = net.get("bssid", "")
        privacy = net.get("privacy", "")
        issues = []
        if "WPA2" not in privacy and "WPA3" not in privacy:
            issues.append("Weak encryption (not WPA2/WPA3)")
        if "WEP" in privacy:
            issues.append("WEP encryption - trivially crackable")
        if "OPN" in privacy:
            issues.append("Open network - no encryption")
        if essid.lower().startswith("starbucks") or essid.lower().startswith("attwifi"):
            issues.append("Public hotspot - no client isolation expected")
        if essid == "":
            issues.append("Hidden SSID (network name hidden)")
        if len(essid) <= 3 and essid:
            issues.append("Very short SSID - potential rogue AP")
        if issues:
            findings.append({
                "bssid": bssid,
                "essid": essid or "(hidden)",
                "privacy": privacy,
                "issues": issues,
                "risk": "high" if "WEP" in privacy or "OPN" in privacy else "medium"
            })
    return findings

def capture_handshake(bssid, channel, interface="wlan0", timeout=30):
    """Capture WPA handshake for a target AP."""
    has_sudo, msg = _check_sudo()
    if not has_sudo:
        return {"error": msg}
    temp_dir = tempfile.mkdtemp(prefix="apollo_hc_")
    try:
        subprocess.run(["sudo", "airmon-ng", "start", interface], capture_output=True, timeout=10)
        mon_if = f"{interface}mon"
        proc = subprocess.Popen(
            ["sudo", "airodump-ng", "-c", str(channel), "--bssid", bssid,
             "-w", os.path.join(temp_dir, "handshake"), mon_if],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        import time; time.sleep(timeout)
        proc.terminate()
        proc.wait()
        cap_files = [f for f in os.listdir(temp_dir) if f.endswith(".cap") or f.endswith(".pcap")]
        handshake_files = []
        for f in cap_files:
            fpath = os.path.join(temp_dir, f)
            result = subprocess.run(["airodump-ng", "-r", fpath, "--bssid", bssid, "-w", "/dev/null"],
                                  capture_output=True, timeout=10)
            if "WPA" in result.stderr.decode() or "handshake" in result.stderr.decode().lower():
                handshake_files.append(fpath)
        subprocess.run(["sudo", "airmon-ng", "stop", mon_if], capture_output=True, timeout=10)
        return {
            "bssid": bssid,
            "channel": channel,
            "captures": handshake_files,
            "count": len(handshake_files)
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        subprocess.run(["rm", "-rf", temp_dir], capture_output=True)

def crack_handshake(cap_file, wordlist="/usr/share/wordlists/rockyou.txt"):
    """Attempt to crack WPA handshake with aircrack-ng."""
    if not os.path.exists(cap_file):
        return {"error": "Capture file not found"}
    if not os.path.exists(wordlist):
        return {"error": f"Wordlist not found: {wordlist}"}
    result = subprocess.run(
        ["aircrack-ng", "-w", wordlist, cap_file],
        capture_output=True, timeout=300, text=True
    )
    key_match = re.search(r"KEY FOUND! \[ (.+?) \]", result.stdout)
    if key_match:
        return {"success": True, "key": key_match.group(1)}
    return {"success": False, "output": result.stdout[:500]}

def deauth_detected(interface="wlan0", timeout=10):
    """Check for deauthentication attacks on the network."""
    has_sudo, msg = _check_sudo()
    if not has_sudo:
        return {"error": msg}
    try:
        result = subprocess.run(
            ["sudo", "timeout", str(timeout), "tcpdump", "-i", interface, "-c", "10", "-e", "-t",
             "type", "mgt", "subtype", "deauth"],
            capture_output=True, timeout=timeout+10, text=True
        )
        count = len([l for l in result.stdout.split("\n") if "DeAuthentication" in l])
        return {"deauth_frames": count, "attack_detected": count > 5, "interface": interface}
    except FileNotFoundError:
        return {"error": "tcpdump not found. Install: sudo apt install tcpdump"}
    except Exception as e:
        return {"error": str(e)}

def inject_findings(project_id, results):
    """Inject wireless audit findings into KB."""
    pid = project_id if project_id else get_project_id()
    hid = add_host(pid, "wireless:scan", "wireless_environment", tags="wireless")
    count = 0
    for finding in results.get("findings", []):
        add_vulnerability(hid, f"WiFi: {finding.get('essid', 'unknown')} - {'; '.join(finding.get('issues', []))}",
                        severity=finding.get("risk", "medium"),
                        description=f"BSSID: {finding.get('bssid', '')} Encryption: {finding.get('privacy', '')}",
                        mitre_id="T1465")
        count += 1
    return count

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "check":
            print(json.dumps(check_tools(), indent=2))
        elif sys.argv[1] == "scan":
            iface = sys.argv[2] if len(sys.argv) > 2 else "wlan0"
            timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 15
            networks = scan_networks(iface, timeout)
            print(json.dumps(networks[:20], indent=2) if isinstance(networks, list) else json.dumps(networks, indent=2))
        elif sys.argv[1] == "audit":
            iface = sys.argv[2] if len(sys.argv) > 2 else "wlan0"
            timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 15
            networks = scan_networks(iface, timeout)
            findings = audit_network_security(networks)
            print(json.dumps({"networks_scanned": len(networks) if isinstance(networks, list) else 0, "findings": findings}, indent=2))
        elif sys.argv[1] == "inject":
            iface = sys.argv[2] if len(sys.argv) > 2 else "wlan0"
            networks = scan_networks(iface)
            findings = audit_network_security(networks)
            count = inject_findings(None, {"findings": findings})
            print(f"Injected {count} wireless findings")
        elif sys.argv[1] == "deauth-check":
            iface = sys.argv[2] if len(sys.argv) > 2 else "wlan0"
            result = deauth_detected(iface)
            print(json.dumps(result, indent=2))
        else:
            print("Usage:")
            print("  wireless_auditor.py check         - Check tool availability")
            print("  wireless_auditor.py scan [iface] [timeout]")
            print("  wireless_auditor.py audit [iface] [timeout]")
            print("  wireless_auditor.py inject [iface]")
            print("  wireless_auditor.py deauth-check [iface]")
