#!/usr/bin/env python3
"""
APOLLO Kali Tool Auditor v4 - Tool availability, auto-install,
Kali paths, and smart recommendations. Expanded tool registry.
"""
import subprocess, os, sys, shutil
from pathlib import Path

TOOL_REGISTRY = {
    "recon": [
        ("subfinder", "subfinder", "subfinder", "Passive subdomain enumeration", "amass"),
        ("amass", "amass", "amass", "Attack surface mapping", ""),
        ("httpx", "httpx", "httpx", "HTTP probing toolkit", "curl"),
        ("theHarvester", "theHarvester", "theharvester", "OSINT email/subdomain gatherer", ""),
        ("nmap", "nmap", "nmap", "Network mapper", ""),
        ("masscan", "masscan", "masscan", "High-speed port scanner", "nmap"),
        ("rustscan", "rustscan", "rustscan", "Fast port scanner (Rust)", ""),
        ("dnsx", "dnsx", "dnsx", "DNS query tool", ""),
        ("shodan", "shodan", "shodan", "Shodan CLI", ""),
        ("censys", "censys", "censys", "Censys search CLI", ""),
        ("gowitness", "gowitness", "gowitness", "Web screenshot tool", ""),
        ("subjack", "subjack", "subjack", "Subdomain takeover checker", ""),
        ("trufflehog", "trufflehog", "trufflehog", "Secret scanner", ""),
    ],
    "scanning": [
        ("naabu", "naabu", "naabu", "Fast port scanner", "nmap"),
        ("nuclei", "nuclei", "nuclei", "Vulnerability scanner", ""),
        ("nikto", "nikto", "nikto", "Web server scanner", ""),
        ("wpscan", "wpscan", "wpscan", "WordPress scanner", ""),
        ("joomscan", "joomscan", "joomscan", "Joomla scanner", ""),
        ("droopescan", "droopescan", "droopescan", "Drupal scanner", ""),
        ("sslscan", "sslscan", "sslscan", "SSL/TLS scanner", ""),
        ("testssl", "testssl.sh", "testssl.sh", "SSL/TLS checker", ""),
        ("wapiti", "wapiti", "wapiti", "Web vulnerability scanner", ""),
    ],
    "web": [
        ("ffuf", "ffuf", "ffuf", "Web fuzzer", "wfuzz"),
        ("wfuzz", "wfuzz", "wfuzz", "Web fuzzer", "ffuf"),
        ("sqlmap", "sqlmap", "sqlmap", "SQL injection automation", ""),
        ("dalfox", "dalfox", "dalfox", "XSS scanner", ""),
        ("xsstrike", "xsstrike", "xsstrike", "XSS scanner", "dalfox"),
        ("dirb", "dirb", "dirb", "Directory brute forcer", "ffuf"),
        ("gobuster", "gobuster", "gobuster", "Directory/file brute forcer", "ffuf"),
        ("arjun", "arjun", "arjun", "HTTP parameter discovery", ""),
        ("paramspider", "paramspider", "paramspider", "Parameter discovery", ""),
        ("commix", "commix", "commix", "Command injection tester", ""),
        ("skipfish", "skipfish", "skipfish", "Web app security scanner", ""),
        ("whatweb", "whatweb", "whatweb", "Web tech profiler", ""),
    ],
    "exploit": [
        ("msfconsole", "msfconsole", "metasploit-framework", "Metasploit console", ""),
        ("msfvenom", "msfvenom", "metasploit-framework", "Payload generator", ""),
        ("searchsploit", "searchsploit", "exploitdb", "Exploit database search", ""),
        ("metasploit", "msfrpcd", "metasploit-framework", "Metasploit RPC daemon", ""),
        ("crackmapexec", "crackmapexec", "crackmapexec", "AD post-exploitation", ""),
        ("pwncat", "pwncat", "pwncat", "Reverse shell handler", ""),
        ("shellter", "shellter", "shellter", "Dynamic shellcode injector", ""),
        ("veil", "veil", "veil", "Payload generator (evasion)", ""),
    ],
    "password": [
        ("hashcat", "hashcat", "hashcat", "GPU password cracker", "john"),
        ("john", "john", "john", "CPU password cracker", "hashcat"),
        ("hydra", "hydra", "hydra", "Online password attack", "medusa"),
        ("medusa", "medusa", "medusa", "Parallel password attack", "hydra"),
        ("johnny", "johnny", "johnny", "John GUI", ""),
        ("cewl", "cewl", "cewl", "Custom wordlist generator", ""),
        ("crunch", "crunch", "crunch", "Wordlist generator", ""),
        ("rsmangler", "rsmangler", "rsmangler", "Wordlist mangler", ""),
        ("ophcrack", "ophcrack", "ophcrack", "Windows password cracker", ""),
        ("chntpw", "chntpw", "chntpw", "Windows SAM editor", ""),
    ],
    "ad": [
        ("ldapsearch", "ldapsearch", "ldap-utils", "LDAP query tool", ""),
        ("ldapdomaindump", "ldapdomaindump", "ldapdomaindump", "LDAP domain dumper", ""),
        ("enum4linux", "enum4linux", "enum4linux", "SMB enumeration", ""),
        ("enum4linux-ng", "enum4linux-ng", "enum4linux-ng", "SMB enumeration next-gen", ""),
        ("impacket-GetNPUsers", "GetNPUsers.py", "impacket-scripts", "AS-REP roasting", ""),
        ("impacket-GetUserSPNs", "GetUserSPNs.py", "impacket-scripts", "Kerberoasting", ""),
        ("impacket-secretsdump", "secretsdump.py", "impacket-scripts", "DCSync/cred dumping", ""),
        ("impacket-wmiexec", "wmiexec.py", "impacket-scripts", "WMI execution", ""),
        ("impacket-psexec", "psexec.py", "impacket-scripts", "PSExec", ""),
        ("impacket-smbexec", "smbexec.py", "impacket-scripts", "SMB execution", ""),
        ("impacket-ticketer", "ticketer.py", "impacket-scripts", "Golden ticket", ""),
        ("bloodhound-python", "bloodhound-python", "bloodhound", "AD relationship mapping", ""),
        ("bloodhound", "bloodhound", "bloodhound", "BloodHound GUI", ""),
        ("responder", "responder", "responder", "LLMNR/NBT-NS poisoner", ""),
        ("mitm6", "mitm6", "mitm6", "IPv6 DNS hijacker", ""),
        ("kerbrute", "kerbrute", "kerbrute", "Kerberos brute forcer", ""),
        ("adidnsdump", "adidnsdump", "adidnsdump", "AD DNS dumper", ""),
        ("gpp-decrypt", "gpp-decrypt", "gpp-decrypt", "GPP password decryptor", ""),
        ("bloodyAD", "bloodyAD", "bloodyad", "AD privilege escalation toolkit", ""),
        ("certipy", "certipy", "certipy-ad", "AD CS exploitation tool", ""),
        ("adPEAS", "adpeas", "adpeas", "AD privilege escalation enumeration", ""),
        ("pywerview", "pywerview", "pywerview", "PowerView in Python", ""),
    ],
    "post": [
        ("smbclient", "smbclient", "smbclient", "SMB client", ""),
        ("smbmap", "smbmap", "smbmap", "SMB share enumerator", ""),
        ("psexec", "psexec", "psexec", "PsExec tool", ""),
        ("evil-winrm", "evil-winrm", "evil-winrm", "WinRM shell", ""),
        ("mimikatz", "mimikatz", "mimikatz", "Credential extractor", ""),
        ("netcat", "nc", "netcat-openbsd", "Network Swiss Army knife", ""),
        ("ncat", "ncat", "ncat", "Enhanced netcat", ""),
        ("socat", "socat", "socat", "Socket relay tool", ""),
        ("chisel", "chisel", "chisel", "Tunneling tool", ""),
        ("ligolo-ng", "ligolo-ng", "ligolo-ng", "Tunneling tool", "chisel"),
        ("proxychains", "proxychains", "proxychains4", "Proxy chain tool", ""),
        ("rpivot", "rpivot", "rpivot", "SOCKS proxy tool", ""),
        ("sshuttle", "sshuttle", "sshuttle", "VPN over SSH", ""),
    ],
    "mobile": [
        ("aircrack-ng", "aircrack-ng", "aircrack-ng", "WiFi auditing", ""),
        ("airgeddon", "airgeddon", "airgeddon", "WiFi auditor", ""),
        ("bettercap", "bettercap", "bettercap", "MITM framework", ""),
        ("dsniff", "dsniff", "dsniff", "Network sniffing tools", ""),
        ("wireshark", "wireshark", "wireshark", "Packet analyzer", ""),
        ("tshark", "tshark", "tshark", "CLI packet analyzer", ""),
        ("tcpdump", "tcpdump", "tcpdump", "Packet capture", ""),
        ("macchanger", "macchanger", "macchanger", "MAC address changer", ""),
        ("reaver", "reaver", "reaver", "WPS brute forcer", ""),
        ("bully", "bully", "bully", "WPS brute forcer", "reaver"),
        ("hcxdumptool", "hcxdumptool", "hcxdumptool", "PMKID capture tool", ""),
        ("hcxpcapngtool", "hcxpcapngtool", "hcxpcapngtool", "PMKID converter", ""),
    ],
    "cloud": [
        ("aws", "aws", "awscli", "AWS CLI", ""),
        ("az", "az", "azure-cli", "Azure CLI", ""),
        ("gcloud", "gcloud", "google-cloud-sdk", "GCP CLI", ""),
        ("cloud_enum", "cloud_enum", "cloud-enum", "Cloud enumeration", ""),
        ("s3scanner", "s3scanner", "s3scanner", "S3 bucket scanner", ""),
        ("pacu", "pacu", "pacu", "AWS exploitation framework", ""),
        ("nimbus", "nimbus", "nimbus", "Cloud enumeration", ""),
    ],
    "container": [
        ("docker", "docker", "docker.io", "Docker CLI", ""),
        ("kubectl", "kubectl", "kubectl", "Kubernetes CLI", ""),
        ("helm", "helm", "helm", "Kubernetes package manager", ""),
        ("kubeaudit", "kubeaudit", "kubeaudit", "Kubernetes auditor", ""),
        ("kube-bench", "kube-bench", "kube-bench", "CIS benchmark checker", ""),
        ("trivy", "trivy", "trivy", "Container vulnerability scanner", ""),
        ("grype", "grype", "grype", "Container vulnerability scanner", "trivy"),
        ("dive", "dive", "dive", "Image layer explorer", ""),
        ("kubescape", "kubescape", "kubescape", "K8s security scanner", ""),
        ("kubewarden", "kubewarden", "kubewarden", "K8s policy engine", ""),
    ],
    "reverse_engineering": [
        ("radare2", "radare2", "radare2", "Reverse engineering framework", ""),
        ("rizin", "rizin", "rizin", "RE framework (r2 fork)", ""),
        ("ghidra", "ghidra", "ghidra", "SRE framework", ""),
        ("gdb", "gdb", "gdb", "GNU debugger", ""),
        ("objdump", "objdump", "binutils", "Binary analysis", ""),
        ("strings", "strings", "binutils", "String extraction", ""),
        ("binwalk", "binwalk", "binwalk", "Firmware analysis", ""),
        ("stegsolve", "stegsolve", "stegsolve", "Steganography solver", ""),
        ("exiftool", "exiftool", "exiftool", "Metadata extraction", ""),
        ("yara", "yara", "yara", "Pattern matching tool", ""),
    ],
    "evasion": [
        ("upx", "upx", "upx", "Executable packer", ""),
        ("donut", "donut", "donut", ".NET to shellcode", ""),
        ("ScareCrow", "ScareCrow", "scarecrow", "Evasive loader", ""),
        ("veil-evasion", "veil", "veil", "Payload generator", ""),
        ("shellter", "shellter", "shellter", "Shellcode injector", ""),
        ("hyperion", "hyperion", "hyperion", "PE crypter", ""),
        ("confuser", "ConfuserEx", "confuserex", ".NET obfuscator", ""),
    ],
    "utility": [
        ("curl", "curl", "curl", "HTTP client", "wget"),
        ("wget", "wget", "wget", "HTTP downloader", "curl"),
        ("jq", "jq", "jq", "JSON processor", ""),
        ("openssl", "openssl", "openssl", "Cryptography toolkit", ""),
        ("git", "git", "git", "Version control", ""),
        ("python3", "python3", "python3", "Python interpreter", ""),
        ("pip3", "pip3", "python3-pip", "Python package manager", ""),
        ("socat", "socat", "socat", "Socket relay", ""),
        ("screen", "screen", "screen", "Terminal multiplexer", ""),
        ("tmux", "tmux", "tmux", "Terminal multiplexer", "screen"),
        ("rdesktop", "rdesktop", "rdesktop", "RDP client", ""),
        ("xfreerdp", "xfreerdp", "freerdp2-x11", "RDP client", "rdesktop"),
        ("vim", "vim", "vim", "Text editor", ""),
        ("nano", "nano", "nano", "Text editor", ""),
    ],
}

KALI_PATHS = {
    "rockyou": "/usr/share/wordlists/rockyou.txt",
    "rockyou_gz": "/usr/share/wordlists/rockyou.txt.gz",
    "seclists": "/usr/share/seclists",
    "hashcat_rules": "/usr/share/hashcat/rules",
    "nmap_scripts": "/usr/share/nmap/scripts",
    "metasploit": "/usr/share/metasploit-framework",
    "exploitdb": "/usr/share/exploitdb",
    "responder": "/usr/share/responder",
    "wordlists": "/usr/share/wordlists",
    "dirb_wordlists": "/usr/share/dirb/wordlists",
    "wfuzz_wordlists": "/usr/share/wfuzz/wordlist",
    "seclists_discovery": "/usr/share/seclists/Discovery",
    "seclists_passwords": "/usr/share/seclists/Passwords",
    "seclists_usernames": "/usr/share/seclists/Usernames",
    "john_config": "/etc/john/john.conf",
    "hashcat_rules_best64": "/usr/share/hashcat/rules/best64.rule",
    "nuclei_templates": "~/nuclei-templates",
}

def check_tool(name):
    """Check if a tool binary is available, with alias support."""
    return shutil.which(name) is not None

# Alias map: common tool names that changed in newer Kali
TOOL_ALIASES = {
    "crackmapexec": "netexec",
    "nmap": "nmap",
    "msfrpcd": "msfconsole",
}

def audit_all():
    results = {}
    for category, tools in TOOL_REGISTRY.items():
        results[category] = []
        for name, binary, pkg, desc, fallback in tools:
            # Check primary binary, then aliases
            available = check_tool(binary)
            if not available:
                alias = TOOL_ALIASES.get(name) or TOOL_ALIASES.get(binary)
                if alias:
                    available = check_tool(alias)
            results[category].append({"name": name, "binary": binary,
                "effective_binary": alias if (not check_tool(binary) and alias) else binary,
                "package": pkg, "description": desc, "available": available, "fallback": fallback})
    return results

def check_path(path_key):
    path = KALI_PATHS.get(path_key)
    if not path: return None
    return os.path.exists(os.path.expanduser(path))

def audit_paths():
    results = {}
    for key, path in KALI_PATHS.items():
        expanded = os.path.expanduser(path)
        results[key] = {"path": expanded, "exists": os.path.exists(expanded)}
        if os.path.exists(expanded):
            try:
                results[key]["size"] = subprocess.check_output(["du", "-sh", expanded], stderr=subprocess.DEVNULL).decode().split("\t")[0]
            except: results[key]["size"] = "?"
    return results

def suggest_install(target_name):
    for category, tools in TOOL_REGISTRY.items():
        for name, binary, pkg, desc, fallback in tools:
            if name == target_name or binary == target_name:
                if pkg: return f"sudo apt install -y {pkg}"
                else: return f"# {target_name}: no apt package found, try pip or manual install"
    return f"# {target_name}: unknown tool"

def missing_essentials():
    essentials = [
        "nmap", "nuclei", "sqlmap", "hashcat", "hydra", "curl", "wget",
        "python3", "git", "openssl", "ldapsearch", "smbclient", "responder",
        "netexec", "searchsploit", "ffuf", "nikto", "whatweb",
        "masscan", "socat", "amass",
    ]
    # Check aliases
    alias_check = {"crackmapexec": "netexec", "jq": "jq", "docker": "docker", "kubectl": "kubectl"}
    missing = []
    for tool in essentials:
        if not check_tool(tool):
            alias = alias_check.get(tool)
            if alias and check_tool(alias):
                continue
            missing.append(tool)
    return missing

def auto_install(missing_tools):
    pkgs = set()
    for tool in missing_tools:
        for category, tools in TOOL_REGISTRY.items():
            for name, binary, pkg, desc, fallback in tools:
                if name == tool and pkg: pkgs.add(pkg)
    if pkgs: return f"sudo apt update && sudo apt install -y {' '.join(sorted(pkgs))}"
    return ""

def expand_rockyou():
    gz = KALI_PATHS["rockyou_gz"]
    txt = KALI_PATHS["rockyou"]
    if os.path.exists(gz) and not os.path.exists(txt): return f"gunzip -k {gz}", True
    if os.path.exists(txt): return f"{txt} exists ({os.path.getsize(txt)} bytes)", False
    return "rockyou not found", False

def check_wordlist(name):
    paths = [f"/usr/share/wordlists/{name}", f"/usr/share/seclists/{name}", f"/usr/share/dict/{name}"]
    for p in paths:
        if os.path.exists(p): return p
    return None

def get_categories():
    return list(TOOL_REGISTRY.keys())

def get_tools_by_category(category):
    return TOOL_REGISTRY.get(category, [])

def count_by_category():
    return {cat: len(tools) for cat, tools in TOOL_REGISTRY.items()}

if __name__ == "__main__":
    import json as j
    if len(sys.argv) < 2:
        results = audit_all()
        totals = count_by_category()
        print("=" * 60)
        print("  APOLLO Kali Tool Audit v4")
        print("=" * 60)
        for category in sorted(results.keys()):
            tools = results[category]
            avail = sum(1 for t in tools if t["available"])
            total = len(tools)
            bar = "#" * avail + "-" * (total - avail)
            print(f"\n[{category.upper():20s}] {bar} {avail}/{total}")
            for t in tools:
                status = "OK" if t["available"] else "MISSING"
                fb = f" -> fallback: {t['fallback']}" if t.get('fallback') else ""
                print(f"  {status} {t['name']:25s} {t['binary']:20s} apt: {t['package']:30s}{fb}")
        total_tools = sum(totals.values())
        total_avail = sum(sum(1 for t in audit_all()[c] if t["available"]) for c in audit_all())
        print(f"\n{'='*60}")
        print(f"  Total: {total_avail}/{total_tools} tools available ({total_avail*100//max(total_tools,1)}%)")
        print(f"  Categories: {len(totals)}")
        print(f"  Paths: {j.dumps(audit_paths(), indent=2)}")
        msg, needs = expand_rockyou()
        print(f"\n  Rockyou: {msg}")
    elif sys.argv[1] == "install":
        tools = sys.argv[2:]
        cmd = auto_install(tools)
        print(cmd)
    elif sys.argv[1] == "check":
        print(j.dumps({"present": check_tool(sys.argv[2]) if len(sys.argv) > 2 else False}))
    elif sys.argv[1] == "json":
        print(j.dumps(audit_all(), indent=2))
    elif sys.argv[1] == "categories":
        print(j.dumps(get_categories(), indent=2))
    elif sys.argv[1] == "count":
        print(j.dumps(count_by_category(), indent=2))
    elif sys.argv[1] == "missing":
        print(j.dumps(missing_essentials(), indent=2))
