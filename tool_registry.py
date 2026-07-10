#!/usr/bin/env python3
"""
APOLLO Tool Registry v1 - Dynamic tool detection and capability mapping.
"""
import subprocess, shutil, sys, os, json, re
from typing import Dict, List, Optional, Tuple

# Ensure Go binary path is in PATH for tool detection
_GO_BIN = os.path.expanduser("~/go/bin")
if os.path.isdir(_GO_BIN) and _GO_BIN not in os.environ.get("PATH", ""):
    os.environ["PATH"] = _GO_BIN + os.pathsep + os.environ.get("PATH", "")
# Also check common Go install paths
for _gpath in ["/usr/local/go/bin", "/usr/lib/go/bin"]:
    if os.path.isdir(_gpath) and _gpath not in os.environ.get("PATH", ""):
        os.environ["PATH"] = _gpath + os.pathsep + os.environ.get("PATH", "")

_TOOL_CACHE = None
_CATEGORY_CACHE = None

TOOL_CATEGORIES = {
    "recon": {
        "nmap": {"binary": "nmap", "check": "nmap --version 2>&1"},
        "masscan": {"binary": "masscan", "check": "masscan --version 2>&1"},
        "nuclei": {"binary": "nuclei", "check": "nuclei --version 2>&1"},
        "httpx": {"binary": "httpx", "check": "httpx --version 2>&1"},
        "amass": {"binary": "amass", "check": "amass -version 2>&1"},
        "theHarvester": {"binary": "theHarvester", "check": "theHarvester --version 2>&1"},
        "gobuster": {"binary": "gobuster", "check": "gobuster --version 2>&1"},
        "dnsx": {"binary": "dnsx", "check": "dnsx --version 2>&1"},
        "subfinder": {"binary": "subfinder", "check": "subfinder --version 2>&1"},
        "naabu": {"binary": "naabu", "check": "naabu --version 2>&1"},
    },
    "scanning": {
        "nmap": {"binary": "nmap", "check": "nmap --version 2>&1"},
        "masscan": {"binary": "masscan", "check": "masscan --version 2>&1"},
        "nuclei": {"binary": "nuclei", "check": "nuclei --version 2>&1"},
    },
    "web": {
        "ffuf": {"binary": "ffuf", "check": "ffuf --version 2>&1"},
        "gobuster": {"binary": "gobuster", "check": "gobuster --version 2>&1"},
        "dirb": {"binary": "dirb", "check": "dirb 2>&1"},
        "wfuzz": {"binary": "wfuzz", "check": "wfuzz --version 2>&1"},
        "whatweb": {"binary": "whatweb", "check": "whatweb --version 2>&1"},
        "wpscan": {"binary": "wpscan", "check": "wpscan --version 2>&1"},
        "nikto": {"binary": "nikto", "check": "nikto -Version 2>&1"},
        "sqlmap": {"binary": "sqlmap", "check": "sqlmap --version 2>&1"},
        "commix": {"binary": "commix", "check": "commix --version 2>&1"},
        "nuclei": {"binary": "nuclei", "check": "nuclei --version 2>&1"},
    },
    "exploit": {
        "msfconsole": {"binary": "msfconsole", "check": "msfconsole --version 2>&1"},
        "msfvenom": {"binary": "msfvenom", "check": "msfvenom --version 2>&1"},
        "searchsploit": {"binary": "searchsploit", "check": "searchsploit 2>&1"},
        "sqlmap": {"binary": "sqlmap", "check": "sqlmap --version 2>&1"},
        "hydra": {"binary": "hydra", "check": "hydra --version 2>&1"},
    },
    "password": {
        "hashcat": {"binary": "hashcat", "check": "hashcat --version 2>&1"},
        "john": {"binary": "john", "check": "john 2>&1"},
        "hydra": {"binary": "hydra", "check": "hydra --version 2>&1"},
        "medusa": {"binary": "medusa", "check": "medusa 2>&1"},
        "patator": {"binary": "patator", "check": "patator --version 2>&1"},
    },
    "ad": {
        "impacket-secretsdump": {"binary": "impacket-secretsdump", "check": "impacket-secretsdump 2>&1"},
        "impacket-wmiexec": {"binary": "impacket-wmiexec", "check": "impacket-wmiexec 2>&1"},
        "impacket-psexec": {"binary": "impacket-psexec", "check": "impacket-psexec 2>&1"},
        "impacket-smbexec": {"binary": "impacket-smbexec", "check": "impacket-smbexec 2>&1"},
        "netexec": {"binary": "netexec", "check": "netexec --version 2>&1"},
        "smbmap": {"binary": "smbmap", "check": "smbmap 2>&1"},
        "enum4linux": {"binary": "enum4linux", "check": "enum4linux 2>&1"},
        "ldapsearch": {"binary": "ldapsearch", "check": "ldapsearch --version 2>&1"},
        "ldapdomaindump": {"binary": "ldapdomaindump", "check": "ldapdomaindump 2>&1"},
        "certipy-ad": {"binary": "certipy-ad", "check": "certipy-ad 2>&1"},
        "bloodhound-python": {"binary": "bloodhound-python", "check": "bloodhound-python 2>&1"},
        "responder": {"binary": "responder", "check": "responder --version 2>&1"},
        "evil-winrm": {"binary": "evil-winrm", "check": "evil-winrm --version 2>&1"},
    },
    "post": {
        "impacket-secretsdump": {"binary": "impacket-secretsdump", "check": "impacket-secretsdump 2>&1"},
        "impacket-wmiexec": {"binary": "impacket-wmiexec", "check": "impacket-wmiexec 2>&1"},
        "impacket-psexec": {"binary": "impacket-psexec", "check": "impacket-psexec 2>&1"},
        "netexec": {"binary": "netexec", "check": "netexec --version 2>&1"},
        "evil-winrm": {"binary": "evil-winrm", "check": "evil-winrm --version 2>&1"},
    },
    "wireless": {
        "aircrack-ng": {"binary": "aircrack-ng", "check": "aircrack-ng --version 2>&1"},
        "kismet": {"binary": "kismet", "check": "kismet --version 2>&1"},
        "reaver": {"binary": "reaver", "check": "reaver --version 2>&1"},
        "bully": {"binary": "bully", "check": "bully 2>&1"},
        "fern-wifi-cracker": {"binary": "fern-wifi-cracker", "check": "fern-wifi-cracker --version 2>&1"},
    },
}

PYTHON_TOOLS = {
    "pymetasploit3": "pymetasploit3",
    "fpdf2": "fpdf",
    "beautifulsoup4": "bs4",
    "dnspython": "dns",
    "mysql-connector-python": "mysql.connector",
    "docker": "docker",
}

MSF_AVAILABLE = None

def _run_check(check_cmd: str) -> bool:
    try:
        r = subprocess.run(check_cmd, shell=True, capture_output=True, timeout=5)
        return r.returncode == 0
    except: return False

def detect_tools(force: bool = False) -> Dict[str, bool]:
    global _TOOL_CACHE
    if _TOOL_CACHE and not force:
        return _TOOL_CACHE
    result = {}
    for cat, tools in TOOL_CATEGORIES.items():
        for name, info in tools.items():
            if name not in result:
                result[name] = shutil.which(info["binary"]) is not None
    _TOOL_CACHE = result
    return result

def detect_python_modules() -> Dict[str, bool]:
    result = {}
    for mod_name, import_name in PYTHON_TOOLS.items():
        try:
            exec(f"import {import_name}")
            result[mod_name] = True
        except ImportError:
            result[mod_name] = False
    return result

def get_available_tools(category: Optional[str] = None) -> Dict[str, bool]:
    all_tools = detect_tools()
    if category:
        if category not in TOOL_CATEGORIES:
            return {}
        return {name: all_tools.get(name, False) for name in TOOL_CATEGORIES[category]}
    return all_tools

def is_available(name: str) -> bool:
    tools = detect_tools()
    return tools.get(name, False)

def get_binary(name: str) -> Optional[str]:
    info = None
    for cat in TOOL_CATEGORIES.values():
        if name in cat:
            info = cat[name]
            break
    if info:
        return shutil.which(info["binary"])
    return None

def msf_available() -> bool:
    global MSF_AVAILABLE
    if MSF_AVAILABLE is None:
        MSF_AVAILABLE = shutil.which("msfconsole") is not None
    return MSF_AVAILABLE

def run_tool(name: str, args: str, timeout: int = 60) -> Dict:
    binary = get_binary(name)
    if not binary:
        return {"success": False, "error": f"{name} not installed", "exit_code": -1}
    cmd = f"{binary} {args}"
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        out = (r.stdout + r.stderr).decode("utf-8", errors="ignore")
        return {"success": r.returncode == 0, "output": out[:5000],
                "exit_code": r.returncode, "command": cmd}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "TIMEOUT", "exit_code": -1}
    except Exception as e:
        return {"success": False, "error": str(e), "exit_code": -1}

def run_msf_command(resource_script: str, timeout: int = 120) -> Dict:
    if not msf_available():
        return {"success": False, "error": "msfconsole not installed"}
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
        f.write(resource_script)
        rc_path = f.name
    cmd = f"msfconsole -q -r {rc_path} 2>&1"
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        out = (r.stdout + r.stderr).decode("utf-8", errors="ignore")
        os.unlink(rc_path)
        return {"success": r.returncode == 0, "output": out[:5000],
                "exit_code": r.returncode, "command": cmd}
    except subprocess.TimeoutExpired:
        os.unlink(rc_path)
        return {"success": False, "error": "TIMEOUT", "output": "", "exit_code": -1}
    except Exception as e:
        os.unlink(rc_path)
        return {"success": False, "error": str(e), "exit_code": -1}

def install_missing(name: str) -> Dict:
    pip_tools = {"naabu", "subfinder", "dnsx", "httpx", "nuclei"}
    apt_tools = {"jq": "jq", "chisel": "chisel"}
    if name in pip_tools:
        tool_map = {"naabu": "naabu", "subfinder": "subfinder", "dnsx": "dnsx",
                    "httpx": "httpx", "nuclei": "nuclei"}
        r = subprocess.run(f"go install -v github.com/projectdiscovery/{tool_map.get(name, name)}/cmd/{name}@latest 2>&1",
                          shell=True, capture_output=True, timeout=120)
        out = (r.stdout + r.stderr).decode("utf-8", errors="ignore")
        return {"installed": r.returncode == 0, "output": out[:200]}
    elif name in apt_tools:
        r = subprocess.run(f"apt-get install -y {apt_tools[name]} 2>&1", shell=True, capture_output=True, timeout=60)
        out = (r.stdout + r.stderr).decode("utf-8", errors="ignore")
        return {"installed": r.returncode == 0, "output": out[:200]}
    return {"installed": False, "error": f"Unknown tool: {name}"}

def summary() -> Dict:
    tools = detect_tools()
    available = sum(1 for v in tools.values() if v)
    total = len(tools)
    by_cat = {}
    for cat, cat_tools in TOOL_CATEGORIES.items():
        avail = sum(1 for name in cat_tools if tools.get(name, False))
        by_cat[cat] = {"available": avail, "total": len(cat_tools)}
    py_mods = detect_python_modules()
    py_avail = sum(1 for v in py_mods.values() if v)

    return {"tools_available": f"{available}/{total}",
            "by_category": by_cat,
            "python_modules_available": f"{py_avail}/{len(py_mods)}",
            "msf_available": msf_available(),
            "tools_list": {k: v for k, v in sorted(tools.items())}}

if __name__ == "__main__":
    import json
    if len(sys.argv) > 1 and sys.argv[1] == "summary":
        print(json.dumps(summary(), indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "install":
        if len(sys.argv) > 2:
            print(json.dumps(install_missing(sys.argv[2]), indent=2))
        else:
            print("Usage: tool_registry.py install <tool_name>")
    else:
        tools = detect_tools()
        print("APOLLO Tool Registry - Installed Tools:")
        for name, avail in sorted(tools.items()):
            status = "OK" if avail else "MISSING"
            print(f"  [{status}] {name}")
        py = detect_python_modules()
        for mod, avail in py.items():
            status = "OK" if avail else "MISSING"
            print(f"  [{status}] python:{mod}")
