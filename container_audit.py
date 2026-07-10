#!/usr/bin/env python3
"""
APOLLO Container Security Auditor - Docker/K8s security checks,
misconfiguration detection, privilege escalation paths.
"""
import sys, os, json, subprocess, tempfile, shlex
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import *

DOCKER_CHECKS = [
    {"name": "Running as root", "check": "docker info 2>/dev/null | grep -q 'root'", "risk": "high",
     "mitre": "T1610", "desc": "Container running with root privileges"},
    {"name": "Privileged mode", "check": "cat /proc/1/status 2>/dev/null | grep -q 'CapEff:.*0000003fffffffff'", "risk": "critical",
     "mitre": "T1610", "desc": "Container running in privileged mode"},
    {"name": "Host PID namespace", "check": "cat /proc/1/sched 2>/dev/null | head -1 | grep -v '^systemd'", "risk": "high",
     "mitre": "T1610", "desc": "Container sharing host PID namespace"},
    {"name": "Docker socket mounted", "check": "[ -S /var/run/docker.sock ]", "risk": "critical",
     "mitre": "T1610", "desc": "Docker socket mounted inside container - escape possible"},
    {"name": "Host network mode", "check": "ip link 2>/dev/null | grep -q docker", "risk": "medium",
     "mitre": "T1610", "desc": "Container using host network"},
    {"name": "SYS_ADMIN capability", "check": "cat /proc/1/status 2>/dev/null | grep CapEff | grep -qi '00000000........1f'", "risk": "high",
     "mitre": "T1610", "desc": "SYS_ADMIN capability enabled"},
    {"name": "Read-only rootfs", "check": "mount 2>/dev/null | grep 'on / ' | grep -q 'ro,'", "risk": "low",
     "mitre": "T1610", "desc": "Root filesystem is read-only (good)"},
    {"name": "Seccomp disabled", "check": "cat /proc/1/status 2>/dev/null | grep Seccomp | grep -q '0$'", "risk": "medium",
     "mitre": "T1610", "desc": "Seccomp is disabled"},
    {"name": "AppArmor disabled", "check": "cat /proc/1/attr/current 2>/dev/null | grep -q 'unconfined'", "risk": "medium",
     "mitre": "T1610", "desc": "AppArmor profile is unconfined"},
    {"name": "Sensitive mount: /etc", "check": "mount 2>/dev/null | grep '/etc' | grep -q 'rw'", "risk": "high",
     "mitre": "T1610", "desc": "/etc mounted writable - host config manipulation possible"},
]

KUBERNETES_CHECKS = [
    {"name": "API server accessible", "check": "kubectl get nodes 2>/dev/null || curl -sk https://kubernetes.default.svc 2>/dev/null | grep -q 'api'", "risk": "critical",
     "mitre": "T1610", "desc": "Kubernetes API server accessible from pod"},
    {"name": "Service account mounted", "check": "[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]", "risk": "high",
     "mitre": "T1525", "desc": "Kubernetes service account token mounted"},
    {"name": "Pod deletion rights", "check": "kubectl auth can-i delete pods 2>/dev/null | grep -q yes", "risk": "high",
     "mitre": "T1610", "desc": "Pod has delete permission"},
    {"name": "HostPath volume", "check": "mount 2>/dev/null | grep -E '/dev|/proc|/sys' | grep -v 'cgroup'", "risk": "high",
     "mitre": "T1610", "desc": "HostPath volume detected"},
]

def run_check(check_cmd):
    """Run a shell check command and return result."""
    try:
        result = subprocess.run(check_cmd, shell=True, capture_output=True, timeout=5, executable="/bin/bash")
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        return False
    except Exception:
        return False

def audit_docker():
    """Audit Docker container security."""
    results = []
    for check in DOCKER_CHECKS:
        vulnerable = run_check(check["check"])
        if vulnerable:
            results.append({**check, "status": "vulnerable"})
    return results

def audit_kubernetes():
    """Audit Kubernetes pod security."""
    results = []
    for check in KUBERNETES_CHECKS:
        vulnerable = run_check(check["check"])
        if vulnerable:
            results.append({**check, "status": "vulnerable"})
    return results

def full_audit():
    """Run full container security audit."""
    return {
        "docker": audit_docker(),
        "kubernetes": audit_kubernetes(),
        "summary": {
            "docker_vulns": len(audit_docker()),
            "k8s_vulns": len(audit_kubernetes()),
            "total": len(audit_docker()) + len(audit_kubernetes())
        }
    }

def escape_suggestions(audit_results):
    """Suggest container escape methods based on findings."""
    suggestions = []
    for finding in audit_results.get("docker", []):
        name = finding["name"]
        if "Docker socket mounted" in name:
            suggestions.append({
                "technique": "Docker socket escape",
                "command": "docker run -it -v /:/host --rm alpine chroot /host /bin/bash",
                "mitre": "T1610"
            })
        elif "Privileged mode" in name:
            suggestions.append({
                "technique": "Privileged container escape",
                "command": "mount /dev/sda1 /mnt && chroot /mnt",
                "mitre": "T1610"
            })
        elif "SYS_ADMIN" in name:
            suggestions.append({
                "technique": "SYS_ADMIN namespace escape",
                "command": "unshare -Urm /bin/bash",
                "mitre": "T1610"
            })
        elif "Host PID namespace" in name:
            suggestions.append({
                "technique": "PID namespace breakout",
                "command": "nsenter --target 1 --mount --uts --ipc --pid /bin/bash",
                "mitre": "T1610"
            })
        elif "Running as root" in name:
            suggestions.append({
                "technique": "Root in container",
                "command": "Check capabilities: cat /proc/1/status | grep CapEff",
                "mitre": "T1610"
            })
    return suggestions

def run_trivy_scan(image=None, path=None):
    """Run trivy vulnerability scanner on image or filesystem."""
    cmd = ""
    if image:
        cmd = f"trivy image --no-progress --format json {image} 2>/dev/null"
    elif path:
        cmd = f"trivy fs --no-progress --format json {path} 2>/dev/null"
    if not cmd:
        return {"error": "Provide image or path"}
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=180, executable="/bin/bash")
        if r.returncode != 0:
            return {"error": (r.stderr.decode("utf-8", errors="ignore"))[:300]}
        results = json.loads(r.stdout.decode("utf-8", errors="ignore"))
        # Summarize
        vulns = []
        for res in results.get("Results", []):
            for v in res.get("Vulnerabilities", []):
                vulns.append({
                    "pkg": v.get("PkgName", ""),
                    "severity": v.get("Severity", "UNKNOWN"),
                    "cve": v.get("VulnerabilityID", ""),
                    "title": v.get("Title", "")[:80]
                })
        return {"total": len(vulns), "vulnerabilities": vulns}
    except FileNotFoundError:
        return {"error": "trivy not installed"}
    except Exception as e:
        return {"error": str(e)[:200]}


def remote_docker_audit(ssh_user, ssh_host, ssh_port=22):
    """Run container audit on a remote host via SSH."""
    checks = [
        ("docker ps", "docker_info"),
        ("docker version --format '{{json .}}'", "docker_version"),
        ("docker images --format '{{.Repository}}:{{.Tag}}'", "images"),
        ("docker info 2>/dev/null | grep -E 'Storage|Cgroup|Runtimes|Security'", "docker_config"),
        ("cat /proc/1/status 2>/dev/null | grep CapEff", "capabilities"),
        ("mount 2>/dev/null | grep -E '/dev|/proc|/sys|/etc'", "mounts"),
    ]
    results = {}
    for cmd, key in checks:
        try:
            ssh_cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p {ssh_port} {ssh_user}@{ssh_host} {shlex.quote(cmd)} 2>/dev/null"
            r = subprocess.run(ssh_cmd, shell=True, capture_output=True, timeout=30, executable="/bin/bash")
            results[key] = r.stdout.decode("utf-8", errors="ignore")[:500]
        except:
            results[key] = "FAILED"
    return results


def inject_findings(project_id, ip, audit_results):
    """Inject container security findings into KB."""
    pid = get_project_id()
    hid = add_host(pid, ip, tags="container")
    count = 0
    for finding in audit_results.get("docker", []):
        add_vulnerability(hid, f"Docker: {finding['name']}",
                        severity=finding["risk"],
                        mitre_id=finding.get("mitre", "T1610"),
                        description=finding.get("desc", ""))
        count += 1
    for finding in audit_results.get("kubernetes", []):
        add_vulnerability(hid, f"K8s: {finding['name']}",
                        severity=finding["risk"],
                        mitre_id=finding.get("mitre", "T1525"),
                        description=finding.get("desc", ""))
        count += 1
    create_event(pid, "container_audit", "container_audit",
                f"Container audit for {ip}: {count} findings", json.dumps(audit_results), "info")
    return count

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "docker":
            results = audit_docker()
            print(json.dumps(results, indent=2))
        elif sys.argv[1] == "k8s":
            results = audit_kubernetes()
            print(json.dumps(results, indent=2))
        elif sys.argv[1] == "full":
            results = full_audit()
            print(json.dumps(results, indent=2))
        elif sys.argv[1] == "escape":
            results = full_audit()
            suggestions = escape_suggestions(results)
            print(json.dumps(suggestions, indent=2))
        elif sys.argv[1] == "inject" and len(sys.argv) > 2:
            ip = sys.argv[2]
            results = full_audit()
            count = inject_findings(None, ip, results)
            print(f"Injected {count} findings for {ip}")
        elif sys.argv[1] == "trivy" and len(sys.argv) > 2:
            target = sys.argv[2]
            img = target if ":" in target or "/" in target else None
            res = run_trivy_scan(image=img) if img else run_trivy_scan(path=target)
            print(json.dumps(res, indent=2))
        elif sys.argv[1] == "remote-audit" and len(sys.argv) > 3:
            res = remote_docker_audit(sys.argv[2], sys.argv[3],
                                      int(sys.argv[4]) if len(sys.argv) > 4 else 22)
            print(json.dumps(res, indent=2))
        else:
            print("Usage:")
            print("  container_audit.py docker                 - Audit local Docker")
            print("  container_audit.py k8s                    - Audit local K8s pod")
            print("  container_audit.py full                   - Full container audit")
            print("  container_audit.py escape                 - Suggest escape methods")
            print("  container_audit.py inject <ip>            - Audit + inject into KB")
            print("  container_audit.py trivy <image|path>     - Trivy vuln scan")
            print("  container_audit.py remote-audit <user> <host> [port]")
