#!/usr/bin/env python3
"""
APOLLO BloodHound Processor - Parse BloodHound JSON output,
extract AD attack paths, inject into knowledge base.
"""
import sys, os, json, glob, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import *

def parse_users(json_data):
    """Extract users from BloodHound JSON."""
    users = []
    for item in json_data.get("users", []):
        props = item.get("Properties", {})
        users.append({
            "objectid": props.get("objectid", ""),
            "name": props.get("name", ""),
            "samaccountname": props.get("samaccountname", props.get("displayname", "")),
            "enabled": props.get("enabled", True),
            "admin_count": props.get("admincount", 0),
            "domain": props.get("domain", ""),
            "title": props.get("title", ""),
            "email": props.get("email", ""),
            "pwdlastset": props.get("pwdlastset", 0),
            "lastlogon": props.get("lastlogon", 0),
            "sensitive": props.get("sensitive", False),
            "highvalue": props.get("highvalue", False),
        })
    return users

def parse_computers(json_data):
    computers = []
    for item in json_data.get("computers", []):
        props = item.get("Properties", {})
        computers.append({
            "objectid": props.get("objectid", ""),
            "name": props.get("name", ""),
            "operatingsystem": props.get("operatingsystem", ""),
            "enabled": props.get("enabled", True),
            "highvalue": props.get("highvalue", False),
            "domain": props.get("domain", ""),
            "sessions": props.get("sessions", []),
        })
    return computers

def parse_groups(json_data):
    groups = []
    for item in json_data.get("groups", []):
        props = item.get("Properties", {})
        groups.append({
            "objectid": props.get("objectid", ""),
            "name": props.get("name", ""),
            "domain": props.get("domain", ""),
            "highvalue": props.get("highvalue", False),
            "admin_count": props.get("admincount", 0),
        })
    return groups

def parse_edges(json_data):
    """Extract attack paths from BloodHound edges."""
    paths = []
    for edge in json_data.get("edges", []):
        paths.append({
            "source": edge.get("SourceNode", ""),
            "target": edge.get("TargetNode", ""),
            "label": edge.get("Label", ""),
            "type": edge.get("Type", ""),
        })
    return paths

def process_bloodhound_file(filepath, project_id=None):
    """Parse a BloodHound JSON file and return structured data."""
    if not os.path.exists(filepath):
        return {"error": f"File not found: {filepath}"}
    with open(filepath) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON"}
    users = parse_users(data)
    computers = parse_computers(data)
    groups = parse_groups(data)
    edges = parse_edges(data)
    return {
        "users": users, "computers": computers,
        "groups": groups, "edges": edges,
        "stats": {"users": len(users), "computers": len(computers),
                  "groups": len(groups), "edges": len(edges)}
    }

def _extract_ip(name):
    """Extract IP from computer name (e.g. 'DC01.domain.local' -> 'DC01')."""
    ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', name)
    if ip_match:
        return ip_match.group(1)
    host_part = name.split(".")[0] if "." in name else name
    return host_part if host_part else name

def inject_bloodhound_findings(project_id, filepath):
    """Parse BloodHound JSON and inject findings into KB."""
    data = process_bloodhound_file(filepath, project_id)
    if data.get("error"):
        return data
    pid = project_id if project_id else get_project_id()
    results = {"users_added": 0, "computers_added": 0, "paths_added": 0, "high_value_targets": []}
    dc_ips = set()
    for computer in data.get("computers", []):
        name = computer.get("name", "")
        ip = _extract_ip(name)
        os_info = computer.get("operatingsystem", "")
        hid = add_host(pid, ip, name, os_info,
                      tags="bloodhound,ad," + ("highvalue" if computer.get("highvalue") else "workstation"))
        results["computers_added"] += 1
        if computer.get("highvalue"):
            dc_ips.add(ip)
            results["high_value_targets"].append(ip)
    for group in data.get("groups", []):
        if group.get("admin_count", 0) > 0 or group.get("highvalue"):
            name = group.get("name", "")
            add_note(pid, f"AD Privileged Group: {name}", 
                    f"High-value AD group: {name} (Domain: {group.get('domain', '')})",
                    "ad-privilege")
    for edge in data.get("edges", []):
        if edge.get("label") in ("MemberOf", "AdminTo", "HasSession", "ForceChangePassword",
                                 "AddMember", "AllExtendedRights", "GenericAll", "WriteDacl",
                                 "CanRDP", "SQLAdmin", "DCSync", "GetChanges", "GetChangesAll",
                                 "Owns", "WriteOwner", "ExecuteDCOM", "ReadLAPSPassword"):
            source = edge.get("source", "")
            target = edge.get("target", "")
            technique = f"BloodHound: {edge.get('label', '')}"
            add_attack_path(pid, source, target, technique,
                          mitre_id="T1482" if "DCSync" in technique else "T1069",
                          service_used="AD", description=f"BloodHound edge: {edge.get('label', '')} from {source} to {target}")
            results["paths_added"] += 1
    results["dc_targets"] = list(dc_ips)
    create_event(pid, "bloodhound", "bloodhound_processor",
                f"BloodHound analysis: {results['computers_added']} computers, {results['paths_added']} attack paths",
                json.dumps(results), "info")
    return results

def suggest_ad_attacks(project_id):
    """Suggest AD attack paths from KB."""
    paths = get_attack_paths(project_id)
    creds = get_credentials(project_id)
    suggestions = []
    dcsync_paths = [p for p in paths if "DCSync" in p.get("technique", "")]
    if dcsync_paths:
        suggestions.append({
            "technique": "DCSync Attack",
            "mitre_id": "T1003.006",
            "command": "impacket-secretsdump -just-dc <domain>/<user>:<password>@<dc_ip>",
            "priority": "critical"
        })
    admin_paths = [p for p in paths if "AdminTo" in p.get("technique", "")]
    if admin_paths:
        suggestions.append({
            "technique": "AdminTo Lateral Movement",
            "mitre_id": "T1021.002",
            "command": "crackmapexec smb <target> -u <user> -p <pass> -x whoami",
            "priority": "high"
        })
    force_reset = [p for p in paths if "ForceChangePassword" in p.get("technique", "")]
    if force_reset:
        suggestions.append({
            "technique": "Force Change Password",
            "mitre_id": "T1098",
            "command": "bloodyAD --host <dc> -d <domain> -u <user> -p <pass> set password <target> <newpass>",
            "priority": "high"
        })
    generic_all = [p for p in paths if "GenericAll" in p.get("technique", "")]
    if generic_all:
        suggestions.append({
            "technique": "GenericAll ACE Abuse",
            "mitre_id": "T1098",
            "command": "Add-DomainObjectAcl -TargetIdentity <target> -PrincipalIdentity <user> -Rights All",
            "priority": "high"
        })
    return suggestions

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "parse" and len(sys.argv) > 2:
            result = process_bloodhound_file(sys.argv[2])
            print(json.dumps(result["stats"] if "stats" in result else result, indent=2))
        elif sys.argv[1] == "inject" and len(sys.argv) > 2:
            pid = int(sys.argv[3]) if len(sys.argv) > 3 else get_project_id()
            result = inject_bloodhound_findings(pid, sys.argv[2])
            print(json.dumps(result, indent=2))
        elif sys.argv[1] == "suggest":
            pid = int(sys.argv[2]) if len(sys.argv) > 2 else get_project_id()
            suggestions = suggest_ad_attacks(pid)
            print(json.dumps(suggestions, indent=2))
        else:
            print("Usage:")
            print("  bloodhound_processor.py parse <bloodhound.json>")
            print("  bloodhound_processor.py inject <bloodhound.json> [project_id]")
            print("  bloodhound_processor.py suggest [project_id]")
