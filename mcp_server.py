#!/usr/bin/env python3
"""
APOLLO MCP Server v4 - Full KB + NVD + Notifications + Container +
BloodHound + API + Phishing + Wireless + Payload integration.
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import *
from planner import generate_plan
from report_generator import generate_report
from nvd_enricher import fetch_cve, search_cve, fetch_epss, load_kev, auto_enrich_kb
from notifications import alert, alert_new_host, alert_new_vuln, alert_new_cred, alert_new_session, send_test as notif_test, configure_interactive as notif_configure
from bloodhound_processor import process_bloodhound_file, inject_bloodhound_findings, suggest_ad_attacks
from container_audit import audit_docker, audit_kubernetes, full_audit as container_full_audit, escape_suggestions, inject_findings as container_inject, run_trivy_scan, remote_docker_audit
from payload_server import PayloadServer, add_payload, list_payloads, generate_powershell_download, generate_curl_download, generate_wget_download
from api_tester import APITester, analyze_results as api_analyze, inject_findings as api_inject
from phishing_engine import create_phishing_page, create_campaign, list_campaigns, list_templates, generate_phishing_server, send_campaign_emails, track_click
from wireless_auditor import scan_networks, audit_network_security, check_tools as wireless_check_tools, deauth_detected
from auto_pwn import find_exploits as autopwn_find, auto_pwn as autopwn_run, attempt_exploit_rpc as autopwn_attempt, suggest_default_creds as autopwn_creds
from tool_registry import detect_tools, get_available_tools, is_available, run_tool, summary as tool_summary, install_missing
try:
    from naabu_wrapper import run_port_scan, smart_scan, inject_naabu_results, classify_ports, port_exploit_map, attack_surface_summary as naabu_surface
    NAABU_WRAPPER = True
except: NAABU_WRAPPER = False
try:
    from subfinder_wrapper import discover_subdomains, verify_and_enrich, detect_takeovers, full_subdomain_enum, inject_to_kb as subfinder_inject, scope_expansion
    SUBFINDER_WRAPPER = True
except: SUBFINDER_WRAPPER = False
try:
    from dnsx_wrapper import enum_dns_records, wildcard_detection, zone_transfer_attempt, full_dns_recon, dns_attack_surface
    DNSX_WRAPPER = True
except: DNSX_WRAPPER = False
try:
    from recon_deep import recon_deep, recon_auto
    RECON_DEEP = True
except: RECON_DEEP = False
from evasion_engine import generate_amsi_bypass_script, generate_obfuscated_powershell, generate_sandbox_detection_script
from pivot_planner import execute_ssh_socks, execute_chisel_pivot, generate_pivot_commands as pivot_plan
from attack_graph import find_path_to as graph_paths, analyze_attack_surface as graph_surface, shortest_chain_report as graph_report, build_graph as graph_build
from c2_commander import list_all_sessions as c2_list, run_command_on_session as c2_run, auto_privesc as c2_privesc, detect_pivot_network as c2_pivot, session_health as c2_health, setup_listener as c2_listen
from cred_vault import vault_summary as cred_summary, detect_hash_type as cred_detect, generate_crack_commands as cred_crack, generate_spray_commands as cred_spray, cred_reuse_matrix as cred_matrix, pass_the_hash_commands as cred_pth, crack_queue as cred_queue
from ioc_engine import extract_iocs as ioc_extract, enrich_ip as ioc_enrich_ip, enrich_hash as ioc_enrich_hash, enrich_domain as ioc_enrich_domain, hunt_iocs as ioc_hunt, extract_from_kb as ioc_from_kb, to_stix as ioc_stix
from recon_monitor import monitor_once as monitor_once_fn, load_state as monitor_state, scan_baseline as monitor_scan
from exploit_sync import sync_exploits as exploit_sync_fn, match_vuln_to_exploit as exploit_match, get_exploit_code as exploit_get, exploit_summary as exploit_sum, clear_cache as exploit_clear

def handle_request(request):
    action = request.get("action", "")
    args = request.get("args", {})
    p = get_active_project()
    pid = create_project(p)

    # --- Original KB actions ---
    if action == "kb_summary":
        return {"type": "text", "content": summary(pid)}
    elif action == "kb_stats":
        return {"type": "text", "content": json.dumps(stats(pid), indent=2)}
    elif action == "kb_add_host":
        hid = add_host(pid, args.get("ip"), args.get("hostname", ""),
                      args.get("os", ""), args.get("mac", ""),
                      args.get("status", "up"), args.get("tags", ""))
        return {"type": "text", "content": f"Host added: {args.get('ip')} (ID: {hid})"}
    elif action == "kb_add_vuln":
        hosts = get_hosts(pid)
        for h in hosts:
            if h["ip"] == args.get("ip"):
                vid = add_vulnerability(h["id"], args.get("name"),
                    args.get("severity", "medium"),
                    description=args.get("description", ""),
                    cve_id=args.get("cve", ""), mitre_id=args.get("mitre_id", ""),
                    evidence=args.get("evidence", ""))
                return {"type": "text", "content": f"Vuln added: {args.get('name')} (ID: {vid})"}
        return {"type": "text", "content": "Host not found"}
    elif action == "kb_add_cred":
        hosts = get_hosts(pid)
        hid = None
        ip = args.get("ip", "")
        for h in hosts:
            if h["ip"] == ip: hid = h["id"]; break
        cid = add_credential(hid, args.get("service", ""), args.get("username", ""),
                           args.get("password", ""), args.get("hash", ""),
                           args.get("domain", ""), args.get("ntlm", ""),
                           args.get("source", "manual"))
        return {"type": "text", "content": f"Cred added (ID: {cid})"}
    elif action == "kb_creds":
        creds = get_credentials(pid)
        return {"type": "credentials", "content": creds}
    elif action == "kb_add_session":
        hosts = get_hosts(pid)
        hid = None
        ip = args.get("ip", "")
        for h in hosts:
            if h["ip"] == ip: hid = h["id"]; break
        if not hid: hid = add_host(pid, ip)
        sid = add_c2_session(hid, args.get("session_type", "shell"),
                           args.get("session_id", ""), args.get("platform", ""),
                           args.get("privilege", ""), args.get("listener_addr", ""),
                           args.get("listener_port", 0))
        return {"type": "text", "content": f"Session tracked (ID: {sid})"}
    elif action == "kb_sessions":
        sessions = get_c2_sessions(pid, args.get("status", "active"))
        return {"type": "text", "content": json.dumps(sessions, indent=2, default=str)}
    elif action == "kb_add_path":
        aid = add_attack_path(pid, args.get("source", ""), args.get("target", ""),
                            args.get("technique", ""), args.get("mitre_id", ""),
                            args.get("service", ""), args.get("credential", ""),
                            args.get("success", 1), args.get("description", ""))
        return {"type": "text", "content": f"Attack path added (ID: {aid})"}
    elif action == "kb_paths":
        paths = get_attack_paths(pid)
        return {"type": "text", "content": json.dumps(paths, indent=2, default=str)}
    elif action == "kb_timeline":
        events = get_timeline(pid, args.get("limit", 50))
        return {"type": "text", "content": json.dumps(events, indent=2, default=str)}
    elif action == "kb_export":
        data = export_project(pid)
        return {"type": "text", "content": json.dumps(data, indent=2, default=str)}
    elif action == "kb_hosts":
        hosts = get_hosts(pid)
        return {"type": "text", "content": json.dumps(hosts, indent=2, default=str)}
    elif action == "kb_vulns":
        vulns = get_vulnerabilities(pid)
        return {"type": "text", "content": json.dumps(vulns, indent=2, default=str)}
    elif action == "kb_search":
        results = suggest_targets(pid, args.get("query", ""))
        return {"type": "text", "content": json.dumps(results, indent=2)}
    elif action == "kb_note":
        nid = add_note(pid, args.get("title", ""), args.get("content", ""),
                      args.get("category", "general"))
        return {"type": "text", "content": f"Note added (ID: {nid})"}
    elif action == "kb_notes":
        notes = get_notes(pid, args.get("category"))
        return {"type": "text", "content": json.dumps(notes, indent=2, default=str)}
    elif action == "kb_log":
        cid = log_command(pid, args.get("command", ""), args.get("tool", ""),
                        args.get("target", ""), args.get("output", ""),
                        args.get("exit_code", 0))
        return {"type": "text", "content": f"Command logged (ID: {cid})"}

    # New KB actions
    elif action == "kb_update_host":
        hid = update_host(args.get("host_id"), args.get("hostname"),
                         args.get("os"), args.get("status"), args.get("tags"))
        return {"type": "text", "content": f"Host updated (ID: {hid})"}
    elif action == "kb_add_port":
        hosts = get_hosts(pid)
        for h in hosts:
            if h["ip"] == args.get("ip"):
                pid2 = add_port(h["id"], args.get("port"), args.get("protocol","tcp"),
                               args.get("service",""), args.get("version",""),
                               args.get("state","open"), args.get("banner",""))
                return {"type": "text", "content": f"Port added (ID: {pid2})"}
        return {"type": "text", "content": "Host not found"}
    elif action == "kb_ports":
        hosts = get_hosts(pid)
        all_ports = []
        for h in hosts:
            ports = get_ports(h["id"])
            for p in ports:
                p["ip"] = h["ip"]
                all_ports.append(p)
        return {"type": "text", "content": json.dumps(all_ports, indent=2, default=str)}
    elif action == "kb_update_vuln":
        updated = update_vuln_status(args.get("vuln_id"), args.get("status","open"),
                                     args.get("evidence",""))
        return {"type": "text", "content": f"Vuln updated: {updated}"}
    elif action == "kb_update_session":
        updated = update_c2_session(args.get("session_id"), args.get("status","active"))
        return {"type": "text", "content": f"Session updated: {updated}"}
    elif action == "kb_add_command":
        cid = add_c2_command(args.get("session_id"), args.get("command",""),
                             args.get("result",""), args.get("exit_code",0))
        return {"type": "text", "content": f"C2 command logged (ID: {cid})"}
    elif action == "kb_import":
        data = args.get("data", {})
        if isinstance(data, str):
            try: data = json.loads(data)
            except: return {"type": "error", "content": "Invalid JSON data"}
        result = import_project(data)
        return {"type": "text", "content": json.dumps(result, indent=2, default=str)}
    elif action == "kb_suggest":
        results = suggest_targets(pid, args.get("query", ""))
        return {"type": "text", "content": json.dumps(results, indent=2)}
    elif action == "kb_event":
        eid = create_event(pid, args.get("event_type","info"), args.get("source","mcp"),
                          args.get("description",""), args.get("severity","info"),
                          data=args.get("data"))
        return {"type": "text", "content": f"Event created (ID: {eid})"}

    elif action == "plan":
        return {"type": "text", "content": generate_plan(pid)}
    elif action == "report":
        out = args.get("output", "")
        report = generate_report(pid, out if out else None)
        return {"type": "text", "content": report}
    elif action == "project_list":
        return {"type": "text", "content": json.dumps(list_projects(), indent=2, default=str)}
    elif action == "project_set":
        if args.get("name"):
            set_active_project(args["name"])
            return {"type": "text", "content": f"Active project: {args['name']}"}

    # --- NVD/CVE Enrichment ---
    elif action == "cve_fetch":
        return {"type": "text", "content": json.dumps(fetch_cve(args.get("cve", "")), indent=2)}
    elif action == "cve_enrich":
        return {"type": "text", "content": json.dumps(fetch_cve(args.get("cve", "")), indent=2)}
    elif action == "cve_enrich_all":
        return {"type": "text", "content": json.dumps(auto_enrich_kb(pid), indent=2)}
    elif action == "cve_search":
        return {"type": "text", "content": json.dumps(search_cve(args.get("query", ""), args.get("limit", 10)), indent=2)}
    elif action == "cve_kev":
        return {"type": "text", "content": json.dumps(load_kev(), indent=2)}
    elif action == "cve_epss":
        return {"type": "text", "content": json.dumps(fetch_epss(args.get("cve", "")), indent=2)}

    # --- Notifications ---
    elif action == "notify_alert":
        result = alert(args.get("message", ""), args.get("severity", "info"))
        return {"type": "text", "content": json.dumps(result, indent=2)}
    elif action == "notify_test":
        return {"type": "text", "content": json.dumps(notif_test(), indent=2)}
    elif action == "notify_configure":
        return {"type": "text", "content": "Use python3 -c 'from notifications import configure_interactive; configure_interactive()'"}
    elif action == "notify_clear_dedup":
        from notifications import clear_dedup
        return {"type": "text", "content": json.dumps(clear_dedup(), indent=2)}

    # --- BloodHound ---
    elif action == "bh_parse":
        result = process_bloodhound_file(args.get("file", ""))
        return {"type": "text", "content": json.dumps(result.get("stats", result), indent=2)}
    elif action == "bh_inject":
        result = inject_bloodhound_findings(pid, args.get("file", ""))
        return {"type": "text", "content": json.dumps(result, indent=2)}
    elif action == "bh_suggest":
        return {"type": "text", "content": json.dumps(suggest_ad_attacks(pid), indent=2)}

    # --- Container Security ---
    elif action == "container_docker":
        return {"type": "text", "content": json.dumps(audit_docker(), indent=2)}
    elif action == "container_k8s":
        return {"type": "text", "content": json.dumps(audit_kubernetes(), indent=2)}
    elif action == "container_full":
        return {"type": "text", "content": json.dumps(container_full_audit(), indent=2)}
    elif action == "container_escape":
        return {"type": "text", "content": json.dumps(escape_suggestions(container_full_audit()), indent=2)}
    elif action == "container_inject":
        count = container_inject(pid, args.get("ip", ""), container_full_audit())
        return {"type": "text", "content": f"Injected {count} container findings"}
    elif action == "container_trivy":
        return {"type": "text", "content": json.dumps(run_trivy_scan(args.get("image"), args.get("path")), indent=2)}
    elif action == "container_remote_audit":
        return {"type": "text", "content": json.dumps(remote_docker_audit(args.get("user", "root"), args.get("host", ""), args.get("port", 22)), indent=2)}

    # --- Payload Server ---
    elif action == "payload_list":
        return {"type": "text", "content": json.dumps(list_payloads(), indent=2)}
    elif action == "payload_add":
        return {"type": "text", "content": json.dumps(add_payload(args.get("file", "")), indent=2)}
    elif action == "payload_gen_ps":
        return {"type": "text", "content": generate_powershell_download(args.get("url", ""))}
    elif action == "payload_gen_curl":
        return {"type": "text", "content": generate_curl_download(args.get("url", ""))}
    elif action == "payload_gen_wget":
        return {"type": "text", "content": generate_wget_download(args.get("url", ""))}

    # --- API Tester ---
    elif action == "api_discover":
        tester = APITester(args.get("url", ""))
        return {"type": "text", "content": json.dumps(tester.discover_endpoints(), indent=2)}
    elif action == "api_full":
        tester = APITester(args.get("url", ""))
        results = tester.full_test()
        return {"type": "text", "content": json.dumps(results, indent=2)}
    elif action == "api_inject":
        tester = APITester(args.get("url", ""))
        results = tester.full_test()
        count = api_inject(pid, args.get("url", ""), results)
        return {"type": "text", "content": f"API test injected {count} findings"}

    # --- Phishing ---
    elif action == "phish_templates":
        return {"type": "text", "content": json.dumps(list_templates(), indent=2)}
    elif action == "phish_create_page":
        result = create_phishing_page(args.get("template", "microsoft_login"))
        return {"type": "text", "content": json.dumps(result, indent=2)}
    elif action == "phish_create_campaign":
        targets = args.get("targets", "")
        result = create_campaign(args.get("name", "Campaign"), args.get("template"), targets.split(",") if targets else [])
        return {"type": "text", "content": json.dumps({k:v for k,v in result.items() if k != "captured_creds"}, indent=2)}
    elif action == "phish_list":
        return {"type": "text", "content": json.dumps(list_campaigns(), indent=2)}
    elif action == "phish_gen_server":
        result = generate_phishing_server(args.get("template", "microsoft_login"), args.get("port", 8080))
        return {"type": "text", "content": json.dumps(result, indent=2)}
    elif action == "phish_send":
        result = send_campaign_emails(args.get("campaign_id"), args.get("smtp_server", "localhost"),
                                      args.get("smtp_port", 25), args.get("smtp_user", ""),
                                      args.get("smtp_pass", ""), template_name=args.get("template", "password_expiry"))
        return {"type": "text", "content": json.dumps(result, indent=2)}
    elif action == "phish_track_click":
        result = track_click(args.get("campaign_id"), args.get("target_idx"))
        return {"type": "text", "content": json.dumps(result, indent=2)}

    # --- Wireless ---
    elif action == "wireless_check":
        return {"type": "text", "content": json.dumps(wireless_check_tools(), indent=2)}
    elif action == "wireless_scan":
        networks = scan_networks(args.get("interface", "wlan0"), args.get("timeout", 15))
        return {"type": "text", "content": json.dumps(networks[:20] if isinstance(networks, list) else networks, indent=2)}
    elif action == "wireless_audit":
        networks = scan_networks(args.get("interface", "wlan0"), args.get("timeout", 15))
        findings = audit_network_security(networks)
        return {"type": "text", "content": json.dumps({"findings": findings}, indent=2)}

    # --- Auto-Pwn Engine ---
    elif action == "autopwn_find":
        return {"type": "text", "content": json.dumps(autopwn_find(pid), indent=2, default=str)}
    elif action == "autopwn_check":
        result = autopwn_run(pid, dry_run=True, max_attempts=args.get("max", 20))
        return {"type": "text", "content": json.dumps(result, indent=2, default=str)}
    elif action == "autopwn_exploit":
        result = autopwn_run(pid, lhost=args.get("lhost"), lport=args.get("lport", 4444),
                            dry_run=False, max_attempts=args.get("max", 20))
        return {"type": "text", "content": json.dumps(result, indent=2, default=str)}
    elif action == "autopwn_creds":
        return {"type": "text", "content": json.dumps(autopwn_creds(pid), indent=2, default=str)}

    # --- Attack Graph ---
    elif action == "graph_paths":
        return {"type": "text", "content": json.dumps(graph_paths(pid, args.get("target_ip")), indent=2, default=str)}
    elif action == "graph_surface":
        return {"type": "text", "content": json.dumps(graph_surface(pid), indent=2, default=str)}
    elif action == "graph_report":
        return {"type": "text", "content": graph_report(pid, args.get("target_ip"))}
    elif action == "graph_dot":
        g = graph_build(pid)
        return {"type": "text", "content": g.to_dot()}

    # --- C2 Commander ---
    elif action == "c2_sessions":
        return {"type": "text", "content": json.dumps(c2_list(pid), indent=2, default=str)}
    elif action == "c2_run":
        return {"type": "text", "content": json.dumps(c2_run(args.get("session",""), args.get("command",""), args.get("framework","auto")), indent=2, default=str)}
    elif action == "c2_privesc":
        return {"type": "text", "content": json.dumps(c2_privesc(args.get("session",""), args.get("platform","linux")), indent=2, default=str)}
    elif action == "c2_pivot":
        return {"type": "text", "content": json.dumps(c2_pivot(args.get("session",""), "auto", args.get("platform","linux")), indent=2, default=str)}
    elif action == "c2_health":
        return {"type": "text", "content": json.dumps(c2_health(pid), indent=2, default=str)}
    elif action == "c2_listen":
        return {"type": "text", "content": json.dumps(c2_listen(args.get("lhost","0.0.0.0"), args.get("lport",4444), args.get("payload","windows/x64/meterpreter/reverse_tcp")), indent=2, default=str)}

    # --- Credential Vault ---
    elif action == "cred_summary":
        return {"type": "text", "content": json.dumps(cred_summary(pid), indent=2, default=str)}
    elif action == "cred_detect":
        return {"type": "text", "content": json.dumps(cred_detect(args.get("hash","")), indent=2)}
    elif action == "cred_crack":
        return {"type": "text", "content": json.dumps(cred_crack(args.get("hash",""), args.get("wordlist","rockyou")), indent=2)}
    elif action == "cred_spray":
        return {"type": "text", "content": json.dumps(cred_spray(pid, args.get("ip"), args.get("service","smb")), indent=2, default=str)}
    elif action == "cred_matrix":
        return {"type": "text", "content": json.dumps(cred_matrix(pid), indent=2, default=str)}
    elif action == "cred_pth":
        return {"type": "text", "content": json.dumps(cred_pth(pid, args.get("ip")), indent=2, default=str)}
    elif action == "cred_queue":
        return {"type": "text", "content": json.dumps(cred_queue(pid), indent=2, default=str)}

    # --- IOC Engine ---
    elif action == "ioc_extract":
        return {"type": "text", "content": json.dumps(ioc_extract(args.get("text","")), indent=2)}
    elif action == "ioc_hunt":
        return {"type": "text", "content": json.dumps(ioc_hunt(args.get("text",""), pid), indent=2, default=str)}
    elif action == "ioc_kb":
        return {"type": "text", "content": json.dumps(ioc_from_kb(pid), indent=2, default=str)}
    elif action == "ioc_stix":
        return {"type": "text", "content": json.dumps(ioc_stix(ioc_extract(args.get("text",""))), indent=2, default=str)}
    elif action == "ioc_enrich_ip":
        return {"type": "text", "content": json.dumps(ioc_enrich_ip(args.get("ip","")), indent=2, default=str)}

    # --- Recon Monitor ---
    elif action == "monitor_once":
        return {"type": "text", "content": json.dumps(monitor_once_fn(args.get("target",""), pid, args.get("scan_type","quick")), indent=2, default=str)}
    elif action == "monitor_state":
        return {"type": "text", "content": json.dumps(monitor_state(), indent=2, default=str)}
    elif action == "monitor_scan":
        return {"type": "text", "content": json.dumps(monitor_scan(args.get("target",""), args.get("scan_type","quick")), indent=2, default=str)}

    # --- Exploit Sync ---
    elif action == "exploit_sync":
        return {"type": "text", "content": json.dumps(exploit_sync_fn(pid, args.get("force",False)), indent=2, default=str)}
    elif action == "exploit_match":
        return {"type": "text", "content": json.dumps(exploit_match(args.get("name"), args.get("cve")), indent=2, default=str)}
    elif action == "exploit_get":
        return {"type": "text", "content": json.dumps(exploit_get(args.get("edb_id","")), indent=2, default=str)}
    elif action == "exploit_summary":
        return {"type": "text", "content": json.dumps(exploit_sum(pid), indent=2, default=str)}
    elif action == "exploit_clear":
        return {"type": "text", "content": exploit_clear()}

    # --- Evasion Engine ---
    elif action == "evasion_amsi":
        result = generate_amsi_bypass_script(args.get("output"))
        return {"type": "text", "content": (result if isinstance(result, str) else json.dumps(result))}
    elif action == "evasion_obfuscate":
        result = generate_obfuscated_powershell(args.get("command", "whoami"), args.get("output"))
        return {"type": "text", "content": result if isinstance(result, str) else json.dumps(result)}
    elif action == "evasion_sandbox":
        result = generate_sandbox_detection_script(args.get("output"))
        return {"type": "text", "content": json.dumps(result, indent=2)}

    # --- Pivot Planner ---
    elif action == "pivot_plan":
        return {"type": "text", "content": json.dumps(pivot_plan(args.get("source",""), args.get("target","")), indent=2)}
    elif action == "pivot_exec_ssh":
        result = execute_ssh_socks(args.get("pivot_ip"), args.get("username","root"),
                                   args.get("port",22), args.get("socks_port",1080))
        return {"type": "text", "content": json.dumps(result, indent=2)}
    elif action == "pivot_exec_chisel":
        result = execute_chisel_pivot(args.get("pivot_ip"), args.get("chisel_bin","./chisel"),
                                      args.get("server_port",8000), args.get("socks_port",1080))
        return {"type": "text", "content": json.dumps(result, indent=2)}

    # --- Tool Registry ---
    elif action == "tool_summary":
        return {"type": "text", "content": json.dumps(tool_summary(), indent=2)}
    elif action == "tool_check":
        return {"type": "text", "content": json.dumps({"available": is_available(args.get("name",""))})}
    elif action == "tool_run":
        result = run_tool(args.get("name",""), args.get("args",""), args.get("timeout", 60))
        return {"type": "text", "content": json.dumps(result, indent=2, default=str)}
    elif action == "tool_install":
        return {"type": "text", "content": json.dumps(install_missing(args.get("name","")), indent=2)}
    elif action == "tool_categories":
        return {"type": "text", "content": json.dumps(get_available_tools(args.get("category")), indent=2)}

    # --- naabu Wrapper ---
    elif action == "naabu_scan":
        if not NAABU_WRAPPER: return {"type": "error", "content": "naabu_wrapper not loaded"}
        return {"type": "text", "content": json.dumps(smart_scan(pid, args.get("target",""), args.get("depth","normal")), indent=2, default=str)}
    elif action == "naabu_quick":
        if not NAABU_WRAPPER: return {"type": "error", "content": "naabu_wrapper not loaded"}
        return {"type": "text", "content": json.dumps(run_port_scan(args.get("target",""), args.get("ports","top-100"), args.get("rate",3000)), indent=2, default=str)}
    elif action == "naabu_surface":
        if not NAABU_WRAPPER: return {"type": "error", "content": "naabu_wrapper not loaded"}
        return {"type": "text", "content": json.dumps(naabu_surface(pid), indent=2, default=str)}
    elif action == "naabu_exploit_map":
        return {"type": "text", "content": json.dumps(port_exploit_map(args.get("port",80), args.get("service")), indent=2)}

    # --- subfinder Wrapper ---
    elif action == "subfinder_enum":
        if not SUBFINDER_WRAPPER: return {"type": "error", "content": "subfinder_wrapper not loaded"}
        return {"type": "text", "content": json.dumps(full_subdomain_enum(pid, args.get("domain",""), args.get("recursive",False)), indent=2, default=str)}
    elif action == "subfinder_quick":
        if not SUBFINDER_WRAPPER: return {"type": "error", "content": "subfinder_wrapper not loaded"}
        return {"type": "text", "content": json.dumps(discover_subdomains(args.get("domain",""), args.get("recursive",False)), indent=2, default=str)}
    elif action == "subfinder_scope":
        if not SUBFINDER_WRAPPER: return {"type": "error", "content": "subfinder_wrapper not loaded"}
        return {"type": "text", "content": json.dumps(scope_expansion(pid, args.get("domain","")), indent=2, default=str)}

    # --- dnsx Wrapper ---
    elif action == "dnsx_recon":
        if not DNSX_WRAPPER: return {"type": "error", "content": "dnsx_wrapper not loaded"}
        return {"type": "text", "content": json.dumps(full_dns_recon(pid, args.get("domain","")), indent=2, default=str)}
    elif action == "dnsx_records":
        if not DNSX_WRAPPER: return {"type": "error", "content": "dnsx_wrapper not loaded"}
        return {"type": "text", "content": json.dumps(enum_dns_records(args.get("domain","")), indent=2, default=str)}
    elif action == "dnsx_attack_surface":
        if not DNSX_WRAPPER: return {"type": "error", "content": "dnsx_wrapper not loaded"}
        return {"type": "text", "content": json.dumps(dns_attack_surface(pid, args.get("domain","")), indent=2, default=str)}
    elif action == "dnsx_wildcard":
        if not DNSX_WRAPPER: return {"type": "error", "content": "dnsx_wrapper not loaded"}
        return {"type": "text", "content": json.dumps(wildcard_detection(args.get("domain","")), indent=2, default=str)}
    elif action == "dnsx_zone_transfer":
        if not DNSX_WRAPPER: return {"type": "error", "content": "dnsx_wrapper not loaded"}
        return {"type": "text", "content": json.dumps(zone_transfer_attempt(args.get("domain","")), indent=2, default=str)}

    # --- Recon Deep (Unified Orchestrator) ---
    elif action == "recon_deep":
        if not RECON_DEEP: return {"type": "error", "content": "recon_deep not loaded"}
        return {"type": "text", "content": json.dumps(recon_deep(pid, args.get("target",""), args.get("depth","normal"), args.get("scope","domain")), indent=2, default=str)}
    elif action == "recon_auto":
        if not RECON_DEEP: return {"type": "error", "content": "recon_deep not loaded"}
        return {"type": "text", "content": json.dumps(recon_auto(pid, args.get("targets",[])), indent=2, default=str)}
    elif action == "recon_full":
        if not RECON_DEEP: return {"type": "error", "content": "recon_deep not loaded"}
        return {"type": "text", "content": json.dumps(recon_deep(pid, args.get("target",""), "deep", args.get("scope","domain")), indent=2, default=str)}

    # Deep Test Actions (v4 - from live bug bounty validation)
    elif action == "deep_cors_test":
        """Test CORS across multiple origins, methods, and endpoints."""
        target = args.get("target", "")
        if not target: return {"type": "error", "content": "target required"}
        import subprocess, base64, json as _json
        origins = ["https://evil.com", "https://attacker.org", "null", "https://192.168.1.1",
                   "https://localhost:3000", "http://evil.com", "https://evil.com:8080"]
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]
        endpoints = args.get("endpoints", ["/", "/.well-known/openid-configuration", "/api/auth/session"])
        results = {"target": target, "origins_tested": 0, "methods_tested": 0,
                   "vulnerable_origins": [], "vulnerable_methods": [], "jwt_leak": False}
        for ep in endpoints:
            url = f"https://{target}{ep}"
            for origin in origins:
                r = subprocess.run(["curl", "-sk", "-D", "-", "-o", "/dev/null", url,
                    "-H", f"Origin: {origin}", "--connect-timeout", "5", "--max-time", "8"],
                    capture_output=True, text=True, timeout=15)
                aaco = "access-control-allow-origin" in r.stdout
                acac = "access-control-allow-credentials: true" in r.stdout
                if aaco and acac:
                    results["vulnerable_origins"].append(origin)
                    # Extract Location header for JWT
                    for line in r.stdout.split("\n"):
                        if line.lower().startswith("location:"):
                            loc = line.split(":", 1)[1].strip()
                            if "meta=" in loc:
                                meta = loc.split("meta=")[1].split("&")[0]
                                try:
                                    padded = meta + "=="[: (4 - len(meta) % 4) % 4]
                                    parts = meta.split(".")
                                    if len(parts) >= 2:
                                        pay = parts[1] + "=="[: (4 - len(parts[1]) % 4) % 4]
                                        decoded = _json.loads(base64.urlsafe_b64decode(pay))
                                        results["jwt_leak"] = True
                                        results["jwt_payload"] = decoded
                                except: pass
            for method in methods:
                r = subprocess.run(["curl", "-sk", "-D", "-", "-o", "/dev/null", "-X", method, url,
                    "-H", "Origin: https://evil.com", "--connect-timeout", "5", "--max-time", "8"],
                    capture_output=True, text=True, timeout=15)
                if "access-control-allow-origin" in r.stdout and "access-control-allow-credentials: true" in r.stdout:
                    results["vulnerable_methods"].append(method)
        results["origins_tested"] = len(origins)
        results["methods_tested"] = len(methods)
        results["vulnerable"] = len(results["vulnerable_origins"]) > 0
        create_event(pid, "deep_cors_test", "mcp_server", f"CORS test for {target}: {len(results['vulnerable_origins'])} vulnerable origins", results, "high" if results["vulnerable"] else "info")
        return {"type": "text", "content": _json.dumps(results, indent=2, default=str)}

    elif action == "deep_takeover_check":
        """Check subdomain takeover feasibility (CloudFront edge, SSL, DNS)."""
        target = args.get("target", "")
        if not target: return {"type": "error", "content": "target required"}
        import subprocess, json as _json
        results = {"target": target, "dns": {}, "cloudfront_edge": {}, "acm_feasibility": "", "takeover_possible": False}
        # DNS check - use nslookup for reliable CNAME detection
        r = subprocess.run(["nslookup", target, "8.8.8.8"], capture_output=True, text=True, timeout=10)
        nslookup_out = r.stdout
        cname = ""
        if "canonical name" in nslookup_out.lower():
            import re as _re
            cm = _re.search(r'canonical name = (\S+)', nslookup_out, _re.IGNORECASE)
            if cm: cname = cm.group(1).rstrip(".")
        results["dns"]["cname"] = cname if cname else "none"
        # Check if the CNAME target resolves
        if cname:
            r = subprocess.run(["dig", "+short", cname, "A"], capture_output=True, text=True, timeout=10)
            target_a = r.stdout.strip()
            results["dns"]["cname_target_a"] = target_a if target_a else "none"
            # Check CNAME target CNAME chain
            r = subprocess.run(["dig", "+short", cname, "CNAME"], capture_output=True, text=True, timeout=10)
            inner = r.stdout.strip()
            results["dns"]["cname_target_cname"] = inner if inner else "none"
        # Check final A record for the CNAME chain
        if cname:
            r = subprocess.run(["host", target, "8.8.8.8"], capture_output=True, text=True, timeout=10)
            host_out = r.stdout
            has_address = "has address" in host_out.lower() or "has IPv6 address" in host_out.lower()
            results["dns"]["resolves"] = has_address
            results["dns"]["dangling"] = bool(cname) and not has_address
            # CloudFront edge check
            try:
                edge_ip = subprocess.run(["dig", "+short", cname.split()[0] if " " in cname else cname, "A"],
                    capture_output=True, text=True, timeout=10).stdout.strip().split("\n")[0]
                if edge_ip:
                    r = subprocess.run(["curl", "-sk", "--connect-timeout", "5",
                        "--resolve", f"{target}:443:{edge_ip}",
                        f"https://{target}/", "-H", f"Host: {target}", "-o", "/dev/null", "-w", "%{http_code}"],
                        capture_output=True, text=True, timeout=15)
                    results["cloudfront_edge"]["reachable"] = True
                    results["cloudfront_edge"]["http_code"] = r.stdout.strip()
                    results["cloudfront_edge"]["response"] = "403_no_distribution" if "403" in r.stdout else r.stdout.strip()
            except: results["cloudfront_edge"]["reachable"] = False
        else:
            results["dns"]["dangling"] = False
        results["takeover_possible"] = results["dns"].get("dangling", False) and results["cloudfront_edge"].get("reachable", False)
        create_event(pid, "deep_takeover_check", "mcp_server", f"Takeover check for {target}: DNS dangling={results['dns'].get('dangling')}", results, "high" if results.get("takeover_possible") else "info")
        return {"type": "text", "content": _json.dumps(results, indent=2, default=str)}

    elif action == "vuln_correlation_report":
        """Generate comprehensive vulnerability correlation report from current KB state."""
        import json as _json
        hosts = get_hosts(pid)
        report = {"project": pid, "hosts": [], "summary": {"total_vulns": 0, "cors_findings": [], "takeover_findings": [], "auth_findings": []}}
        for h in hosts:
            vulns = get_vulnerabilities(h["id"])
            ports = get_ports(h["id"])
            host_info = {"ip": h["ip"], "hostname": h.get("hostname", ""), "vulns": len(vulns), "ports": len(ports), "vulnerabilities": []}
            for v in vulns:
                vinfo = {"name": v.get("name", ""), "severity": v.get("severity", ""), "cve": v.get("cve_id", "")}
                host_info["vulnerabilities"].append(vinfo)
                report["summary"]["total_vulns"] += 1
                if "cors" in v.get("name", "").lower():
                    report["summary"]["cors_findings"].append(f"{h['ip']}: {v['name']}")
                if "takeover" in v.get("name", "").lower() or "dangling" in v.get("name", "").lower():
                    report["summary"]["takeover_findings"].append(f"{h['ip']}: {v['name']}")
                if "aad" in v.get("name", "").lower() or "device code" in v.get("name", "").lower() or "oauth" in v.get("name", "").lower():
                    report["summary"]["auth_findings"].append(f"{h['ip']}: {v['name']}")
            report["hosts"].append(host_info)
        return {"type": "text", "content": _json.dumps(report, indent=2, default=str)}

    return {"type": "error", "content": f"Unknown action: {action}"}

if __name__ == "__main__":
    init_db()
    if len(sys.argv) > 1:
        request = json.loads(sys.argv[1]) if sys.argv[1].startswith("{") else {"action": sys.argv[1], "args": {}}
        if len(sys.argv) > 2:
            try: request["args"] = json.loads(sys.argv[2])
            except json.JSONDecodeError: request["args"] = {"raw": sys.argv[2]}
        result = handle_request(request)
        print(json.dumps(result, indent=2, default=str))
    else:
        print("APOLLO MCP Server v5 ready. 90+ actions available.")
        print("Usage: mcp_server.py <json_request>")
