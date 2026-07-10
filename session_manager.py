#!/usr/bin/env python3
"""
APOLLO Session Manager - C2 session tracking, management, and logging.
Coordinates with Knowledge Base for persistent session state.
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import *

class C2Manager:
    def __init__(self):
        init_db()

    def register_session(self, host_id, session_type="shell", session_id="",
                         platform="", privilege="", listener_addr="",
                         listener_port=0, proto="tcp", status="active"):
        pid = get_project_id()
        cid = add_c2_session(host_id, session_type, session_id,
                             platform, privilege, listener_addr,
                             listener_port, proto, status)
        create_event(pid, "session", "C2Manager",
                     f"Session registered: {session_type} on host {host_id} ({status})",
                     json.dumps({"host_id": host_id, "type": session_type,
                                 "session_id": session_id, "status": status}),
                     "info")
        return cid

    def log_command_result(self, session_id, command, result_summary, exit_code=0):
        return add_c2_command(session_id, command, result_summary, exit_code)

    def summary(self):
        sessions = get_c2_sessions()
        data = {
            "total_active": len(sessions),
            "sessions": []
        }
        for s in sessions:
            data["sessions"].append({
                "id": s.get("session_id", ""),
                "type": s.get("session_type", ""),
                "ip": s.get("ip", ""),
                "platform": s.get("platform", ""),
                "privilege": s.get("privilege", ""),
                "proto": s.get("proto", ""),
                "last_seen": s.get("last_seen", "")
            })
        return data


def track_session(host_ip, session_type, session_id, platform="", privilege=""):
    """Quick-track a session by host IP (auto-resolve host_id)."""
    init_db()
    pid = get_project_id()
    conn = get_connection()
    row = conn.execute(
        "SELECT id FROM hosts WHERE project_id=? AND ip=?",
        (pid, host_ip)).fetchone()
    conn.close()
    if not row:
        hid = add_host(pid, host_ip)
    else:
        hid = row["id"]
    mgr = C2Manager()
    return mgr.register_session(hid, session_type, session_id, platform, privilege)

def close_tracked_session(session_id):
    update_c2_session(session_id, status="closed")


def _usage():
    print("APOLLO Session Manager")
    print("Usage:")
    print(f"  {sys.argv[0]}                     - List active sessions")
    print(f"  {sys.argv[0]} track <ip> <type> <id> [platform] [priv]")
    print(f"  {sys.argv[0]} close <session_id>")
    print(f"  {sys.argv[0]} list")
    print(f"  {sys.argv[0]} log <session_id> <cmd> <result>")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        mgr = C2Manager()
        s = mgr.summary()
        print(json.dumps(s, indent=2))
    elif sys.argv[1] in ("track", "register", "--register"):
        ip = sys.argv[2] if len(sys.argv) > 2 else input("Host IP: ")
        stype = sys.argv[3] if len(sys.argv) > 3 else "shell"
        sid = sys.argv[4] if len(sys.argv) > 4 else ""
        plat = sys.argv[5] if len(sys.argv) > 5 else ""
        priv = sys.argv[6] if len(sys.argv) > 6 else ""
        result = track_session(ip, stype, sid, plat, priv)
        print(json.dumps({"session_id": sid, "db_id": result}, indent=2))
    elif sys.argv[1] in ("close", "stop", "--close"):
        if len(sys.argv) > 2:
            close_tracked_session(sys.argv[2])
            print(f"Session {sys.argv[2]} closed")
        else:
            _usage()
    elif sys.argv[1] in ("list", "summary", "--list"):
        mgr = C2Manager()
        print(json.dumps(mgr.summary(), indent=2))
    elif sys.argv[1] == "log":
        if len(sys.argv) > 4:
            mgr = C2Manager()
            mgr.log_command_result(sys.argv[2], sys.argv[3], sys.argv[4])
            print("Logged")
        else:
            _usage()
    else:
        _usage()
