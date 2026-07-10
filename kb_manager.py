#!/usr/bin/env python3
"""
APOLLO Knowledge Base Manager v3 - Enterprise Intelligence System
SQLite-backed with obfuscated credential storage (PBKDF2 + base64),
C2 session tracking, attack path analysis, project import/export,
and event timeline.
"""
import sqlite3, json, os, sys, re, csv, io, hashlib, base64, threading
from datetime import datetime, timezone

DB_PATH = os.environ.get("APOLLO_KB_PATH",
    os.path.expanduser("~/.config/opencode/apollo-engine/apollo.db"))
ENCRYPTION_KEY = os.environ.get("APOLLO_ENCRYPTION_KEY", "")
ACTIVE_PROJECT_FILE = os.path.expanduser(
    "~/.config/opencode/apollo-engine/.active_project")
_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    scope TEXT, client TEXT, engagement_type TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    ip TEXT NOT NULL, hostname TEXT, os TEXT, mac TEXT,
    status TEXT DEFAULT 'unknown', tags TEXT,
    first_seen TEXT DEFAULT (datetime('now')),
    last_seen TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL, port INTEGER, protocol TEXT DEFAULT 'tcp',
    service TEXT, version TEXT, state TEXT DEFAULT 'open', banner TEXT,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER, port_id INTEGER,
    name TEXT NOT NULL, severity TEXT DEFAULT 'medium',
    cvss REAL, description TEXT, mitre_id TEXT, cve_id TEXT, evidence TEXT,
    status TEXT DEFAULT 'open', discovered TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER, service TEXT, username TEXT,
    password_enc TEXT, hash_enc TEXT, domain TEXT, ntlm_hash TEXT,
    source TEXT, priv_level TEXT, notes TEXT,
    discovered TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS exploits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER, edb_id TEXT, name TEXT,
    module_path TEXT, payload TEXT, target TEXT,
    success INTEGER DEFAULT 0, executed TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
);
CREATE TABLE IF NOT EXISTS c2_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER, session_type TEXT, session_id TEXT UNIQUE,
    platform TEXT, privilege TEXT, listener_addr TEXT, listener_port INTEGER,
    proto TEXT, status TEXT DEFAULT 'active',
    first_seen TEXT DEFAULT (datetime('now')),
    last_seen TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);
CREATE TABLE IF NOT EXISTS c2_commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER, command TEXT, result_summary TEXT,
    exit_code INTEGER, executed TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (session_id) REFERENCES c2_sessions(id)
);
CREATE TABLE IF NOT EXISTS attack_paths (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER, source_host TEXT, target_host TEXT,
    technique TEXT, mitre_id TEXT, service_used TEXT, credential_used TEXT,
    success INTEGER DEFAULT 1, description TEXT,
    discovered TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (project_id) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER, event_type TEXT, source TEXT,
    description TEXT, data TEXT, severity TEXT DEFAULT 'info',
    timestamp TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (project_id) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER, title TEXT, content TEXT, category TEXT DEFAULT 'general',
    created TEXT DEFAULT (datetime('now')), updated TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (project_id) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS commands_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER, command TEXT, tool TEXT, target TEXT,
    output_summary TEXT, exit_code INTEGER, duration_ms INTEGER,
    executed TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (project_id) REFERENCES projects(id)
);
CREATE INDEX IF NOT EXISTS idx_hosts_project ON hosts(project_id);
CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulnerabilities(host_id);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_sessions_host ON c2_sessions(host_id);
CREATE INDEX IF NOT EXISTS idx_events_project ON events(project_id);
CREATE VIRTUAL TABLE IF NOT EXISTS kb_fts USING fts5(
    content, category, source, project_id UNINDEXED
);
"""

def get_connection():
    """Thread-local connection pooling with WAL mode and connection health check."""
    conn = getattr(_local, 'conn', None)
    if conn is not None:
        try:
            conn.execute("SELECT 1")
        except (sqlite3.ProgrammingError, sqlite3.OperationalError):
            conn = None
            _local.conn = None
    if conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-8000")
        _local.conn = conn
    return conn

def _close_connection():
    conn = getattr(_local, 'conn', None)
    if conn:
        conn.close()
        _local.conn = None

def _encrypt(text):
    """AES-256-GCM encryption via Fernet (SHA256-derived key)."""
    if not text:
        return ""
    if not ENCRYPTION_KEY:
        return text
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64 as b64
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'apollo_v4_salt', iterations=600000)
    key = b64.urlsafe_b64encode(kdf.derive(ENCRYPTION_KEY.encode()))
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()

def _decrypt(token):
    if not token:
        return ""
    if not ENCRYPTION_KEY:
        return token
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        import base64 as b64
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'apollo_v4_salt', iterations=600000)
        key = b64.urlsafe_b64encode(kdf.derive(ENCRYPTION_KEY.encode()))
        f = Fernet(key)
        return f.decrypt(token.encode()).decode()
    except Exception:
        return token

def create_event(pid, etype, source, desc, data=None, severity="info"):
    try:
        conn = get_connection()
        conn.execute("INSERT INTO events (project_id, event_type, source, description, data, severity) VALUES (?,?,?,?,?,?)",
                     (pid, etype, source, desc, json.dumps(data) if data else None, severity))
        conn.commit()
        conn.close()
    except Exception as e:
        sys.stderr.write(f"[APOLLO] create_event failed: {e}\n")

def _migrate_schema(conn):
    """Add columns that may be missing from older schema versions."""
    migrations = [
        ("projects", "client", "TEXT DEFAULT ''"),
        ("projects", "engagement_type", "TEXT DEFAULT ''"),
        ("hosts", "mac", "TEXT DEFAULT ''"),
        ("hosts", "tags", "TEXT DEFAULT ''"),
        ("vulnerabilities", "status", "TEXT DEFAULT 'open'"),
        ("vulnerabilities", "discovered", "TEXT DEFAULT (datetime('now'))"),
        ("credentials", "password_enc", "TEXT DEFAULT ''"),
        ("credentials", "hash_enc", "TEXT DEFAULT ''"),
        ("credentials", "priv_level", "TEXT DEFAULT ''"),
        ("credentials", "notes", "TEXT DEFAULT ''"),
        ("credentials", "discovered", "TEXT DEFAULT (datetime('now'))"),
    ]
    for table, col, dtype in migrations:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {dtype}")
        except sqlite3.OperationalError:
            pass  # column already exists

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_connection()
    conn.executescript(SCHEMA)
    _migrate_schema(conn)
    conn.commit()

def create_project(name, scope="", client="", engagement_type=""):
    conn = get_connection()
    try:
        c = conn.execute("INSERT OR IGNORE INTO projects (name, scope, client, engagement_type) VALUES (?,?,?,?)",
                        (name, scope, client, engagement_type))
        conn.commit()
        row = conn.execute("SELECT id FROM projects WHERE name=?", (name,)).fetchone()
        conn.close()
        return row["id"]
    except Exception as e:
        conn.close()
        return None

def set_active_project(name):
    os.makedirs(os.path.dirname(ACTIVE_PROJECT_FILE), exist_ok=True)
    with open(ACTIVE_PROJECT_FILE, 'w') as f:
        f.write(name)
    pid = create_project(name)
    create_event(pid, "project", "system", f"Switched to project: {name}")

def get_active_project():
    try:
        with open(ACTIVE_PROJECT_FILE) as f:
            return f.read().strip()
    except:
        return "default"

def get_project_id(name=None):
    if not name: name = get_active_project()
    conn = get_connection()
    row = conn.execute("SELECT id FROM projects WHERE name=?", (name,)).fetchone()
    conn.close()
    if row: return row["id"]
    pid = create_project(name)
    return pid

def list_projects():
    conn = get_connection()
    rows = conn.execute("SELECT id, name, scope, client, engagement_type, created_at FROM projects ORDER BY updated_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- Hosts ---
def add_host(project_id, ip, hostname="", os="", mac="",
             status="up", tags=""):
    conn = get_connection()
    existing = conn.execute(
        "SELECT id FROM hosts WHERE project_id=? AND ip=?",
        (project_id, ip)).fetchone()
    if existing:
        conn.execute("UPDATE hosts SET last_seen=datetime('now'), status=? WHERE id=?",
                    (status, existing["id"]))
        conn.commit()
        hid = existing["id"]
    else:
        c = conn.execute("INSERT INTO hosts (project_id,ip,hostname,os,mac,status,tags) VALUES (?,?,?,?,?,?,?)",
                        (project_id, ip, hostname, os, mac, status, tags))
        hid = c.lastrowid
    conn.commit()
    conn.close()
    create_event(project_id, "host", "kb_manager",
                  f"Host {'updated' if existing else 'added'}: {ip} ({hostname})",
                  {"ip": ip, "hostname": hostname, "os": os, "status": status})
    return hid

def get_hosts(project_id):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM hosts WHERE project_id=?", (project_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def update_host(host_id, **kwargs):
    allowed = ["hostname", "os", "mac", "status", "tags"]
    sets = ", ".join(f"{k}=?" for k in kwargs if k in allowed)
    if not sets: return False
    vals = [kwargs[k] for k in kwargs if k in allowed] + [host_id]
    conn = get_connection()
    conn.execute(f"UPDATE hosts SET {sets}, last_seen=datetime('now') WHERE id=?", vals)
    conn.commit()
    conn.close()
    return True

# --- Ports ---
def add_port(host_id, port, protocol="tcp", service="", version="",
             state="open", banner=""):
    conn = get_connection()
    existing = conn.execute(
        "SELECT id FROM ports WHERE host_id=? AND port=? AND protocol=?",
        (host_id, port, protocol)).fetchone()
    if existing:
        conn.execute("UPDATE ports SET service=?,version=?,state=?,banner=? WHERE id=?",
                    (service, version, state, banner, existing["id"]))
        hid = existing["id"]
    else:
        c = conn.execute("INSERT INTO ports (host_id,port,protocol,service,version,state,banner) VALUES (?,?,?,?,?,?,?)",
                        (host_id, port, protocol, service, version, state, banner))
        hid = c.lastrowid
    conn.commit()
    conn.close()
    return hid

def get_ports(host_id):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM ports WHERE host_id=?", (host_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- Vulnerabilities ---
def add_vulnerability(host_id, name, severity="medium", cvss=None,
                     description="", mitre_id="", cve_id="",
                     evidence="", port_id=None, status="open"):
    conn = get_connection()
    c = conn.execute("""INSERT INTO vulnerabilities
        (host_id,port_id,name,severity,cvss,description,mitre_id,cve_id,evidence,status)
        VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (host_id, port_id, name, severity, cvss, description,
         mitre_id, cve_id, evidence, status))
    vid = c.lastrowid
    conn.commit()
    conn.close()
    return vid

def get_vulnerabilities(project_id):
    conn = get_connection()
    rows = conn.execute("""
        SELECT v.*, h.ip, h.hostname FROM vulnerabilities v
        JOIN hosts h ON v.host_id = h.id
        WHERE h.project_id=?
        ORDER BY CASE v.severity
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1
            WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
    """, (project_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def update_vuln_status(vuln_id, status):
    conn = get_connection()
    conn.execute("UPDATE vulnerabilities SET status=? WHERE id=?", (status, vuln_id))
    conn.commit()
    conn.close()

# --- Credentials (with encryption) ---
def add_credential(host_id=None, service="", username="", password="",
                  hash="", domain="", ntlm_hash="", source="manual",
                  priv_level="", notes=""):
    conn = get_connection()
    pwd_enc = _encrypt(password)
    hash_enc = _encrypt(hash)
    c = conn.execute("""INSERT INTO credentials
        (host_id,service,username,password_enc,hash_enc,domain,ntlm_hash,source,priv_level,notes)
        VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (host_id, service, username, pwd_enc, hash_enc,
         domain, ntlm_hash, source, priv_level, notes))
    cid = c.lastrowid
    conn.commit()
    return cid

def get_credentials(project_id):
    conn = get_connection()
    rows = conn.execute("""
        SELECT c.*, COALESCE(h.ip, 'orphan') as ip, COALESCE(h.hostname, '') as hostname
        FROM credentials c
        LEFT JOIN hosts h ON c.host_id = h.id
        WHERE (h.project_id=? OR c.host_id IS NULL)
    """, (project_id,)).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["password"] = _decrypt(d.pop("password_enc", ""))
        d["hash"] = _decrypt(d.pop("hash_enc", ""))
        results.append(d)
    return results

# --- C2 Sessions ---
def add_c2_session(host_id, session_type, session_id, platform="",
                   privilege="", listener_addr="", listener_port=0,
                   proto="tcp", status="active"):
    conn = get_connection()
    c = conn.execute("""INSERT OR REPLACE INTO c2_sessions
        (host_id,session_type,session_id,platform,privilege,listener_addr,
         listener_port,proto,status)
        VALUES (?,?,?,?,?,?,?,?,?)""",
        (host_id, session_type, session_id, platform, privilege,
         listener_addr, listener_port, proto, status))
    sid = c.lastrowid
    conn.commit()
    conn.close()
    return sid

def get_c2_sessions(project_id=None, status="active"):
    conn = get_connection()
    if project_id:
        rows = conn.execute("""
            SELECT s.*, h.ip, h.hostname FROM c2_sessions s
            JOIN hosts h ON s.host_id = h.id
            WHERE h.project_id=? AND s.status=?
        """, (project_id, status)).fetchall()
    else:
        rows = conn.execute("""
            SELECT s.*, h.ip, h.hostname FROM c2_sessions s
            JOIN hosts h ON s.host_id = h.id
            WHERE s.status=?
        """, (status,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def update_c2_session(session_id, status=None, privilege=None, last_seen=True):
    sets = []
    vals = []
    if status: sets.append("status=?"); vals.append(status)
    if privilege: sets.append("privilege=?"); vals.append(privilege)
    if last_seen: sets.append("last_seen=datetime('now')")
    if not sets: return
    conn = get_connection()
    conn.execute(f"UPDATE c2_sessions SET {', '.join(sets)} WHERE session_id=?",
                vals + [session_id])
    conn.commit()
    conn.close()

def add_c2_command(session_id, command, result_summary="", exit_code=0):
    conn = get_connection()
    c = conn.execute("INSERT INTO c2_commands (session_id,command,result_summary,exit_code) VALUES (?,?,?,?)",
                    (session_id, command, result_summary, exit_code))
    cid = c.lastrowid
    conn.commit()
    conn.close()
    return cid

# --- Attack Paths ---
def add_attack_path(project_id, source_host, target_host, technique,
                   mitre_id="", service_used="", credential_used="",
                   success=1, description=""):
    conn = get_connection()
    c = conn.execute("""INSERT INTO attack_paths
        (project_id,source_host,target_host,technique,mitre_id,
         service_used,credential_used,success,description)
        VALUES (?,?,?,?,?,?,?,?,?)""",
        (project_id, source_host, target_host, technique, mitre_id,
         service_used, credential_used, success, description))
    aid = c.lastrowid
    conn.commit()
    conn.close()
    return aid

def get_attack_paths(project_id):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM attack_paths WHERE project_id=? ORDER BY discovered",
        (project_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- Events / Timeline ---
def get_timeline(project_id, limit=100, event_type=None):
    conn = get_connection()
    if event_type:
        rows = conn.execute(
            "SELECT * FROM events WHERE project_id=? AND event_type=? ORDER BY timestamp DESC LIMIT ?",
            (project_id, event_type, limit)).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM events WHERE project_id=? ORDER BY timestamp DESC LIMIT ?",
            (project_id, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- Notes ---
def add_note(project_id, title, content, category="general"):
    conn = get_connection()
    c = conn.execute("INSERT INTO notes (project_id,title,content,category) VALUES (?,?,?,?)",
                    (project_id, title, content, category))
    nid = c.lastrowid
    conn.commit()
    conn.close()
    return nid

def get_notes(project_id, category=None):
    conn = get_connection()
    if category:
        rows = conn.execute("SELECT * FROM notes WHERE project_id=? AND category=?",
                          (project_id, category)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM notes WHERE project_id=?",
                          (project_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- Command Log ---
def log_command(project_id, command, tool="", target="",
               output_summary="", exit_code=0, duration_ms=0):
    conn = get_connection()
    c = conn.execute("""INSERT INTO commands_log
        (project_id,command,tool,target,output_summary,exit_code,duration_ms)
        VALUES (?,?,?,?,?,?,?)""",
        (project_id, command, tool, target, output_summary, exit_code, duration_ms))
    cid = c.lastrowid
    conn.commit()
    conn.close()
    return cid

def get_command_log(project_id, limit=50):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM commands_log WHERE project_id=? ORDER BY executed DESC LIMIT ?",
        (project_id, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- Import / Export ---
def export_project(project_id):
    conn = get_connection()
    project = conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
    if not project: return None
    hosts = conn.execute("SELECT * FROM hosts WHERE project_id=?", (project_id,)).fetchall()
    data = {"project": dict(project), "hosts": []}
    for h in hosts:
        hd = dict(h)
        hd["ports"] = [dict(r) for r in conn.execute("SELECT * FROM ports WHERE host_id=?", (h["id"],)).fetchall()]
        hd["vulnerabilities"] = [dict(r) for r in conn.execute("SELECT * FROM vulnerabilities WHERE host_id=?", (h["id"],)).fetchall()]
        hd["credentials"] = []
        for r in conn.execute("SELECT * FROM credentials WHERE host_id=?", (h["id"],)).fetchall():
            cd = dict(r)
            cd["password"] = _decrypt(cd.pop("password_enc", ""))
            cd["hash"] = _decrypt(cd.pop("hash_enc", ""))
            hd["credentials"].append(cd)
        data["hosts"].append(hd)
    data["sessions"] = [dict(r) for r in conn.execute(
        "SELECT s.*,h.ip FROM c2_sessions s JOIN hosts h ON s.host_id=h.id WHERE h.project_id=?",
        (project_id,)).fetchall()]
    data["attack_paths"] = [dict(r) for r in conn.execute(
        "SELECT * FROM attack_paths WHERE project_id=?", (project_id,)).fetchall()]
    data["notes"] = [dict(r) for r in conn.execute(
        "SELECT * FROM notes WHERE project_id=?", (project_id,)).fetchall()]
    data["events"] = [dict(r) for r in conn.execute(
        "SELECT * FROM events WHERE project_id=?", (project_id,)).fetchall()]
    conn.close()
    return data

def import_project(data):
    p = data.get("project", {})
    pid = create_project(p.get("name", "imported"), p.get("scope", ""),
                        p.get("client", ""), p.get("engagement_type", ""))
    conn = get_connection()
    for h in data.get("hosts", []):
        hid = add_host(pid, h["ip"], h.get("hostname", ""), h.get("os", ""),
                      h.get("mac", ""), h.get("status", "up"), h.get("tags", ""))
        for port in h.get("ports", []):
            add_port(hid, port["port"], port.get("protocol", "tcp"),
                    port.get("service", ""), port.get("version", ""),
                    port.get("state", "open"), port.get("banner", ""))
        for vuln in h.get("vulnerabilities", []):
            add_vulnerability(hid, vuln["name"], vuln.get("severity", "medium"),
                            vuln.get("cvss"), vuln.get("description", ""),
                            vuln.get("mitre_id", ""), vuln.get("cve_id", ""),
                            vuln.get("evidence", ""))
        for cred in h.get("credentials", []):
            add_credential(hid, cred.get("service", ""), cred.get("username", ""),
                          cred.get("password", ""), cred.get("hash", ""),
                          cred.get("domain", ""), cred.get("ntlm_hash", ""),
                          cred.get("source", "imported"))
    for session in data.get("sessions", []):
        try:
            conn.execute("""INSERT INTO c2_sessions
                (host_id,session_type,session_id,platform,privilege,listener_addr,listener_port,proto,status)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (session["host_id"], session.get("session_type", ""),
                 session.get("session_id", ""), session.get("platform", ""),
                 session.get("privilege", ""), session.get("listener_addr", ""),
                 session.get("listener_port", 0), session.get("proto", "tcp"),
                 session.get("status", "active")))
        except: pass
    for note in data.get("notes", []):
        add_note(pid, note.get("title", ""), note.get("content", ""), note.get("category", "general"))
    for path in data.get("attack_paths", []):
        add_attack_path(pid, path.get("source_host", ""), path.get("target_host", ""),
                       path.get("technique", ""), path.get("mitre_id", ""),
                       path.get("service_used", ""), path.get("credential_used", ""),
                       path.get("success", 1), path.get("description", ""))
    conn.close()
    create_event(pid, "import", "kb_manager", f"Imported project data")
    return pid

# --- Summary ---
def summary(project_id):
    conn = get_connection()
    hosts = conn.execute("SELECT COUNT(*) as c FROM hosts WHERE project_id=?", (project_id,)).fetchone()["c"]
    ports = conn.execute("""
        SELECT COUNT(*) as c FROM ports p
        JOIN hosts h ON p.host_id = h.id WHERE h.project_id=?
    """, (project_id,)).fetchone()["c"]
    vulns = conn.execute("""
        SELECT severity, COUNT(*) as c FROM vulnerabilities v
        JOIN hosts h ON v.host_id = h.id WHERE h.project_id=?
        GROUP BY severity
    """, (project_id,)).fetchall()
    creds = conn.execute("""
        SELECT COUNT(*) as c FROM credentials c
        LEFT JOIN hosts h ON c.host_id = h.id
        WHERE h.project_id=? OR c.host_id IS NULL
    """, (project_id,)).fetchone()["c"]
    sessions = conn.execute("""
        SELECT COUNT(*) as c FROM c2_sessions s
        JOIN hosts h ON s.host_id = h.id WHERE h.project_id=? AND s.status='active'
    """, (project_id,)).fetchone()["c"]
    paths = conn.execute("SELECT COUNT(*) as c FROM attack_paths WHERE project_id=?", (project_id,)).fetchone()["c"]
    events = conn.execute("SELECT COUNT(*) as c FROM events WHERE project_id=?", (project_id,)).fetchone()["c"]
    proj = conn.execute("SELECT name FROM projects WHERE id=?", (project_id,)).fetchone()
    conn.close()
    vuln_by_sev = {r["severity"]: r["c"] for r in vulns}
    report = f"""=== APOLLO Knowledge Base Summary ===
Project: {proj['name'] if proj else 'Unknown'} (ID: {project_id})
Hosts discovered: {hosts}
Open ports: {ports}
Credentials: {creds}
Active C2 sessions: {sessions}
Attack paths mapped: {paths}
Timeline events: {events}
Vulnerabilities by severity:"""
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in vuln_by_sev:
            report += f"\n  [{sev.upper():8}] {vuln_by_sev[sev]}"
    if not vuln_by_sev:
        report += "\n  (none)"
    return report

def stats(project_id):
    """Return structured stats dict for API/report use."""
    conn = get_connection()
    s = {}
    s["hosts"] = conn.execute("SELECT COUNT(*) FROM hosts WHERE project_id=?", (project_id,)).fetchone()[0]
    s["ports"] = conn.execute("SELECT COUNT(*) FROM ports p JOIN hosts h ON p.host_id=h.id WHERE h.project_id=?", (project_id,)).fetchone()[0]
    s["vulns"] = conn.execute("SELECT COUNT(*) FROM vulnerabilities v JOIN hosts h ON v.host_id=h.id WHERE h.project_id=?", (project_id,)).fetchone()[0]
    s["creds"] = conn.execute("SELECT COUNT(*) FROM credentials c LEFT JOIN hosts h ON c.host_id=h.id WHERE h.project_id=? OR c.host_id IS NULL", (project_id,)).fetchone()[0]
    s["sessions"] = conn.execute("SELECT COUNT(*) FROM c2_sessions s JOIN hosts h ON s.host_id=h.id WHERE h.project_id=? AND s.status='active'", (project_id,)).fetchone()[0]
    s["attack_paths"] = conn.execute("SELECT COUNT(*) FROM attack_paths WHERE project_id=?", (project_id,)).fetchone()[0]
    rows = conn.execute("SELECT severity, COUNT(*) as c FROM vulnerabilities v JOIN hosts h ON v.host_id=h.id WHERE h.project_id=? GROUP BY severity", (project_id,)).fetchall()
    s["vulns_by_severity"] = {r[0]: r[1] for r in rows}
    conn.close()
    return s

# --- Autocomplete tool for shell integration ---
def suggest_targets(project_id, query):
    conn = get_connection()
    rows = conn.execute("""
        SELECT ip, hostname, os FROM hosts
        WHERE project_id=? AND (ip LIKE ? OR hostname LIKE ?)
        LIMIT 10
    """, (project_id, f"%{query}%", f"%{query}%")).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- CLI ---
if __name__ == "__main__":
    init_db()
    if len(sys.argv) < 2:
        pid = get_project_id()
        print(summary(pid))
        sys.exit(0)
    cmd = sys.argv[1]
    pid = get_project_id()
    if cmd == "init":
        init_db()
        print("APOLLO Knowledge Base initialized.")
    elif cmd == "summary":
        if len(sys.argv) > 2:
            pid = get_project_id(sys.argv[2])
        print(summary(pid))
    elif cmd == "stats":
        if len(sys.argv) > 2:
            pid = get_project_id(sys.argv[2])
        print(json.dumps(stats(pid), indent=2))
    elif cmd == "project":
        if len(sys.argv) > 2:
            set_active_project(sys.argv[2])
            print(f"Active project: {sys.argv[2]}")
        else:
            print(f"Active project: {get_active_project()}")
    elif cmd == "projects":
        for p in list_projects():
            print(f"  {p['id']:3d}  {p['name']:20s}  scope={p.get('scope',''):20s}  created={p.get('created_at','')}")
    elif cmd == "export":
        fn = sys.argv[2] if len(sys.argv) > 2 else f"/tmp/apollo_export_{get_active_project()}.json"
        data = export_project(pid)
        if data:
            with open(fn, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            print(f"Exported to: {fn}")
        else:
            print("Export failed")
    elif cmd == "import":
        if len(sys.argv) > 2:
            with open(sys.argv[2]) as f:
                data = json.load(f)
            npid = import_project(data)
            print(f"Imported to project ID: {npid}")
        else:
            print("Usage: import <file.json>")
    elif cmd == "timeline":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        for ev in get_timeline(pid, limit):
            print(f"  [{ev['timestamp']}] [{ev['event_type']:12s}] {ev['description']}")
    elif cmd == "add_host":
        ip = sys.argv[2] if len(sys.argv) > 2 else input("IP: ")
        hostname = sys.argv[3] if len(sys.argv) > 3 else input("Hostname: ")
        os_str = sys.argv[4] if len(sys.argv) > 4 else input("OS: ")
        tags = sys.argv[5] if len(sys.argv) > 5 else ""
        hid = add_host(pid, ip, hostname, os_str, tags=tags)
        print(f"Host added (ID: {hid})")
    elif cmd == "add_vuln":
        hid = int(sys.argv[2]) if len(sys.argv) > 2 else input("Host ID: ")
        name = sys.argv[3] if len(sys.argv) > 3 else input("Vuln name: ")
        severity = sys.argv[4] if len(sys.argv) > 4 else "medium"
        vid = add_vulnerability(hid, name, severity)
        print(f"Vulnerability added (ID: {vid})")
    elif cmd == "add_cred":
        hid = int(sys.argv[2]) if len(sys.argv) > 2 else input("Host ID: ")
        svc = sys.argv[3] if len(sys.argv) > 3 else input("Service: ")
        user = sys.argv[4] if len(sys.argv) > 4 else input("Username: ")
        pwd = sys.argv[5] if len(sys.argv) > 5 else input("Password: ")
        cid = add_credential(hid, svc, user, pwd)
        print(f"Credential added (ID: {cid})")
    elif cmd == "add_session":
        hid = int(sys.argv[2]) if len(sys.argv) > 2 else input("Host ID: ")
        stype = sys.argv[3] if len(sys.argv) > 3 else input("Session type (meterpreter/shell/sliver): ")
        sid = sys.argv[4] if len(sys.argv) > 4 else input("Session ID: ")
        platform = sys.argv[5] if len(sys.argv) > 5 else input("Platform: ")
        sid_new = add_c2_session(hid, stype, sid, platform)
        print(f"C2 session tracked (ID: {sid_new})")
    elif cmd == "add_path":
        src = sys.argv[2] if len(sys.argv) > 2 else input("Source host: ")
        tgt = sys.argv[3] if len(sys.argv) > 3 else input("Target host: ")
        tech = sys.argv[4] if len(sys.argv) > 4 else input("Technique: ")
        aid = add_attack_path(pid, src, tgt, tech)
        print(f"Attack path added (ID: {aid})")
    elif cmd == "sessions":
        for s in get_c2_sessions(pid):
            print(f"  [{s['session_id']:20s}] {s['session_type']:12s} {s.get('ip',''):15s} priv={s.get('privilege',''):8s} status={s.get('status','')}")
    elif cmd == "paths":
        for p in get_attack_paths(pid):
            print(f"  {p['source_host']:20s} -> {p['target_host']:20s} [{p['technique']}] {'OK' if p.get('success') else 'NO'}")
    elif cmd == "hosts":
        for h in get_hosts(pid):
            print(f"  {h['ip']:18s} {h.get('hostname',''):20s} {h.get('os',''):15s} {h.get('status','')}")
    elif cmd == "search":
        if len(sys.argv) > 2:
            for t in suggest_targets(pid, sys.argv[2]):
                print(f"  {t['ip']:18s} {t.get('hostname',''):20s} {t.get('os','')}")
    elif cmd == "note":
        if len(sys.argv) > 3:
            nid = add_note(pid, sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else "general")
            print(f"Note added (ID: {nid})")
        else:
            for n in get_notes(pid):
                print(f"  [{n.get('category','')}] {n['title']}")
    elif cmd == "bulk_hosts":
        if len(sys.argv) > 2:
            import json as _j
            hosts_data = _j.loads(sys.argv[2])
            for h in hosts_data:
                add_host(pid, h.get("ip"), h.get("hostname", ""), h.get("os", ""), tags=h.get("tags", ""))
            print(f"Added {len(hosts_data)} hosts")
        else:
            print("Usage: bulk_hosts '[{\"ip\":\"1.2.3.4\",\"hostname\":\"test\"}]'")
    elif cmd == "tag_hosts":
        tag = sys.argv[2] if len(sys.argv) > 2 else ""
        hosts = get_hosts(pid)
        filtered = [h for h in hosts if tag in (h.get("tags", "") or "")]
        for h in filtered:
            print(f"  {h['ip']:18s} {h.get('hostname',''):20s} tags={h.get('tags','')}")
    elif cmd == "search_all":
        q = sys.argv[2] if len(sys.argv) > 2 else ""
        conn = get_connection()
        host_rows = conn.execute("SELECT ip, hostname, os FROM hosts WHERE project_id=? AND (ip LIKE ? OR hostname LIKE ? OR os LIKE ?)", (pid, f"%{q}%", f"%{q}%", f"%{q}%")).fetchall()
        vuln_rows = conn.execute("SELECT v.name, h.ip FROM vulnerabilities v JOIN hosts h ON v.host_id=h.id WHERE h.project_id=? AND v.name LIKE ?", (pid, f"%{q}%")).fetchall()
        cred_rows = conn.execute("SELECT c.username, c.service, h.ip FROM credentials c JOIN hosts h ON c.host_id=h.id WHERE h.project_id=? AND (c.username LIKE ? OR c.service LIKE ?)", (pid, f"%{q}%", f"%{q}%")).fetchall()
        conn.close()
        print(f"Search: '{q}'")
        for r in host_rows: print(f"  [HOST] {r['ip']} {r['hostname']}")
        for r in vuln_rows: print(f"  [VULN] {r['name']} on {r['ip']}")
        for r in cred_rows: print(f"  [CRED] {r['username']}@{r['ip']} ({r['service']})")
    else:
        print(f"Unknown command: {cmd}")
        print("Available: init, summary, stats, project, projects, export, import,")
        print("  timeline, add_host, add_vuln, add_cred, add_session, add_path,")
        print("  sessions, paths, hosts, search, note, bulk_hosts, tag_hosts, search_all")
