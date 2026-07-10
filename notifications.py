#!/usr/bin/env python3
"""
APOLLO Notification Engine v2 - Webhook + Email + SMS alerts with dedup.
"""
import sys, os, json, urllib.request, urllib.error, time, hashlib, smtplib
from email.mime.text import MIMEText
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

CONFIG_FILE = os.path.expanduser("~/.config/opencode/apollo-engine/.notif_config.json")
DEDUP_FILE = os.path.expanduser("~/.config/opencode/apollo-engine/.notif_dedup.json")
DEDUP_WINDOW = 300  # seconds

DEFAULT_CONFIG = {
    "slack_webhook": "",
    "discord_webhook": "",
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "smtp_server": "",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_pass": "",
    "email_from": "",
    "email_to": "",
    "twilio_account_sid": "",
    "twilio_auth_token": "",
    "twilio_from": "",
    "twilio_to": "",
    "alert_on_critical": True,
    "alert_on_new_session": True,
    "alert_on_creds": True,
    "min_severity": "high",
    "dedup_enabled": True
}

def load_config():
    try:
        with open(CONFIG_FILE) as f: return {**DEFAULT_CONFIG, **json.load(f)}
    except: return DEFAULT_CONFIG

def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f: json.dump(cfg, f, indent=2)

def _dedup_key(message, severity):
    raw = f"{severity}:{message.strip()}"
    return hashlib.md5(raw.encode()).hexdigest()

def _check_dedup(dkey):
    if not os.path.exists(DEDUP_FILE):
        return False
    try:
        with open(DEDUP_FILE) as f: registry = json.load(f)
    except:
        registry = {}
    now = time.time()
    registry = {k: v for k, v in registry.items() if now - v < DEDUP_WINDOW}
    if dkey in registry:
        registry[dkey] = now
        with open(DEDUP_FILE, 'w') as f: json.dump(registry, f, indent=2)
        return True  # dedup hit
    registry[dkey] = now
    with open(DEDUP_FILE, 'w') as f: json.dump(registry, f, indent=2)
    return False

def send_slack(webhook, message):
    if not webhook: return False
    payload = json.dumps({"text": message}).encode()
    try:
        req = urllib.request.Request(webhook, data=payload,
            headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
        return True
    except: return False

def send_discord(webhook, message):
    if not webhook: return False
    payload = json.dumps({"content": message}).encode()
    try:
        req = urllib.request.Request(webhook, data=payload,
            headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
        return True
    except: return False

def send_telegram(bot_token, chat_id, message):
    if not bot_token or not chat_id: return False
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = json.dumps({"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}).encode()
    try:
        req = urllib.request.Request(url, data=payload,
            headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
        return True
    except: return False

def send_email(smtp_server, smtp_port, smtp_user, smtp_pass, from_addr, to_addr, subject, body):
    if not smtp_server or not smtp_user: return False
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as s:
            s.starttls()
            s.login(smtp_user, smtp_pass)
            s.send_message(msg)
        return True
    except: return False

def send_sms(account_sid, auth_token, from_num, to_num, message):
    if not account_sid or not auth_token: return False
    try:
        import urllib.parse
        url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
        data = urllib.parse.urlencode({"From": from_num, "To": to_num, "Body": message[:160]}).encode()
        creds = f"{account_sid}:{auth_token}"
        auth_b64 = __import__("base64").b64encode(creds.encode()).decode()
        req = urllib.request.Request(url, data=data,
            headers={"Authorization": f"Basic {auth_b64}", "Content-Type": "application/x-www-form-urlencoded"})
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception as e:
        return False

def alert(message, severity="info"):
    cfg = load_config()
    if severity == "critical" and not cfg.get("alert_on_critical", True):
        return {"skipped": "critical alerts disabled"}
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    min_sev = cfg.get("min_severity", "info")
    if sev_order.get(severity, 4) > sev_order.get(min_sev, 4):
        return {"skipped": f"severity '{severity}' below minimum '{min_sev}'"}
    if cfg.get("dedup_enabled", True) and _check_dedup(_dedup_key(message, severity)):
        return {"skipped": "dedup"}
    header = f"[APOLLO] {severity.upper()}"
    full_msg = f"{header}\n{message}"
    results = {}
    if cfg.get("slack_webhook"):
        results["slack"] = send_slack(cfg["slack_webhook"], full_msg)
    if cfg.get("discord_webhook"):
        results["discord"] = send_discord(cfg["discord_webhook"], full_msg)
    if cfg.get("telegram_bot_token") and cfg.get("telegram_chat_id"):
        results["telegram"] = send_telegram(cfg["telegram_bot_token"], cfg["telegram_chat_id"], full_msg)
    if cfg.get("smtp_server") and cfg.get("email_to"):
        results["email"] = send_email(
            cfg["smtp_server"], cfg["smtp_port"], cfg["smtp_user"], cfg["smtp_pass"],
            cfg["email_from"], cfg["email_to"],
            f"[APOLLO] {severity.upper()} Alert", full_msg)
    if cfg.get("twilio_account_sid") and cfg.get("twilio_to"):
        results["sms"] = send_sms(
            cfg["twilio_account_sid"], cfg["twilio_auth_token"],
            cfg["twilio_from"], cfg["twilio_to"], full_msg[:160])
    return results

def alert_new_host(ip, hostname="", os_info=""):
    msg = f"New host discovered: `{ip}`"
    if hostname: msg += f" ({hostname})"
    if os_info: msg += f" - {os_info}"
    return alert(msg, "info")

def alert_new_vuln(ip, name, severity):
    msg = f"Vulnerability found: *{name}* on `{ip}` | Severity: *{severity.upper()}*"
    return alert(msg, severity)

def alert_new_cred(ip, username, service):
    msg = f"Credential captured: `{username}` on `{ip}` ({service})"
    return alert(msg, "high")

def alert_new_session(ip, session_type, privilege):
    msg = f"New C2 session: *{session_type}* on `{ip}` | Privilege: {privilege}"
    return alert(msg, "critical" if "admin" in privilege.lower() or "system" in privilege.lower() or "root" in privilege.lower() else "high")

def alert_exfil(file, protocol, size=""):
    msg = f"Exfiltration: `{file}` via {protocol}"
    if size: msg += f" ({size})"
    return alert(msg, "high")

def alert_custom(title, body, severity="info"):
    return alert(f"*{title}*\n{body}", severity)

def send_test():
    return alert("APOLLO Notification Engine v2 - Test message", "info")

def clear_dedup():
    if os.path.exists(DEDUP_FILE):
        os.remove(DEDUP_FILE)
        return {"status": "dedup cache cleared"}
    return {"status": "no dedup cache"}

def configure_interactive():
    cfg = load_config()
    print("APOLLO Notification v2 Configuration (Enter to keep)")
    fields = [
        ("slack_webhook", "Slack Webhook URL"),
        ("discord_webhook", "Discord Webhook URL"),
        ("telegram_bot_token", "Telegram Bot Token"),
        ("telegram_chat_id", "Telegram Chat ID"),
        ("smtp_server", "SMTP Server"),
        ("smtp_port", "SMTP Port"),
        ("smtp_user", "SMTP User"),
        ("smtp_pass", "SMTP Password"),
        ("email_from", "Email From"),
        ("email_to", "Email To"),
        ("twilio_account_sid", "Twilio Account SID"),
        ("twilio_auth_token", "Twilio Auth Token"),
        ("twilio_from", "Twilio From Number"),
        ("twilio_to", "Twilio To Number"),
    ]
    for key, label in fields:
        current = cfg.get(key, "")
        val = input(f"  {label} [{str(current)[:30]}]: ").strip()
        if val:
            if key == "smtp_port" and val:
                cfg[key] = int(val)
            else:
                cfg[key] = val
    sev = input(f"  Min severity (critical/high/medium/low/info) [{cfg.get('min_severity', 'info')}]: ").strip()
    if sev: cfg["min_severity"] = sev
    dedup = input(f"  Enable dedup (y/n) [{'y' if cfg.get('dedup_enabled', True) else 'n'}]: ").strip().lower()
    if dedup: cfg["dedup_enabled"] = dedup == 'y'
    save_config(cfg)
    print("Saved. Sending test...")
    print(json.dumps(send_test(), indent=2))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "configure":
            configure_interactive()
        elif cmd == "test":
            print(json.dumps(send_test(), indent=2))
        elif cmd == "alert":
            sev = sys.argv[2] if len(sys.argv) > 2 else "info"
            msg = sys.argv[3] if len(sys.argv) > 3 else "APOLLO alert"
            print(json.dumps(alert(msg, sev), indent=2))
        elif cmd == "clear-dedup":
            print(json.dumps(clear_dedup(), indent=2))
        else:
            print("Usage: notifications.py [configure|test|alert|clear-dedup]")
