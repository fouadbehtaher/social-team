"""LOOPBACK MOCK, not a real n8n. A tiny local HTTP receiver that mimics only the header-auth contract (random per-test secret).
It proves the client sends the header and reports a rejection cleanly. It does NOT prove what a real n8n answers."""
import unittest, tempfile, json, os, re, secrets, threading, http.server, stat, time
from socialteam import exports, review
from socialteam.store import Store

def _server(secret, seen):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0)); body = self.rfile.read(n)
            ok = self.headers.get("X-Test-Auth") == secret
            seen.append((ok, len(body)))
            self.send_response(200 if ok else 403); self.end_headers(); self.wfile.write(b'{"ok":true}' if ok else b"")
    s = http.server.HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=s.serve_forever, daemon=True).start(); return s

class LoopbackMockN8n(unittest.TestCase):
    def test_header_contract(self):
        secret = secrets.token_hex(16); seen = []; s = _server(secret, seen)
        try:
            url = "http://127.0.0.1:%d/webhook/social-team" % s.server_address[1]
            pl = {"schema": 1, "items": [{"id": "x"}]}
            self.assertEqual(exports.send_n8n(pl, url, "X-Test-Auth: " + secret, send=True)["status"], 200)
            r = exports.send_n8n(pl, url, "X-Test-Auth: " + secrets.token_hex(16), send=True)
            self.assertEqual((r["status"], r["ok"], r["rejected"]), (403, False, True))
            self.assertEqual([x[0] for x in seen], [True, False])
        finally: s.shutdown()

class EnvDrift(unittest.TestCase):
    def test_every_n8n_variable_is_documented(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        code = " ".join(open(os.path.join(root, "socialteam", f)).read() for f in os.listdir(os.path.join(root, "socialteam")) if f.endswith(".py"))
        used = set(re.findall(r"[\"'](N8N_[A-Z_]+|ST_[A-Z_]+)[\"']", code))
        docs = open(os.path.join(root, "docs", "ACTIVATION.md")).read() + open(os.path.join(root, "README.md")).read() + open(os.path.join(root, "deploy", "README.md")).read()
        missing = sorted(u for u in used if u not in docs)
        self.assertEqual(missing, [], "env vars read by code but not documented")

if __name__ == "__main__": unittest.main()
