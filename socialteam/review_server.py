"""Local review/approval page. Binds 127.0.0.1 only. Approving needs the human's approval token (same file and check as the CLI) and only records
an approved hash; nothing is published. Guards: Host header check (DNS rebinding), same-origin check on POST, image route limited to OUT/cards,
failed-token lockout. Meant to be run by the human on their own machine."""
import os, time, urllib.parse, http.server, json
from . import review

def make_handler(store, out_dir, port):
    fails = []
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    cards = os.path.realpath(f"{out_dir}/cards")
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _send(self, code, body, ctype="text/html; charset=utf-8", extra=()):
            b = body if isinstance(body, bytes) else body.encode(); self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
            self.send_header("Content-Security-Policy", "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; form-action 'self'"); self.send_header("X-Frame-Options", "DENY")
            for k, v in extra: self.send_header(k, v)
            self.end_headers(); self.wfile.write(b)
        def _host_ok(self): return self.headers.get("Host", "") in hosts
        def do_GET(self):
            if not self._host_ok(): return self._send(403, "bad host")
            u = urllib.parse.urlparse(self.path)
            if u.path == "/":
                msg = urllib.parse.parse_qs(u.query).get("m", [""])[0][:200]
                return self._send(200, review.render_page(store, out_dir, True, lambda p: "/img/" + os.path.basename(p), msg))
            if u.path.startswith("/img/"):
                f = os.path.realpath(os.path.join(cards, os.path.basename(u.path)))
                if os.path.dirname(f) == cards and f.endswith(".png") and os.path.exists(f): return self._send(200, open(f, "rb").read(), "image/png")
            self._send(404, "not found")
        def do_POST(self):
            if not self._host_ok() or self.path != "/decide": return self._send(403, "refused")
            org = self.headers.get("Origin")
            if org is not None and urllib.parse.urlparse(org).netloc not in hosts: return self._send(403, "bad origin")
            n = int(self.headers.get("Content-Length", "0"))
            if n > 20000: return self._send(413, "too large")
            f = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}
            now = time.time(); fails[:] = [t for t in fails if t > now - 60]
            if len(fails) >= 5: return self._redirect("locked for 60s after repeated bad tokens")
            it = store.get(f.get("id", ""))
            if not it or it["state"] != "PENDING_REVIEW": return self._redirect("item is not pending review")
            try:
                if f.get("action") == "approve":
                    old = json.loads(it["draft"])["text"]; txt = f.get("text", "").replace("\r\n", "\n")
                    review.approve(store, out_dir, it["id"], f.get("token", ""), edit_text=txt if txt.strip() and txt != old else None); m = "approved (nothing published)"
                elif f.get("action") == "reject": review.reject(store, out_dir, it["id"], f.get("token", "")); m = "rejected"
                else: return self._redirect("unknown action")
                review.export_approved(store, out_dir); review.render(store, out_dir)
            except PermissionError as e: fails.append(now); m = "refused: " + str(e)
            self._redirect(m)
        def _redirect(self, m): self._send(303, "", extra=[("Location", "/?m=" + urllib.parse.quote(m))])
    return H
def serve(store, out_dir, port=8765):
    srv = http.server.HTTPServer(("127.0.0.1", port), make_handler(store, out_dir, port)); return srv
