import json, html, os, hashlib, hmac, secrets, stat
def content_hash(platform, text, image_path):
    img = hashlib.sha256(open(image_path, "rb").read()).hexdigest() if image_path and os.path.exists(image_path) else ""
    return hashlib.sha256(json.dumps([platform, text, img]).encode()).hexdigest()
def init_token(out_dir):
    """Approval secret in a 0600 file. Must be read by the HUMAN's shell; pipeline/agents never need it."""
    p = f"{out_dir}/.approval_token"
    if not os.path.exists(p):
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.write(fd, secrets.token_hex(16).encode()); os.close(fd)
    return p
def authorize(out_dir, token):
    p = f"{out_dir}/.approval_token"
    if not os.path.exists(p) or stat.S_IMODE(os.stat(p).st_mode) & 0o077: raise PermissionError("approval token missing or file permissions too open")
    if not token or not hmac.compare_digest(open(p).read().strip(), token.strip()): raise PermissionError("bad approval token")
def stamp(store, id_):
    it = store.get(id_); d = json.loads(it["draft"])
    store.db.execute("UPDATE items SET content_hash=? WHERE id=?", (content_hash(it["platform"], d["text"], it["image"]), id_)); store.db.commit()
def approve(store, out_dir, id_, token, edit_text=None):
    authorize(out_dir, token); it = store.get(id_)
    if edit_text is not None:      # human edits are allowed; they replace the text and are what gets hashed and approved
        d = json.loads(it["draft"]); d["text"] = edit_text; d["provider"] += "+human-edit"
        store.db.execute("UPDATE items SET draft=? WHERE id=?", (json.dumps(d), id_)); store.db.commit(); it = store.get(id_)
    h = content_hash(it["platform"], json.loads(it["draft"])["text"], it["image"])
    store.move(id_, "APPROVED", approved_hash=h)
def reject(store, out_dir, id_, token): authorize(out_dir, token); store.move(id_, "REJECTED")
def export_approved(store, out_dir):
    items, blocked = [], []
    for r in store.by_state("APPROVED"):
        d = json.loads(r["draft"])
        if content_hash(r["platform"], d["text"], r["image"]) != r["approved_hash"]: blocked.append(r["id"]); continue   # changed after approval
        items.append({"id": r["id"], "platform": r["platform"], "text": d["text"], "image": r["image"], "source": json.loads(r["evidence"])["final_url"], "approved_hash": r["approved_hash"]})
    p = f"{out_dir}/approved_export.json"
    json.dump({"schema": 1, "items": items, "blocked_changed_after_approval": blocked, "note": "publisher must recompute approved_hash and still needs per-post publish approval"}, open(p, "w"), indent=1); return p
def render(store, out_dir):
    rows = []
    for it in store.db.execute("SELECT * FROM items WHERE state IN ('PENDING_REVIEW','APPROVED','REJECTED') ORDER BY created"):
        ev = json.loads(it["evidence"]); d = json.loads(it["draft"]); rel = os.path.relpath(it["image"], out_dir) if it["image"] else ""
        rows.append(f"""<div class=c><img src="{html.escape(rel)}"><div><b>{it['platform'].upper()}</b> <code>{it['id']}</code> <span class=s>{it['state']}</span>
<p><pre>{html.escape(d['text'])}</pre><p class=m>Writer: {html.escape(d['provider'])} | Source: <a href="{html.escape(ev['final_url'])}">{html.escape(ev['domain'])}</a> {'(official allowlisted source: ' + ev.get('source_kind','') + ')' if ev.get('primary') else '(NOT on primary allowlist)'} | Published: {ev['published'] or 'not stated'}{' | Updated: ' + ev['updated'] if ev.get('updated') else ''} | Fetched {ev['fetched_at']}
<br>hash {html.escape((it['content_hash'] or '')[:12])}<br>Approve (needs your token): <code>python -m socialteam approve {it['id']}</code></div></div>""")
    page = ("<meta charset=utf-8><style>body{font:15px system-ui;background:#0e1424;color:#e8ecf4;max-width:980px;margin:20px auto}.c{display:flex;gap:16px;background:#18213a;padding:14px;margin:12px 0;border-radius:10px}"
            "img{width:300px;height:300px}pre{white-space:pre-wrap;font:inherit}.s{background:#00c896;color:#000;padding:2px 8px;border-radius:8px}.m{color:#9aa6bf;font-size:13px}a{color:#7fd}</style>"
            "<h2>Review queue (nothing here is published; this page cannot approve)</h2>" + ("".join(rows) or "<p>Empty."))
    open(f"{out_dir}/review.html", "w").write(page); return f"{out_dir}/review.html"
