"""Durable state as two plain files the owner of a flow keeps somewhere that survives (not this build folder):
- posted_ledger.jsonl: one JSON line per post that really went out, written only after the exact text was approved by the user and published.
- metrics.csv: rows read from the platform's own analytics page (read-only). Missing numbers stay missing, never zero.
Everything here is stateless code over those files."""
import csv, json, os, re, time, hashlib
from .review import content_hash
CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
def source_key(title): m = CVE.search(title or ""); return m.group(0).upper() if m else None
def read(path):
    if not os.path.exists(path): return []
    return [json.loads(l) for l in open(path) if l.strip()]
def seen(path):
    rows = read(path); return {r["lead_id"] for r in rows} | {r["source_key"] for r in rows if r.get("source_key")}
def record_post(path, *, lead_id, title, platform, text, approval_ref, posted_url, posted_at=None, now=None):
    """Refuses: missing approval reference, wrong-platform URL, duplicate lead/source/text/url."""
    if not approval_ref or not approval_ref.strip(): raise ValueError("approval_ref (the user's approval message id) is required")
    host = {"linkedin": "linkedin.com", "x": "x.com", "medium": "medium.com", "tiktok": "tiktok.com"}.get(platform)
    if not host or not re.match(rf"^https://([a-z0-9-]+\.)*{re.escape(host)}/", posted_url or ""): raise ValueError(f"posted_url must be an https {host} URL")
    h = content_hash(platform, text, None); rows = read(path); sk = source_key(title)
    for r in rows:
        if r["lead_id"] == lead_id or (sk and r.get("source_key") == sk) or r["content_hash"] == h or r["posted_url"] == posted_url: raise ValueError("duplicate: this lead, source, text or URL is already in the ledger")
    e = {"lead_id": lead_id, "source_key": sk, "title": title, "platform": platform, "content_hash": h, "approval_ref": approval_ref.strip(), "posted_url": posted_url,
         "posted_at": posted_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now or time.time())), "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now or time.time()))}
    with open(path, "a") as f: f.write(json.dumps(e) + "\n")
    return e
NUM = ("impressions", "reactions", "comments", "reposts", "saves", "sends")
def metric_rows(csv_path):
    """Header: post_url,date plus any of impressions,reactions,comments,reposts,saves,sends. Blank cell = not available (kept as None, never 0).
    engagements = reactions + comments + reposts, only when all three are present."""
    out = []
    if not os.path.exists(csv_path): return out
    for r in csv.DictReader(open(csv_path)):
        row = {"post_url": (r.get("post_url") or "").strip(), "date": (r.get("date") or "").strip()}
        for k in NUM:
            v = (r.get(k) or "").strip()
            if v == "": row[k] = None
            else:
                if not v.isdigit(): raise ValueError(f"{k} must be a whole number or blank, got {v!r}")
                row[k] = int(v)
        row["engagements"] = sum(row[k] for k in ("reactions", "comments", "reposts")) if all(row[k] is not None for k in ("reactions", "comments", "reposts")) else None
        out.append(row)
    return out
def results(ledger_path, metrics_csv):
    rows = metric_rows(metrics_csv); out = []
    for e in read(ledger_path):
        mine = sorted([m for m in rows if m["post_url"] == e["posted_url"]], key=lambda m: m["date"])
        last = mine[-1] if mine else None
        r = {"posted_url": e["posted_url"], "posted_at": e["posted_at"], "platform": e["platform"], "title": e["title"]}
        if not last: r["metrics"] = "not available: no analytics row has been read for this post yet"
        else:
            r["metrics_as_of"] = last["date"]; r["metrics"] = {k: last[k] if last[k] is not None else "not available" for k in NUM + ("engagements",)}
            if last["impressions"] and last["engagements"] is not None: r["engagement_rate"] = round(last["engagements"] / last["impressions"], 4)
        out.append(r)
    n = sum(1 for r in out if isinstance(r["metrics"], dict))
    return {"posts": len(out), "posts_with_metrics": n, "verdict": "no comparison: fewer than 5 posts with metrics" if n < 5 else "enough posts to compare", "items": out}
