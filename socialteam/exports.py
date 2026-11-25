"""Hand-off and observability boundaries. All three are DRY RUN unless send is explicitly requested AND the owner configured a URL and credentials.
None of them is ever run live by the build. They talk to the tools' documented HTTP/file contracts only and copy no code from them
(n8n: Sustainable Use License, Langfuse: MIT with ee/ excepted, Metabase: AGPL/commercial).
1. analytics_export: derived SQLite + CSV with no draft text, readable by Metabase's SQLite driver (self-hosted only, https://www.metabase.com/docs/latest/databases/connections/sqlite).
2. trace_otlp: OTLP/HTTP JSON spans for Langfuse (https://langfuse.com/integrations/native/opentelemetry). The legacy /api/public/ingestion endpoint is deprecated, so it is not used.
   Metadata only by default: no prompts, no model output, no draft text.
3. n8n_handoff: POST of the hash-verified approved export to an n8n Webhook node (https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook), header auth. It is a notification, not a publish command."""
import json, csv, os, sqlite3, hashlib, base64, urllib.request, urllib.parse, time
from .publishers import verified_items, PublishRefused
from .review import is_test

def _https_or_local(url, what):
    u = urllib.parse.urlparse(url)
    if u.scheme != "https" and u.hostname not in ("localhost", "127.0.0.1"): raise PublishRefused(f"{what} URL must be https (or localhost)")
    if u.username or u.password: raise PublishRefused(f"{what} URL must not embed credentials")

# ---- 1. analytics -------------------------------------------------------------------------------------------------
def analytics_export(store, out_dir):
    p = f"{out_dir}/analytics.db"
    if os.path.exists(p): os.remove(p)
    a = sqlite3.connect(p)
    a.executescript("""CREATE TABLE items_summary(id TEXT, platform TEXT, state TEXT, lead_title TEXT, source_domain TEXT, source_primary INT, created TEXT, updated TEXT, content_hash TEXT, approved INT, test_fixture INT);
CREATE TABLE model_calls(ts TEXT, role TEXT, route TEXT, result TEXT, error TEXT);
CREATE TABLE funnel(state TEXT, items INT);
CREATE TABLE metrics(post_id TEXT, platform TEXT, date TEXT, impressions INT, engagements INT);
CREATE VIEW engagement_by_platform AS SELECT platform, COUNT(DISTINCT post_id) posts, SUM(impressions) impressions, SUM(engagements) engagements, ROUND(1.0*SUM(engagements)/NULLIF(SUM(impressions),0),4) engagement_rate FROM metrics GROUP BY platform;
CREATE VIEW route_reliability AS SELECT route, COUNT(*) calls, SUM(result='route_failure') failures FROM model_calls GROUP BY route;""")
    iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
    for r in store.db.execute("SELECT * FROM items"):
        ev = json.loads(r["evidence"]) if r["evidence"] else {}
        a.execute("INSERT INTO items_summary VALUES(?,?,?,?,?,?,?,?,?,?,?)", (r["id"], r["platform"], r["state"], r["lead_title"], ev.get("domain"), int(bool(ev.get("primary"))) if ev else None,
                  iso(r["created"]), iso(r["updated"]), r["content_hash"], int(r["state"] == "APPROVED"), int(is_test(r))))
    for r in store.db.execute("SELECT ts, detail FROM events WHERE node='route' ORDER BY id"):
        d = json.loads(r["detail"]); a.execute("INSERT INTO model_calls VALUES(?,?,?,?,?)", (iso(r["ts"]), d.get("role"), d.get("route"), d.get("result"), (d.get("error") or "")[:120]))
    for r in store.db.execute("SELECT state, COUNT(*) n FROM items GROUP BY state"): a.execute("INSERT INTO funnel VALUES(?,?)", (r["state"], r["n"]))
    for r in store.db.execute("SELECT * FROM metrics"): a.execute("INSERT INTO metrics VALUES(?,?,?,?,?)", tuple(r))
    a.commit(); files = [p]
    for t in ("items_summary", "model_calls", "funnel", "metrics", "engagement_by_platform", "route_reliability"):
        cur = a.execute(f"SELECT * FROM {t}"); f = f"{out_dir}/analytics_{t}.csv"
        with open(f, "w", newline="") as fh: w = csv.writer(fh); w.writerow([c[0] for c in cur.description]); w.writerows(cur)
        files.append(f)
    a.close(); return files

# ---- 2. traces ----------------------------------------------------------------------------------------------------
SAFE = ("role", "route", "result", "ok", "frm", "to", "why", "new", "attempt", "queued", "published", "mode", "platform")
def _attr(k, v):
    if isinstance(v, bool): return {"key": k, "value": {"boolValue": v}}
    if isinstance(v, int): return {"key": k, "value": {"intValue": str(v)}}
    return {"key": k, "value": {"stringValue": str(v)[:200]}}
def trace_otlp(store, include_ids=True):
    """One trace per item (events without an item go to one 'pipeline' trace). Each event is a zero-length span under a root span. Metadata only."""
    groups = {}
    for r in store.db.execute("SELECT id, ts, item_id, node, detail FROM events ORDER BY id"): groups.setdefault(r["item_id"] or "pipeline", []).append(r)
    spans = []
    for key, evs in groups.items():
        tid = hashlib.sha256(("trace:" + key).encode()).hexdigest()[:32]; rid = hashlib.sha256(("root:" + key).encode()).hexdigest()[:16]
        t0, t1 = int(evs[0]["ts"] * 1e9), int(evs[-1]["ts"] * 1e9)
        name = "social-team item" if key != "pipeline" else "social-team pipeline"
        root = [_attr("langfuse.trace.name", name), _attr("langfuse.observation.type", "chain")]
        if include_ids and key != "pipeline": root.append(_attr("langfuse.trace.metadata.item_id", key))
        spans.append({"traceId": tid, "spanId": rid, "name": name, "kind": 1, "startTimeUnixNano": str(t0), "endTimeUnixNano": str(max(t1, t0 + 1)), "attributes": root, "status": {"code": 1}})
        for r in evs:
            d = json.loads(r["detail"] or "{}"); t = int(r["ts"] * 1e9); failed = d.get("result") == "route_failure" or "error" in d or "role_error" in d
            at = [_attr("langfuse.observation.type", "span"), _attr("langfuse.observation.level", "ERROR" if failed else "DEFAULT")]
            at += [_attr(f"langfuse.observation.metadata.{k}", d[k]) for k in SAFE if k in d and not isinstance(d[k], (dict, list))]
            if failed: at.append(_attr("langfuse.observation.status_message", str(d.get("error") or d.get("role_error") or d.get("result"))[:120]))
            spans.append({"traceId": tid, "spanId": hashlib.sha256(f"span:{r['id']}".encode()).hexdigest()[:16], "parentSpanId": rid, "name": r["node"], "kind": 1,
                          "startTimeUnixNano": str(t), "endTimeUnixNano": str(t + 1000), "attributes": at, "status": {"code": 2 if failed else 1}})
    return {"resourceSpans": [{"resource": {"attributes": [_attr("service.name", "social-team")]}, "scopeSpans": [{"scope": {"name": "socialteam"}, "spans": spans}]}]}
def send_traces(payload, base_url, public_key, secret_key, send=False, transport=None):
    if not send: return {"dry_run": True, "spans": len(payload["resourceSpans"][0]["scopeSpans"][0]["spans"])}
    _https_or_local(base_url, "Langfuse")
    if not (public_key and secret_key): raise PublishRefused("Langfuse keys not configured")
    h = {"Authorization": "Basic " + base64.b64encode(f"{public_key}:{secret_key}".encode()).decode(), "x-langfuse-ingestion-version": "4", "Content-Type": "application/json"}
    url = base_url.rstrip("/") + "/api/public/otel/v1/traces"
    if transport: return transport(url, h, payload)
    return {"status": urllib.request.urlopen(urllib.request.Request(url, json.dumps(payload).encode(), h), timeout=30).status}

# ---- 3. n8n -------------------------------------------------------------------------------------------------------
MAX_N8N_BYTES = 16 * 1024 * 1024    # n8n documented default webhook payload limit
def n8n_payload(export_path):
    items = verified_items(export_path)
    if not items: raise PublishRefused("no approved items to hand off")
    return {"schema": 1, "source": "social-team", "kind": "approved_export", "publish": False,
            "note": "Approved text only. A workflow must still get its own per-post publish approval. Recompute approved_hash before use.",
            "items": [{k: it.get(k) for k in ("id", "platform", "text", "title", "subtitle", "source", "approved_hash")} | {"image_file": os.path.basename(it["image"]) if it.get("image") else None} for it in items]}
def send_n8n(payload, webhook_url, header, send=False, transport=None):
    body = json.dumps(payload).encode()
    if len(body) > MAX_N8N_BYTES: raise PublishRefused("payload over the 16MB n8n default")
    if not send: return {"dry_run": True, "items": len(payload["items"]), "bytes": len(body)}
    _https_or_local(webhook_url, "n8n webhook")
    name, _, val = (header or "").partition(":")
    if not (name.strip() and val.strip()): raise PublishRefused("n8n header auth not configured (N8N_AUTH_HEADER='Name: value')")
    h = {name.strip(): val.strip(), "Content-Type": "application/json"}
    if transport: return transport(webhook_url, h, payload)
    try: return {"status": urllib.request.urlopen(urllib.request.Request(webhook_url, body, h), timeout=30).status}
    except urllib.error.HTTPError as e:   # a rejected call is a clean, reported result, never a traceback
        return {"status": e.code, "ok": False, "rejected": e.code in (401, 403), "error": "n8n answered HTTP %s" % e.code}
