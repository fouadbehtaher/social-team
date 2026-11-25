"""Publishing boundary. Deliberately small:
- consumes ONLY the hash-checked approved export (a human approved the exact text); recomputes the content hash itself and refuses any mismatch;
- the Postiz adapter can create DRAFTS only (Postiz API type "draft": stored, not scheduled, not published; promoted by a human in the Postiz UI). "now" and "schedule" are not implemented here on purpose;
- dry run by default: nothing leaves the machine unless send=True AND an instance URL and API key are configured by the owner;
- talks to Postiz over its documented public HTTP API only (https://docs.postiz.com/public-api/posts/create). No Postiz code is copied (Postiz is AGPL-3.0).
Offline-tested with a fake transport. Never run live against any Postiz instance by the build."""
import json, os, time, datetime, urllib.request, urllib.parse
from .review import content_hash

POSTIZ_TYPES = {"linkedin": "linkedin", "x": "x", "medium": "medium"}   # tiktok is a spoken script, not a video file: Postiz TikTok needs media and many settings, so it is refused here
HOURLY_LIMIT = 30                                                         # documented Postiz public API limit: 30 requests per hour

class PublishRefused(Exception): pass

def verified_items(export_path):
    """Items whose recomputed hash equals the approved hash. Anything else is refused, not skipped silently."""
    ex = json.load(open(export_path)); ok = []
    if ex.get("blocked_changed_after_approval"): raise PublishRefused("export lists items changed after approval: " + ",".join(ex["blocked_changed_after_approval"]))
    for it in ex["items"]:
        if content_hash(it["platform"], it["text"], it.get("image")) != it["approved_hash"]: raise PublishRefused(f"hash mismatch for {it['id']}")
        ok.append(it)
    return ok

class PostizDraftAdapter:
    def __init__(self, base_url, api_key, integrations, transport=None, state_path=None, now=None):
        u = urllib.parse.urlparse(base_url)
        if u.scheme != "https" and u.hostname not in ("localhost", "127.0.0.1"): raise PublishRefused("Postiz URL must be https (or localhost)")
        if not api_key: raise PublishRefused("no Postiz API key configured")
        self.url = base_url.rstrip("/") + "/public/v1/posts"; self.key = api_key; self.integrations = integrations
        self._t = transport or self._http; self.state_path = state_path; self._now = now or time.time
    def payload(self, it):
        t = POSTIZ_TYPES.get(it["platform"])
        if not t: raise PublishRefused(f"{it['platform']} is not supported by this adapter")
        iid = self.integrations.get(it["platform"])
        if not iid: raise PublishRefused(f"no Postiz integration id configured for {it['platform']}")
        if t == "medium" and not (it.get("title") and it.get("subtitle")): raise PublishRefused("Medium needs title and subtitle (Postiz settings)")
        settings = {"__type": t}
        if t == "x": settings["who_can_reply_post"] = "everyone"
        if t == "medium": settings.update(title=it["title"], subtitle=it["subtitle"])
        if len(it["text"]) > 280 and t == "x": raise PublishRefused("X text over 280 characters")
        return {"type": "draft", "date": datetime.datetime.fromtimestamp(self._now(), datetime.timezone.utc).isoformat(), "shortLink": False, "tags": [],
                "posts": [{"integration": {"id": iid}, "value": [{"content": it["text"], "image": []}], "settings": settings}]}
    def _budget(self):
        if not self.state_path: return
        st = json.load(open(self.state_path)) if os.path.exists(self.state_path) else []
        st = [x for x in st if x > self._now() - 3600]
        if len(st) >= HOURLY_LIMIT: raise PublishRefused("Postiz hourly request limit (30) reached")
        st.append(self._now()); json.dump(st, open(self.state_path, "w"))
    def _http(self, url, headers, body):
        req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
        return json.load(urllib.request.urlopen(req, timeout=30))
    def create_drafts(self, items, send=False):
        out = []
        for it in items:
            p = self.payload(it)
            if not send: out.append({"id": it["id"], "dry_run": True, "payload": p}); continue
            self._budget()
            r = self._t(self.url, {"Authorization": self.key, "Content-Type": "application/json"}, p)   # raw key in Authorization, no Bearer, per Postiz docs
            out.append({"id": it["id"], "dry_run": False, "response": r})
        return out

class TryPostDraftAdapter:
    """TryPost (AGPL-3.0, no code copied). REST contract read 2026-11-25: POST {APP_URL}/api/posts, Bearer workspace API key, Accept: application/json,
    body {content, status, social_account_id}; status 'draft' is the default and saves an editable draft. https://docs.trypost.it/api-reference/posts/create-post
    IMPORTANT per the same docs: API keys belong to workspace admins and admins publish directly, so ONLY status 'draft' is ever sent here;
    'scheduled' and 'publishing' are not implemented. Limit 60 requests/minute per workspace (a sequential loop stays far below it).
    Networks: linkedin and x only (Medium support not verified in the docs read; TikTok needs media). Offline-tested only; never run against an instance by the build."""
    LIMITS = {"linkedin": 3000, "x": 280}
    def __init__(self, base_url, api_key, accounts, transport=None):
        u = urllib.parse.urlparse(base_url)
        if u.scheme != "https" and u.hostname not in ("localhost", "127.0.0.1"): raise PublishRefused("TryPost URL must be https (or localhost)")
        if not api_key: raise PublishRefused("no TryPost API key configured")
        self.url = base_url.rstrip("/") + "/posts"; self.key = api_key; self.accounts = accounts; self._t = transport or self._http
    def payload(self, it):
        if it["platform"] not in self.LIMITS: raise PublishRefused(f"{it['platform']} is not supported by the TryPost adapter")
        aid = self.accounts.get(it["platform"])
        if not aid: raise PublishRefused(f"no TryPost social account id configured for {it['platform']}")
        if len(it["text"]) > self.LIMITS[it["platform"]]: raise PublishRefused(f"{it['platform']} text over {self.LIMITS[it['platform']]} characters")
        return {"content": it["text"], "status": "draft", "social_account_id": aid}
    def _http(self, url, headers, body):
        return json.load(urllib.request.urlopen(urllib.request.Request(url, json.dumps(body).encode(), headers), timeout=30))
    def create_drafts(self, items, send=False):
        out = []
        for it in items:
            p = self.payload(it)
            if not send: out.append({"id": it["id"], "dry_run": True, "payload": p}); continue
            out.append({"id": it["id"], "dry_run": False, "response": self._t(self.url, {"Authorization": "Bearer " + self.key, "Accept": "application/json", "Content-Type": "application/json"}, p)})
        return out
