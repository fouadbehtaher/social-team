"""Deploy-readiness check. Reads configuration only: no network, no model call, no file written. It never prints a secret value.
Levels: FAIL (do not run), WARN (check before relying on it), OK. Exit code 1 when any FAIL."""
import os, sys, stat, shutil, urllib.parse

PLACEHOLDERS = {"changeme", "change-me", "secret", "password", "xxx", "todo", "example", "test", "dry-run"}

def _meminfo_gb():
    try:
        for l in open("/proc/meminfo"):
            if l.startswith("MemTotal:"): return int(l.split()[1]) / 1048576
    except OSError: pass
    return None

def check(env=None, out_dir="out", repo_root=".", py=None, mem_gb="auto", free_gb=None, which=shutil.which):
    env = os.environ if env is None else env
    r = []
    add = lambda lvl, name, msg: r.append({"level": lvl, "check": name, "detail": msg})
    py = py or sys.version_info[:3]
    add("OK" if tuple(py) >= (3, 10) else "FAIL", "python", "%d.%d.%d (needs 3.10+)" % tuple(py))
    # model route: report which writer the CLI would pick, never the key
    has_or = bool(env.get("OPENROUTER_API_KEY")); has_xai = bool(env.get("XAI_API_KEY"))
    if has_or and env.get("ST_FREE_MODELS") or has_or and env.get("ST_FREE_MODEL"):
        add("WARN", "model", "free OpenRouter route configured; it is a disclosed substitute, never Grok, and may be throttled. Output must stay labeled.")
    elif has_xai: add("WARN", "model", "XAI_API_KEY is set; calls fail until the API team has prepaid credit. No call is made by this check.")
    else: add("WARN", "model", "no model key configured: only 'run --mock' works, and its output is labeled MOCK")
    # n8n handoff
    url = env.get("N8N_WEBHOOK_URL", ""); hdr = env.get("N8N_AUTH_HEADER", "")
    if url:
        u = urllib.parse.urlparse(url)
        ok = (u.scheme == "https" or u.hostname in ("localhost", "127.0.0.1")) and not (u.username or u.password)
        add("OK" if ok else "FAIL", "n8n_url", "https (or loopback) and no embedded credentials" if ok else "N8N_WEBHOOK_URL must be https, or loopback, with no user:pass")
        name, _, val = hdr.partition(":"); name = name.strip(); val = val.strip()
        if not (name and val): add("FAIL", "n8n_auth", "N8N_AUTH_HEADER must look like 'Header-Name: value'")
        elif len(val) < 24 or val.lower() in PLACEHOLDERS: add("FAIL", "n8n_auth", "header value is short or a placeholder (use 24+ random characters)")
        else: add("OK", "n8n_auth", "header configured (value not shown)")
    else: add("WARN", "n8n", "N8N_WEBHOOK_URL not set: n8n-handoff stays a dry run")
    # review page must stay local
    host = env.get("ST_REVIEW_HOST")
    if host and host not in ("127.0.0.1", "localhost"): add("FAIL", "review_host", "the review page must bind loopback only")
    else: add("OK", "review_host", "review page binds 127.0.0.1 only (reach it over an SSH tunnel; no phone-only approval path exists yet)")
    # files
    tok = os.path.join(out_dir, ".approval_token")
    if os.path.exists(tok):
        mode = stat.S_IMODE(os.stat(tok).st_mode)
        add("OK" if mode & 0o077 == 0 else "FAIL", "approval_token", "mode %o" % mode + ("" if mode & 0o077 == 0 else ", must not be group/world readable"))
    if os.path.isdir(out_dir):
        m = stat.S_IMODE(os.stat(out_dir).st_mode)
        add("OK" if not m & 0o002 else "FAIL", "out_dir", "mode %o" % m + ("" if not m & 0o002 else ", world-writable"))
    gi = os.path.join(repo_root, ".gitignore")
    txt = open(gi).read().split() if os.path.exists(gi) else []
    miss = [p for p in (".env", "out*/", "*.db", ".approval_token") if p not in txt]
    add("OK" if not miss else "FAIL", "gitignore", "secrets and state are ignored" if not miss else "missing from .gitignore: " + ", ".join(miss))
    if os.path.exists(os.path.join(repo_root, ".env")): add("WARN", "env_file", ".env exists in the repo folder; keep it out of backups and commits")
    # resources
    mem = _meminfo_gb() if mem_gb == "auto" else mem_gb
    if mem is not None:
        add("OK" if mem >= 3.5 else "WARN", "memory", "%.1f GB total; n8n plus Chrome together are unproven under 4 GB" % mem)
    fr = free_gb if free_gb is not None else (shutil.disk_usage(out_dir if os.path.isdir(out_dir) else ".").free / 1073741824)
    add("OK" if fr >= 20 else "WARN", "disk", "%.0f GB free (30+ GB advised with Docker images)" % fr)
    for tool, why in (("node", "Remotion video export; n8n 2.49.6 requires Node >=24 (observed: refused to start on Node 22)"), ("google-chrome", "Crawl4AI/Remotion (or set ST_CHROME_CHANNEL)")):
        add("OK" if which(tool) or (tool == "google-chrome" and (which("chromium") or env.get("ST_CHROME_CHANNEL"))) else "WARN", tool, ("found" if which(tool) else "not on PATH") + "; used for " + why)
    return r

def main(out_dir="out"):
    import json
    rows = check(out_dir=out_dir)
    for x in rows: print("%-4s %-14s %s" % (x["level"], x["check"], x["detail"]))
    bad = [x for x in rows if x["level"] == "FAIL"]
    print(json.dumps({"fail": len(bad), "warn": sum(x["level"] == "WARN" for x in rows), "ok": sum(x["level"] == "OK" for x in rows)}))
    return 1 if bad else 0
