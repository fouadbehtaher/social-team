"""Repomix (MIT, npm) packs the reviewed brand file and the vendored playbooks into one context file.
Used as a build step: the packed file is scanned by the same fail-closed scanner as playbooks (packs.inspect) and pinned by sha256 in a manifest.
Repomix's own secret scan stays on. The pack is NOT fed to a prompt automatically; playbooks.block remains the only prompt path."""
import hashlib, json, os, shutil, subprocess
from . import packs
class PackError(Exception): pass
def _bin():
    for c in (os.environ.get("ST_REPOMIX"), shutil.which("repomix"), "/tmp/rmx/node_modules/.bin/repomix"):
        if c and os.path.exists(c): return c
    raise PackError("repomix not installed (npm i repomix); nothing packed")
def excerpts(out):
    """The exact capped, hash-checked blocks playbooks.block would give a prompt (the vetted, benign prompt-bearing text), written one file each so Repomix packs only those."""
    from . import playbooks
    d = os.path.join(out, "excerpts"); os.makedirs(d, exist_ok=True); n = 0
    for (role, plat) in playbooks.PICK:
        b = playbooks.block(role, plat or "linkedin")
        if b: open(os.path.join(d, f"{role}-{plat or 'any'}.md"), "w", encoding="utf-8").write(b); n += 1
    return d, n
def pack_excerpts(out, runner=subprocess.run):
    d, n = excerpts(out)
    if not n: raise PackError("no playbook excerpt passed its gate; nothing packed")
    m = pack(d, out, runner, include="**/*.md", name="context.excerpts.pack.md", extra=["--no-file-summary", "--no-directory-structure"])
    # Scan verdict is per vetted excerpt (same gate and reviewed-hash allowance as playbooks.block), plus a check that Repomix kept each excerpt verbatim.
    # Scanning the whole Repomix file would flag the tool's own wrapper text, which is not source content.
    packed = open(m["file"], encoding="utf-8").read(); bad = []
    for f in sorted(os.listdir(d)):
        t = open(os.path.join(d, f), encoding="utf-8").read(); r = packs.inspect(t)
        body_hash_ok = r["ok"] or any(h in playbooks_reviewed() for h in [hashlib.sha256(_strip(t).encode()).hexdigest()])
        if not body_hash_ok: bad.append(f + ": " + ",".join(r["findings"]))
        if t.strip() not in packed: bad.append(f + ": not verbatim in pack")
    m.update(scan_ok=not bad, findings=bad, scope="per-excerpt gate; repomix wrapper text not scanned"); json.dump(m, open(m["file"].replace(".md", ".manifest.json"), "w"), indent=2); return m
def playbooks_reviewed():
    from . import playbooks; return playbooks.REVIEWED_FLAGGED
def _strip(block_text):
    import re; m = re.search(r">\n(.*)\n</playbook>", block_text, re.S); return (m.group(1) if m else block_text).strip()
def pack(root, out, runner=subprocess.run, include="brand/**,playbooks/**", name="context.pack.md", extra=()):
    out_file = os.path.join(out, name); os.makedirs(out, exist_ok=True)
    r = runner([_bin(), root, "--style", "markdown", "--include", include, "--ignore", "**/*.png,**/*.db", "-o", out_file, "--quiet", *extra], capture_output=True, text=True, timeout=120)
    if r.returncode != 0 or not os.path.exists(out_file): raise PackError("repomix failed (exit %s): %s" % (r.returncode, (r.stderr or "")[-300:]))
    data = open(out_file, "rb").read(); text = data.decode("utf-8", "replace")
    scan = packs.inspect(text)
    m = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "scan_ok": scan["ok"], "findings": scan.get("findings", scan.get("hits", [])), "file": out_file, "tool": "repomix"}
    json.dump(m, open(os.path.join(out, name.replace(".md", ".manifest.json")), "w"), indent=2, default=str); return m
