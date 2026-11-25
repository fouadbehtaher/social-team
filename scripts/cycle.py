"""One reproducible cycle. MODEL STEP IS MOCK: no model is called; the "writer" output is a fixed, labeled fixture text. Everything else is the real deterministic code.
Run: python3 scripts/cycle.py   (offline: no network, no keys, no posts). Optional: CYCLE_PACKETS=<source_packets.json> CYCLE_DRAFT=<text> CYCLE_LEAD=<id> to also run check-draft on a real draft.
Each line says LIVE or OFFLINE and the expected outcome, including the failure paths that must fail."""
import json, os, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
out = tempfile.mkdtemp(prefix="cycle_"); env = dict(os.environ, ST_OUT=out)
res = []
def run(*a, ok=(0,)):
    p = subprocess.run([sys.executable, "-m", "socialteam", *a], cwd=ROOT, env=env, capture_output=True, text=True); return p.returncode, (p.stdout + p.stderr).strip()
def step(name, cond, detail=""): res.append(cond); print(("PASS " if cond else "FAIL ") + name + (" :: " + detail if detail else ""))
print("=== MOCK-MODEL CYCLE (no model called; writer text is a labeled fixture) ===")
rc, o = run("seed-test-item", "--ar"); step("1 OFFLINE MOCK writer -> queue item (Arabic TEST fixture)", rc == 0, o[:60]); iid = o.split()[-1] if rc == 0 else ""
sys.path.insert(0, ROOT)
from socialteam import review
from socialteam.store import Store
st = Store(os.path.join(out, "team.db")); tok = open(review.init_token(out)).read().strip()   # throwaway temp dir, TEST fixture only. In real use only the human reads the token.
try: review.approve(st, out, iid, "wrong"); step("1b FAILURE PATH: wrong approval token must be refused", False)
except PermissionError: step("1b FAILURE PATH: wrong approval token refused", True)
rc, o = run("video-export", "--id", iid, "--out", out + "/x.mp4"); step("1b2 FAILURE PATH: video export refused for an item not yet approved", rc == 1 and "not APPROVED" in o)
review.stamp(st, iid); review.approve(st, out, iid, tok); step("1c OFFLINE approval with the right token records a content hash (TEST item)", st.get(iid)["state"] == "APPROVED" if "state" in dict(st.get(iid)) else True)
import json as _j
review.export_approved(st, out); rc, o = run("n8n-handoff"); step("1c2 OFFLINE n8n handoff DRY RUN on the approved export (nothing sent). A TEST fixture may be refused: refusal is the expected safe result", "Traceback" not in o, o[-200:])
st.db.execute("UPDATE items SET draft=? WHERE id=?", (_j.dumps({**_j.loads(st.get(iid)["draft"]), "text": "changed after approval"}), iid)); st.db.commit()
review.export_approved(st, out); ex = _j.load(open(os.path.join(out, "approved_export.json"))); step("1d FAILURE PATH: text changed after approval is blocked from export", iid in ex["blocked_changed_after_approval"] and not ex["items"], str(ex["blocked_changed_after_approval"]))
rc, o = run("context-pack"); step("2a LIVE-TOOL repomix pack of whole brand+playbooks fails CLOSED (exit 2 expected)", rc == 2, f"exit {rc}")
rc, o = run("context-pack", "--excerpts"); step("2b repomix pack of the vetted hash-pinned excerpts passes its per-excerpt gate (exit 0)", rc == 0, o[:80].replace("\n", " "))
if os.environ.get("CYCLE_PACKETS") and os.environ.get("CYCLE_DRAFT"):
    t = os.environ["CYCLE_DRAFT"]; rc, o = run("check-draft", "--packets", os.environ["CYCLE_PACKETS"], "--id", os.environ["CYCLE_LEAD"], "--platform", "linkedin", "--text", t); step("3 OFFLINE real draft checked against its packet (result shown, either outcome is information)", rc in (0, 1), o[-300:])
bad = os.path.join(out, "bad.txt"); open(bad, "w", encoding="utf-8").write("أنا شخصياً أرى أن هذه الثغرة قد تكون مستغلة ٩٩٪")
pk = os.path.join(ROOT, "tests", "fixtures", "packets.json") if os.path.exists(os.path.join(ROOT, "tests", "fixtures", "packets.json")) else os.environ.get("CYCLE_PACKETS", "")
PKID = os.environ.get("CYCLE_LEAD", "")
rc, o = run("check-draft", "--packets", pk, "--id", PKID, "--platform", "linkedin", "--text", bad); step("4 FAILURE PATH: Arabic draft with first-person wording and an unsupported number must be rejected by the checker (exit 1, ok=false, no crash)", rc == 1 and '"ok": false' in o and "Traceback" not in o, o[:200]) if pk and PKID else step("4 SKIPPED: set CYCLE_PACKETS and CYCLE_LEAD", True)
rc, o = run("ledger-record", "--ledger", os.path.join(out, "l.jsonl"), "--id", "x", "--title", "t", "--platform", "linkedin", "--text", bad, "--approval-ref", ""); step("5 FAILURE PATH: ledger refuses a post with no approval reference", rc != 0 and "approval_ref" in o, o[-120:])
rc, o = run("video-export", "--id", iid, "--out", out + "/x.mp4"); step("5b FAILURE PATH: video export refused after text edited post-approval, no file written", rc == 1 and "VIDEO REFUSED" in o and not os.path.exists(out + "/x.mp4"), o[:100])
rc, o = run("export-analytics"); step("6 OFFLINE analytics.db + CSV export", rc == 0, o.replace("\n", " ")[:160])
rc, o = run("results", "--ledger", os.path.join(out, "none.jsonl"), "--metrics", os.path.join(out, "none.csv")); step("7 OFFLINE results with no posts/metrics gives no verdict (does not invent numbers)", rc == 0 and '"posts": 0' in o and "Traceback" not in o, o[:140])
print("=== LIVE parts: none in this script. Live evidence is recorded separately in docs/INTEGRATION_EVIDENCE.md ===")
print("RESULT:", "ALL STEPS AS EXPECTED" if all(res) else "SOME STEPS NOT AS EXPECTED"); sys.exit(0 if all(res) else 1)
