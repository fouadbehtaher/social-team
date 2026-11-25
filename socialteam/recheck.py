"""Re-validate SAVED role results and drafts against the current checks, with no model call.
A saved output that fails a newer check is dropped (the item goes back to VERIFIED so the next run regenerates it); APPROVED items are only reported, a human approved them."""
import json
from . import roles
from .models import Evidence

def recheck(store):
    report = []
    for it in store.db.execute("SELECT * FROM items WHERE roles IS NOT NULL OR draft IS NOT NULL").fetchall():
        ev = Evidence(**json.loads(it["evidence"])) if it["evidence"] else None
        saved = json.loads(it["roles"] or "{}"); problems = {}
        if "strategist" in saved and ev:
            p = roles.semantic_checks("strategist", saved["strategist"], ev)
            if p: problems["strategist"] = p
        if it["draft"] and ev:
            d = json.loads(it["draft"]); p = roles.semantic_checks("writer", {"text": d["text"]}, ev, plat=it["platform"])
            if p: problems["writer"] = p
        if not problems: continue
        action = "reported only (APPROVED by a human)" if it["state"] == "APPROVED" else "reset"
        if it["state"] in ("DRAFTED", "PENDING_REVIEW"):
            for r in ("strategist", "writer", "designer", "scheduler"): saved.pop(r, None)
            store.db.execute("UPDATE items SET roles=?, draft=NULL, image=NULL, content_hash=NULL WHERE id=?", (json.dumps(saved), it["id"])); store.db.commit()
            store.move(it["id"], "VERIFIED")
        store.event("recheck", it["id"], problems=problems, action=action)
        report.append({"id": it["id"], "state_before": it["state"], "problems": problems, "action": action})
    return report
