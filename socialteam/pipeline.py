import json, os, time, urllib.request, urllib.parse
from typing import TypedDict, List
from langgraph.graph import StateGraph, END
from .models import key, to_dict, PLATFORMS, Evidence, Draft
from . import grounding, design, roles

NICHE = ["security", "vulnerab", "bug bounty", "aws", "smart contract", "exploit", "cve", "ethereum", "phishing", "malware", "cloud", "authentication"]
QUERIES = ["bug bounty", "aws security", "smart contract exploit", "vulnerability disclosure"]

class S(TypedDict, total=False):
    stopped: str
    ids: List[str]; verified: List[str]; drafted: List[str]; brand: str

def build(store, provider, out_dir, search=None, verify=None, max_items=3, retries=2, today=None, strict=False, stop_after=None, playbooks_on=False):
    """strict: any model-stage rejection or error halts the run (no fallback output, no later calls). stop_after: halt after that node, for stage-by-stage bounded runs."""
    halt = {"on": False, "why": ""}
    def stop(why): halt["on"] = True; halt["why"] = why; store.event("halt", None, why=why)
    verify = verify or grounding.verify_feed_item
    from .budget import BudgetExceeded
    from . import playbooks
    if playbooks_on == "pack": pb = lambda role, plat: playbooks.pack_block(role, plat, os.path.join(out_dir, "context.excerpts.pack.manifest.json"))   # ST_PLAYBOOKS=pack: only via a verified Repomix pack (run context-pack --excerpts first)
    else: pb = (lambda role, plat: playbooks.block(role, plat)) if playbooks_on else (lambda role, plat: "")
    llm_roles = hasattr(provider, 'complete')
    runner = roles.RoleRunner(provider, retries=retries, on_fail=lambda r, raw, err: store.event('role_fail', None, role=r, error=err, raw=roles.redact(raw)[:2000])) if llm_roles else None
    def src_of(id_): return Evidence(**json.loads(store.get(id_)['evidence']))
    def save_role(id_, role, data):
        cur = json.loads(store.get(id_)['roles'] or '{}'); cur[role] = data
        store.db.execute('UPDATE items SET roles=? WHERE id=?', (json.dumps(cur), id_)); store.db.commit()
    def role(id_, name, user, ev, **kw):
        cached = json.loads(store.get(id_)['roles'] or '{}').get(name)
        if cached: return cached          # checkpoint: a saved role result is never re-requested
        data = runner.run(name, user, ev, plat=store.get(id_)["platform"], **kw); save_role(id_, name, data); store.event('role', id_, role=name, ok=True); return data
    def role_brief(id_, name): return json.loads(store.get(id_)['roles'] or '{}').get(name)

    from . import feeds
    def scout(s):  # role 1: official feeds only. Output = LEADS with feed metadata.
        new = []
        for m in feeds.collect(today=today, log=lambda **k: store.event("scout", **k)) if search is None else search():
            id_ = key(*m["id"]); plat = PLATFORMS[(store.db.execute("SELECT COUNT(*) FROM items").fetchone()[0]) % len(PLATFORMS)]
            if store.add_lead(id_, plat, m["title"], m["url"], json.dumps(m)): new.append(id_)
        store.event("scout", new=len(new)); return {"ids": new}

    def ground(s):  # verification gate: primary page fetched, fresh, relevant. Transient failures retried across runs (max 3), policy failures final.
        ok = []; stopped = []
        def _rel(r): return -(json.loads(r["roles"] or '{}').get("trend_scout") or {}).get("relevance", 0)
        resumable = store.by_state("DRAFTED") + store.by_state("VERIFIED")    # items further along first
        for r in sorted(resumable, key=lambda r: (r["state"] != "DRAFTED", _rel(r), r["id"])):    # resume first (best saved trend_scout rating first): finished roles are never re-called
            if len(ok) >= max_items: break
            if (json.loads(r["roles"] or '{}')).get("trend_scout") and not (r["reviewer_note"] or "").startswith("auto: ") and (r["state"] == "DRAFTED" or not r["draft"]): ok.append(r["id"])
        for it0 in sorted(store.by_state("LEAD"), key=lambda r: json.loads(r["meta"] or "{}").get("published") or "", reverse=True):
            if len(ok) >= max_items: break
            id_ = it0["id"]
            if it0["attempts"] >= 3: store.move(id_, "REJECTED_LEAD", reviewer_note="auto: gave up after 3 fetch attempts"); continue
            try:
                ev = verify(json.loads(it0["meta"])) if it0["meta"] else grounding.verify(it0["lead_url"])
                text = (ev.title + " " + ev.excerpt).lower()
                if not any(k in text for k in NICHE): raise grounding.GroundingError("off-niche")
                fp = grounding.freshness_problem(ev, today=today)
                if fp: raise grounding.GroundingError(fp)
                store.move(id_, "VERIFIED", evidence=json.dumps(to_dict(ev)))
                if llm_roles:   # role 1 editorial ranking (semantic judgement by the model; grounding above is deterministic)
                    t = role(id_, "trend_scout", roles.src(ev), ev)
                    if t["relevance"] < 2 or t["audience_fit"] == "none":
                        store.db.execute("UPDATE items SET reviewer_note=? WHERE id=?", (f"auto: trend_scout rated {t['relevance']}/5, fit {t['audience_fit']}", id_)); store.db.commit(); continue
                ok.append(id_)
            except BudgetExceeded as e: store.event("ground", id_, budget=str(e)); stopped.append(str(e)); break
            except roles.RoleError as e: store.event("ground", id_, role_error=str(e))
            except grounding.GroundingError as e:
                msg = str(e)
                if msg.startswith("fetch failed"):   # transient: keep as LEAD, count attempt
                    store.db.execute("UPDATE items SET attempts=attempts+1 WHERE id=?", (id_,)); store.db.commit(); store.event("ground", id_, transient=msg)
                else: store.move(id_, "REJECTED_LEAD", reviewer_note=f"auto: {msg}"); store.event("ground", id_, rejected=msg)
        for r in ([] if strict else store.by_state("VERIFIED")):    # unfinished from an earlier run (budget stop, writer failure); skip editorially rejected
            if len(ok) >= max_items: break
            if r["id"] not in ok and not r["draft"] and not (r["reviewer_note"] or "").startswith("auto: trend_scout"): ok.append(r["id"])
        return {"verified": ok, "stopped": stopped[0] if stopped else ""}

    def route(s): return "strategist" if s["verified"] else END

    def strategist(s):  # role 2
        for id_ in list(s["verified"]):
            it = store.get(id_); ev = src_of(id_)
            if not llm_roles: store.event("strategist", id_, platform=it["platform"], mode="static"); continue
            try: role(id_, "strategist", f"platform: {it['platform']}\nbrand:\n{s['brand']}\n{pb('strategist', it['platform'])}{roles.src(ev)}", ev)
            except BudgetExceeded as e: store.event("strategist", id_, budget=str(e)); s["verified"].remove(id_); strict and stop(f"strategist budget: {e}")
            except roles.RoleError as e: store.event("strategist", id_, role_error=str(e)); s["verified"].remove(id_); strict and stop(f"strategist rejected: {e}")
            if halt["on"]: break
        return {"verified": s["verified"]}

    def writer(s):  # role 3: Grok writes; claims are validated against evidence; bounded retries
        done = []
        for id_ in s["verified"]:
            it = store.get(id_); ev = Evidence(**json.loads(it["evidence"])); draft = None
            if it["state"] == "DRAFTED" and it["draft"]: done.append(id_); continue    # checkpoint: already drafted
            if halt["on"]: break
            if llm_roles:   # role 3
                try:
                    w = role(id_, "writer", f"platform: {it['platform']}\nbrand:\n{s['brand']}\nplan: {json.dumps(role_brief(id_, 'strategist'))}\n{pb('writer', it['platform'])}{roles.src(ev)}", ev)
                    draft = Draft(it["platform"], w["text"], provider.name if hasattr(provider, "name") else "role-llm")
                except (roles.RoleError, BudgetExceeded) as e: store.event("writer", id_, error=str(e)); draft = None; strict and stop(f"writer rejected: {e}")
                if draft: store.move(id_, "DRAFTED", draft=json.dumps(to_dict(draft))); done.append(id_)
                else: store.db.execute("UPDATE items SET reviewer_note=? WHERE id=?", ("auto: writer role failed validation or budget", id_)); store.db.commit()
                continue
            for attempt in range(retries + 1):
                try: draft = provider.write(it["platform"], s["brand"], ev, "see platform"); 
                except Exception as e: store.event("writer", id_, error=str(e)); break
                draft.problems = grounding.check_claims(draft.text, ev)
                if not draft.problems: break
                store.event("writer", id_, attempt=attempt, problems=draft.problems)
            if draft and not draft.problems:
                store.move(id_, "DRAFTED", draft=json.dumps(to_dict(draft))); done.append(id_)
            else:
                store.db.execute("UPDATE items SET reviewer_note=? WHERE id=?", ("auto: draft failed claim check or provider error", id_)); store.db.commit()
        return {"drafted": done}

    def designer(s):  # role 4: card from verified facts only
        for id_ in s["drafted"]:
            it = store.get(id_); ev = Evidence(**json.loads(it["evidence"]))
            brief = None
            if llm_roles:   # role 4
                try: brief = role(id_, "designer", f"platform: {it['platform']}\n{roles.src(ev)}", ev)
                except (roles.RoleError, BudgetExceeded) as e:
                    store.event("designer", id_, error=str(e)); brief = None   # non-strict: falls back to the source's own title
                    if strict: stop(f"designer rejected: {e}"); break
            p = design.card(f"{out_dir}/cards/{id_}.png", it["platform"], ev, brief)
            store.db.execute("UPDATE items SET image=? WHERE id=?", (p, id_)); store.db.commit()
        return {}

    def scheduler(s):  # role 5: queue for HUMAN review. Never publishes.
        from . import review
        for id_ in s["drafted"]:
            if llm_roles:   # role 5: proposal text only; it cannot schedule
                try: role(id_, "scheduler", f"platform: {store.get(id_)['platform']}\ndraft: {json.loads(store.get(id_)['draft'])['text']}\n{roles.src(src_of(id_))}", src_of(id_))
                except (roles.RoleError, BudgetExceeded) as e:
                    store.event("scheduler", id_, error=str(e))
                    if strict: stop(f"scheduler rejected: {e}"); break
            store.move(id_, "PENDING_REVIEW"); review.stamp(store, id_)
        store.event("scheduler", queued=len(s["drafted"]), published=0); return {}

    def analyst(s):  # role 6: runs on imported metrics
        from . import analytics; rep = analytics.report(store); store.event("analyst", report=rep)
        if llm_roles and rep != {"status": "NO_DATA"}:   # role 6
            try: store.event("analyst_role", out=runner.run("analyst", "METRICS: " + json.dumps(rep), metrics_text=json.dumps(rep)))
            except (roles.RoleError, BudgetExceeded) as e: store.event("analyst_role", error=str(e))
        return {}

    g = StateGraph(S)
    def guard(n, f):
        def run(s):
            if halt["on"]: return {}
            out = f(s)
            if stop_after == n: stop(f"stop_after {n}")
            return out
        return run
    for n, f in [("scout", scout), ("ground", ground), ("strategist", strategist), ("writer", writer), ("designer", designer), ("scheduler", scheduler), ("analyst", analyst)]: g.add_node(n, guard(n, f))
    g.set_entry_point("scout"); g.add_edge("scout", "ground"); g.add_conditional_edges("ground", route, {"strategist": "strategist", END: END})
    for a, b in [("strategist", "writer"), ("writer", "designer"), ("designer", "scheduler"), ("scheduler", "analyst")]: g.add_edge(a, b)
    g.add_edge("analyst", END); return g.compile()
