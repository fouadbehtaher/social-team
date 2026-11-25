import sys, os, json, getpass, re
from .store import Store
from .budget import Budget
from . import pipeline, review, analytics, llm
OUT = os.environ.get("ST_OUT", "out"); os.makedirs(OUT, exist_ok=True); st = Store(f"{OUT}/team.db")
cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
if cmd == "run":
    brand = open("brand/brand.md" if os.path.exists("brand/brand.md") else "brand/brand.example.md").read()
    from .mock import MockLLM
    def free_routes():
        models = [m.strip() for m in (os.environ.get("ST_FREE_MODELS") or os.environ["ST_FREE_MODEL"]).split(",") if m.strip()]
        approved = [m.strip() for m in os.environ.get("ST_FREE_APPROVED_ROUTES", "").split(",") if m.strip()]
        bad = [m for m in models if m not in approved]
        if bad: sys.exit("refusing: route(s) not in ST_FREE_APPROVED_ROUTES (explicit per-route user approval list): " + ", ".join(bad))
        mk = lambda m: llm.OpenRouterFreeProvider(f"{OUT}/team.db", m, daily_requests=int(os.environ.get("ST_FREE_REQUESTS", "20")), allow_retention=os.environ.get("ST_FREE_ALLOW_RETENTION") == "1", stream=os.environ.get("ST_FREE_STREAM") == "1", first_event_timeout=int(os.environ.get("ST_FIRST_EVENT_S", "30")), pin=llm.endpoint_slug(m))
        return llm.RoutedFreeProvider([mk(m) for m in models], on_attempt=lambda role, route, result, err: st.event("route", None, role=role, route=route, result=result, error=err))
    prov = MockLLM() if "--mock" in sys.argv else (free_routes() if os.environ.get("OPENROUTER_API_KEY") and (os.environ.get("ST_FREE_MODELS") or os.environ.get("ST_FREE_MODEL")) else llm.GrokProvider(Budget(f"{OUT}/team.db", float(os.environ.get("ST_DAILY_CAP_USD", "0.25")))) if os.environ.get("XAI_API_KEY") else llm.DemoExtractive())
    if prov.name.startswith("openrouter-free"): brand = next(l for l in brand.splitlines() if l.startswith("Voice:"))   # free route: send only a one-line style hint, no other brand/private text
    print("writer:", prov.name)
    r = pipeline.build(st, prov, OUT, max_items=int(os.environ.get("ST_MAX_ITEMS", "3")), retries=int(os.environ.get("ST_RETRIES", "2")), strict=os.environ.get("ST_STRICT") == "1", stop_after=os.environ.get("ST_STOP_AFTER") or None, playbooks_on=("pack" if os.environ.get("ST_PLAYBOOKS") == "pack" else os.environ.get("ST_PLAYBOOKS") == "1")).invoke({"brand": brand}); print({k: len(v) for k, v in r.items() if isinstance(v, list)}); print(review.render(st, OUT))
elif cmd == "publish-drafts":   # dry run unless --send; creates Postiz DRAFTS only, never schedules or publishes
    from . import publishers
    items = publishers.verified_items(f"{OUT}/approved_export.json")
    if "--target" in sys.argv and sys.argv[sys.argv.index("--target") + 1] == "trypost":
        ad = publishers.TryPostDraftAdapter(os.environ.get("TRYPOST_URL", "https://localhost/api"), os.environ.get("TRYPOST_API_KEY", "dry-run") if "--send" not in sys.argv else os.environ.get("TRYPOST_API_KEY"), json.loads(os.environ.get("TRYPOST_ACCOUNTS", "{}")))
        print(json.dumps(ad.create_drafts(items, send="--send" in sys.argv), indent=1)); sys.exit(0)
    ad = publishers.PostizDraftAdapter(os.environ.get("POSTIZ_URL", "https://localhost"), os.environ.get("POSTIZ_API_KEY", "dry-run") if "--send" not in sys.argv else os.environ.get("POSTIZ_API_KEY"),
                                       json.loads(os.environ.get("POSTIZ_INTEGRATIONS", "{}")), state_path=f"{OUT}/.postiz_rate.json")
    print(json.dumps(ad.create_drafts(items, send="--send" in sys.argv), indent=1))
elif cmd == "export-analytics":
    from . import exports; print("\n".join(exports.analytics_export(st, OUT)))
elif cmd == "export-traces":   # dry run unless --send; metadata only
    from . import exports
    pl = exports.trace_otlp(st); print(json.dumps(exports.send_traces(pl, os.environ.get("LANGFUSE_URL", "https://localhost"), os.environ.get("LANGFUSE_PUBLIC_KEY"), os.environ.get("LANGFUSE_SECRET_KEY"), send="--send" in sys.argv)))
    if "--save" in sys.argv: json.dump(pl, open(f"{OUT}/traces_otlp.json", "w")); print("saved", f"{OUT}/traces_otlp.json")
elif cmd == "n8n-handoff":    # dry run unless --send
    from . import exports
    print(json.dumps(exports.send_n8n(exports.n8n_payload(f"{OUT}/approved_export.json"), os.environ.get("N8N_WEBHOOK_URL", "https://localhost"), os.environ.get("N8N_AUTH_HEADER"), send="--send" in sys.argv)))
elif cmd == "review-serve":   # human runs this locally; 127.0.0.1 only
    from . import review_server
    port = int(os.environ.get("ST_REVIEW_PORT", "8765")); review.init_token(OUT); print(f"review page: http://127.0.0.1:{port}/  (Ctrl-C to stop)"); review_server.serve(st, OUT, port).serve_forever()
elif cmd == "seed-test-item":   # test fixture ONLY: writes a clearly labeled item into ST_OUT. Refuses any DB that already holds real items.
    from . import fixture; print(fixture.seed(st, OUT, arabic="--ar" in sys.argv))
elif cmd == "leads":      # NO model call: official feeds -> deterministic verification gate -> JSON source packets for an external writer. --ledger FILE skips leads/sources already posted.
    class NoModel: name = "no-model"
    from . import roles, ledger
    from .models import Evidence
    pipeline.build(st, NoModel(), OUT, max_items=int(os.environ.get("ST_MAX_ITEMS", "3")), stop_after="ground").invoke({"brand": ""})
    done = ledger.seen(sys.argv[sys.argv.index("--ledger") + 1]) if "--ledger" in sys.argv else set()
    pk = [{"id": r["id"], "title": r["lead_title"], "source_key": ledger.source_key(r["lead_title"]), "source_packet": roles.src(Evidence(**json.loads(r["evidence"]))), "evidence": json.loads(r["evidence"])} for r in st.by_state("VERIFIED") if r["evidence"]]
    print(json.dumps([p for p in pk if p["id"] not in done and p["source_key"] not in done], ensure_ascii=False, indent=1))
elif cmd == "video-export":   # video-export --id ITEM_ID --out FILE.mp4 : renders ONLY an item that is APPROVED and whose hash still matches. No model, no network. Needs `npm i` in video/.
    import tempfile, subprocess
    from . import publishers, ctxpack
    arg = lambda k: sys.argv[sys.argv.index(k) + 1]
    review.export_approved(st, OUT)
    try: items = publishers.verified_items(f"{OUT}/approved_export.json")
    except publishers.PublishRefused as e: print("VIDEO REFUSED:", e); sys.exit(1)
    it = next((i for i in items if i["id"] == arg("--id")), None)
    if not it: print("VIDEO REFUSED: item is not APPROVED (or not in the approved export)"); sys.exit(1)
    vd = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "video")
    if not os.path.isdir(os.path.join(vd, "node_modules", "remotion")): print("VIDEO REFUSED: run npm install in video/ first"); sys.exit(1)
    props = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8"); json.dump({"head": it.get("title") or re.split(r"(?<=[.!?؟])\s", it["text"].strip(), 1)[0], "text": it["text"] if len(it["text"]) <= 400 else it["text"][:400].rsplit(" ", 1)[0] + " ...", "banner": "TEST FIXTURE: fixed text, not model output, not a real claim" if it.get("test_fixture") else ""}, props, ensure_ascii=False); props.close()
    r = subprocess.run([os.path.join(vd, "render.sh"), os.path.abspath(arg("--out")), props.name], capture_output=True, text=True, timeout=300)
    os.unlink(props.name)
    print(json.dumps({"ok": r.returncode == 0, "out": arg("--out"), "approved_hash": it["approved_hash"], "stderr": r.stderr[-300:]})); sys.exit(r.returncode)
elif cmd == "context-pack":   # Repomix packs brand + playbooks into out/context.pack.md; scanned, hash-pinned. No model, no network.
    from . import ctxpack
    try: m = ctxpack.pack_excerpts(OUT) if "--excerpts" in sys.argv else ctxpack.pack(os.path.dirname(os.path.dirname(os.path.abspath(ctxpack.__file__))), OUT)
    except ctxpack.PackError as e: print("PACK FAILED:", e); sys.exit(1)
    print(json.dumps(m, indent=2, default=str)); sys.exit(0 if m["scan_ok"] else 2)
elif cmd == "check-draft":   # check-draft --packets FILE --id LEAD_ID --platform P --text TEXT_FILE  (stateless; exit 1 + problems if the exact text fails). No model.
    from . import grounding, roles
    roles.MAX_WORDS = 0
    from .models import Evidence
    arg = lambda k: sys.argv[sys.argv.index(k) + 1]
    pk = next(p for p in json.load(open(arg("--packets"))) if p["id"] == arg("--id")); ev = Evidence(**pk["evidence"]); text = open(arg("--text")).read().strip(); plat = arg("--platform")
    probs = list(dict.fromkeys(grounding.check_claims(text, ev) + roles.semantic_checks("writer", {"text": text}, ev, plat=plat)))
    notes, extras, failed = [], [], []
    urls = [sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == "--extra-source"]
    if urls:
        from . import sources
        for u in urls:
            try: extras.append(sources.fetch_text(u))
            except Exception as e: failed.append({"url": u, "reason": str(e)[:160]})
        for pr in list(probs):
            if pr.startswith("number not in source: "):
                n = pr.split(": ", 1)[1]; hit = next((x for x in extras if re.search(rf"(?<![0-9.]){re.escape(n)}(?![0-9])", x["text"])), None)
                if hit:
                    probs.remove(pr); notes.append(f"number {n} is not in the lead's source; found in supplementary {hit['domain']} (fetched by {hit['method']}); not an official-allowlist host, so this is a publisher claim")
    print(json.dumps({"ok": not probs, "problems": probs, "notes": notes, "supplementary": [{k: x[k] for k in ("url", "final_url", "method", "fetched_at")} for x in extras], "supplementary_failed": failed, "content_hash": review.content_hash(plat, text, None)}, ensure_ascii=False)); sys.exit(1 if probs else 0)
elif cmd == "ledger-record":   # ledger-record --ledger F --id LEAD_ID --title T --platform P --text FILE --approval-ref WAMID --url URL [--posted-at ISO]
    from . import ledger
    arg = lambda k, d=None: sys.argv[sys.argv.index(k) + 1] if k in sys.argv else d
    print(json.dumps(ledger.record_post(arg("--ledger"), lead_id=arg("--id"), title=arg("--title"), platform=arg("--platform"), text=open(arg("--text")).read().strip(), approval_ref=arg("--approval-ref"), posted_url=arg("--url"), posted_at=arg("--posted-at"))))
elif cmd == "results":   # results --ledger F --metrics metrics.csv : absent metrics are reported as not available, never zero
    from . import ledger
    print(json.dumps(ledger.results(sys.argv[sys.argv.index("--ledger") + 1], sys.argv[sys.argv.index("--metrics") + 1]), indent=1, ensure_ascii=False))
elif cmd == "recheck":
    from . import recheck; print(json.dumps(recheck.recheck(st), indent=1))
elif cmd == "init-token": print("token file:", review.init_token(OUT), "(read it yourself; do not give it to automation)")
elif cmd in ("approve", "reject"):
    tok = getpass.getpass("approval token: ")
    (review.approve(st, OUT, sys.argv[2], tok) if cmd == "approve" else review.reject(st, OUT, sys.argv[2], tok)); print(review.export_approved(st, OUT)); review.render(st, OUT)
elif cmd == "metrics": print(analytics.import_csv(st, open(sys.argv[2]).read())); print(json.dumps(analytics.report(st), indent=1))
