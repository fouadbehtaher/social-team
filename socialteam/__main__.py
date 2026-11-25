import sys, os, json, getpass
from .store import Store
from .budget import Budget
from . import pipeline, review, analytics, llm
OUT = os.environ.get("ST_OUT", "out"); os.makedirs(OUT, exist_ok=True); st = Store(f"{OUT}/team.db")
cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
if cmd == "run":
    brand = open("brand/brand.md" if os.path.exists("brand/brand.md") else "brand/brand.example.md").read()
    from .mock import MockLLM
    prov = MockLLM() if "--mock" in sys.argv else (llm.OpenRouterFreeProvider(f"{OUT}/team.db", os.environ["ST_FREE_MODEL"], daily_requests=int(os.environ.get("ST_FREE_REQUESTS", "20")), allow_retention=os.environ.get("ST_FREE_ALLOW_RETENTION") == "1") if os.environ.get("OPENROUTER_API_KEY") and os.environ.get("ST_FREE_MODEL") else llm.GrokProvider(Budget(f"{OUT}/team.db", float(os.environ.get("ST_DAILY_CAP_USD", "0.25")))) if os.environ.get("XAI_API_KEY") else llm.DemoExtractive())
    if prov.name.startswith("openrouter-free"): brand = next(l for l in brand.splitlines() if l.startswith("Voice:"))   # free route: send only a one-line style hint, no other brand/private text
    print("writer:", prov.name)
    r = pipeline.build(st, prov, OUT).invoke({"brand": brand}); print({k: len(v) for k, v in r.items() if isinstance(v, list)}); print(review.render(st, OUT))
elif cmd == "init-token": print("token file:", review.init_token(OUT), "(read it yourself; do not give it to automation)")
elif cmd in ("approve", "reject"):
    tok = getpass.getpass("approval token: ")
    (review.approve(st, OUT, sys.argv[2], tok) if cmd == "approve" else review.reject(st, OUT, sys.argv[2], tok)); print(review.export_approved(st, OUT)); review.render(st, OUT)
elif cmd == "metrics": print(analytics.import_csv(st, open(sys.argv[2]).read())); print(json.dumps(analytics.report(st), indent=1))
