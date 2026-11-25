# social-team

A local, review-first content pipeline for security-focused social posts. It is a LangGraph graph with six role steps behind one model interface:
trend scout, strategist, writer, designer, scheduler, analyst.

**It never publishes.** It drafts, checks claims against fetched sources, renders an image card, and queues items in a local HTML review page.
A human approves each item with a local token. Approval is bound to a content hash.

## Status (read this first)
The checks below are heuristics: every number and the source URL in a draft must appear in the fetched source text, and a few claim patterns are blocked. They do not verify that a statement is true or complete. A human must review every item.

Tested: grounding, freshness and SSRF guards, budget ledger, approval gate, role schema checks, graph wiring with a mock model (64 offline tests).
Run live on public feeds with a free OpenRouter model: partial. Trend-scout output was produced for 3 real CISA KEV items; the strategist, writer and later stages
have NOT yet produced reviewed live output. Draft quality is unproven.
Not built: publishing to any platform. This project has no platform publishing integrations; drafts are for a human to post. The paid Grok provider path has not been run (it needs prepaid xAI credits).
"Primary source" in this code means only "from an allowlisted official host". It does not mean the publisher's claims are verified.

## What the model is asked to do (traced from `socialteam/pipeline.py`)
One model, six separate prompts. These are not six autonomous agents.
| Step | Model call? | Per item | Notes |
|---|---|---|---|
| scout | no | 0 | feed parsing (CISA KEV, AWS RSS, GitHub Blog RSS) |
| ground | trend_scout: yes | 1 | fetch, allowlist, freshness are deterministic; the model only rates relevance |
| strategist | yes | 1 | plan for the platform |
| writer | yes | 1 | draft text; claim check is deterministic |
| designer | yes | 1 | headline and subline for the card; card is drawn locally with Pillow, no image model |
| scheduler | yes | 1 | proposes a slot text and risk note only. It cannot schedule or post |
| analyst | yes, only if metrics were imported | 0 or 1 per run | summary of imported metrics |
Each role gets up to 3 attempts (1 call plus 2 retries) when its output fails the schema or semantic checks. One item needs at least 5 model calls and at most 15. A 3-item run needs 15 to 45 calls.
Role results are saved per item, so a run that stops partway resumes without calling finished roles again. Failed attempts are logged locally (redacted, first 2000 chars) in the run's database. The `out*/` directories are git-ignored.

## Layout
- `socialteam/` code (feeds, grounding, net, roles, pipeline, review, design, budget, llm providers, analytics)
- `tests/` offline tests, no network
- `brand/brand.example.md` copy to `brand/brand.md` and edit; only the `Voice:` line is sent to free routes
- `docs/` acceptance notes

## Run
    python3 -m venv .venv && . .venv/bin/activate     # tested with Python 3.10
    pip install -r requirements.txt                   # direct dependencies pinned; transitive ones are not
    python -m unittest discover -s tests
    ST_OUT=out python -m socialteam run --mock          # mock model, wiring only
    ST_OUT=out python -m socialteam run                 # extractive, no model
    OPENROUTER_API_KEY=... ST_FREE_MODEL=<free model id> ST_FREE_REQUESTS=20 python -m socialteam run   # zero-price models only
    XAI_API_KEY=... ST_DAILY_CAP_USD=0.25 python -m socialteam run                                       # Grok, paid
    python -m socialteam init-token; python -m socialteam approve <id>

Free route sends `data_collection: deny` by default. `ST_FREE_ALLOW_RETENTION=1` allows endpoints that may train on inputs. Send only public text.
API keys are read from environment variables only and are never written by this code. Drafts, run events, fetched public source text, failed model responses and the review page are stored locally under `ST_OUT` (git-ignored). Secret redaction of failed responses is best effort (key-shaped strings and emails only). Treat `out*/` as private. Set `ST_BYLINE` for the card footer.

## Data sources and third-party notes
Feeds: CISA KEV JSON, AWS security bulletins RSS, GitHub Blog security RSS. See `docs/THIRD_PARTY.md` for licenses of the tools that inspired the design.
