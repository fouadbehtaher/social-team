# What "verified" means here
- primary=true means ONLY: the item came from an allowlisted official host (CISA, AWS, GitHub Blog). It does NOT mean the publisher's claims are correct, complete or independently confirmed.
- Claim check = every number/version in a draft appears in the fetched source text and the source URL is included. It does not check meaning, tone or omissions.
- Human review is required before approval; approval is hash-bound; the pipeline never publishes.

# Acceptance (automated, 64 tests, no network, no Grok)
Grounding/freshness/SSRF/budget/approval-integrity/feeds (37) + six role contracts (7) + graph integration with MOCK LLM (5): strict schema per role, invented numbers blocked,
unsupported exploitation claims blocked, headline must be supported by source title/text, analyst cannot invent numbers or conclude on <5 posts,
prompt injection in source cannot add keys/approve, each role call reserves budget before the request.

# Not yet accepted (needs a real Grok key and the user's budget)
Real-model output quality, JSON compliance rate, retry rate, actual token cost per role, Arabic/English voice fit.

# Mock integration
GraphWithRoles tests run the REAL graph/store/gates with MockLLM (MOCK-TEST-ONLY). They prove wiring, gating, failure and budget-stop behaviour, not model quality.
