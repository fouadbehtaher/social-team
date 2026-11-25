# Publication review: social-team private revision (NOT pushed)
Base: public HEAD 0dca2258 (2026-11-25 14:03Z). Candidate: social-team-next.tgz (see sha256 in the report). Diff: social-team-revision.diff.

## Change summary
- Modified: README, ROADMAP, brand example, ACCEPTANCE, THIRD_PARTY, __main__, design, feeds, grounding, llm, models, pipeline, review, roles, store, tests.
- New code: lang (Arabic checks), sources (extra-source fetch, Crawl4AI with host-pinned Chrome), ctxpack (Repomix), playbooks, publishers (Postiz/TryPost draft-only), exports (analytics, OTLP, n8n), ledger, recheck, review_server, fixture; scripts/cycle.py; video/ (Remotion); docs (COVERAGE, ACTIVATION, LINKEDIN_PILOT, INTEGRATION_EVIDENCE, proof images); vendored MIT playbooks with LICENSE files.
- 127 offline tests pass; cycle script passes with a MOCK model. Not proof of live readiness.

## Security check (local grep, 2026-11-25)
- No API keys, tokens or private keys found (patterns: sk-, xai-, ghp_, AKIA, PEM, Bearer, api_key=).
- No personal data: no email, phone, WhatsApp ids, real post URL or real packet ids in the repo. Test fixtures use synthetic ids and example.invalid. The pilot handoff files and ledger are NOT in the repo.
- Publishing paths are draft-only and dry-run by default; the approval token file is created at runtime with mode 0600 and is not in the repo.
- Crawl4AI fetch: Chrome now gets the validated public IP per allowed host (MAP host IP, everything else unresolvable), verified live on cve.org with TLS intact. Residual: no external audit.

## License / source check
- Repo has NO license file (GitHub reports none): without one, others have no right to reuse it. The owner chooses (e.g. MIT) before or with the push.
- Vendored playbooks are MIT with LICENSE files and pinned commits (playbooks/SOURCES.md). THIRD_PARTY.md now lists Crawl4AI (Apache-2.0), Repomix (MIT), Remotion (custom: individuals, up to 3 employees, non-profits), fonttools (MIT), Noto Kufi (OFL, not shipped). Postiz and TryPost: their repo LICENSE files (Postiz LICENSE, TryPost LICENSE.md on the main branch) were fetched in full on 2026-11-25; their start, end and size match the standard GNU AGPL v3 text (not read line by line); no other terms were checked.
- Unchanged public-source facts rely on CISA KEV feed and BOD 26-04 pages listed in docs.

## Status (2026-11-25)
Published once as commit 5ff7c9bc with an MIT LICENSE chosen by the owner. This file describes the state at that commit plus the follow-up delta below.
Follow-up delta (published as commit 5c03d00; later evidence in docs/N8N_HEADERAUTH_ACCEPTANCE.md): `python -m socialteam preflight` (config-only deploy check), `docs/n8n/handoff-workflow.headerauth.UNTESTED.json` (native Header auth, no Code node, no `$env`), `deploy/` (Docker + Caddy template, never run), 6 new unit tests (133 total), Postiz license wording updated after fetching its LICENSE file in full (start, end and size checked as standard AGPL v3; not read line by line).
AWS trial (single temporary instance, MOCK model, test fixtures, logs not kept): tests, Remotion MP4, Metabase SQLite connector and n8n webhook all ran once; n8n answered HTTP 500, not 401, on a wrong header with the old Code-node workflow. The new header-auth workflow has NOT been imported into n8n, so its rejection status is unobserved.
