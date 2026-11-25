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
- Vendored playbooks are MIT with LICENSE files and pinned commits (playbooks/SOURCES.md). THIRD_PARTY.md now lists Crawl4AI (Apache-2.0), Repomix (MIT), Remotion (custom: individuals, up to 3 employees, non-profits), fonttools (MIT), Noto Kufi (OFL, not shipped). Postiz AGPL status in that file is from memory of its repo and was not re-verified here.
- Unchanged public-source facts rely on CISA KEV feed and BOD 26-04 pages listed in docs.

## Decision needed (not asked of the user yet)
Push or not; and which license. Nothing was pushed.
