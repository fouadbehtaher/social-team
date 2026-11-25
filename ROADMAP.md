# Roadmap
Done: feeds, grounding, SSRF-safe fetch, budget ledger, six role prompts with schema and claim checks, local review page, hash-bound approval token, resume, offline tests.
Next, in order:
1. Run all roles on real model output and read the strategist, writer and designer results. This has not happened yet.
2. Measure retry rate and schema failure rate on a real model; adjust prompts or validators from the logged failures.
3. Pin transitive dependencies (a lock file); add CI that runs the offline tests.
4. Add a publishing adapter per platform behind the approval gate. None exists.
5. Optional, only if wanted: Postiz or n8n as a scheduler (check AGPL / Sustainable Use terms first), Metabase or Langfuse for dashboards and traces.
Not claimed: that all twelve projects from the original idea are integrated. Only LangGraph is used.
