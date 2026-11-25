# Roadmap
Done: feeds, grounding, SSRF-safe fetch, budget ledger, six role prompts with schema and claim checks, local review page, hash-bound approval token, per-role checkpoints, strict stage-by-stage mode, offline tests.
Next, in order:
1. Get one real item through strategist, writer, designer and scheduler and read the output. The last live strategist attempt timed out; the cause is unknown (upstream slowness is a guess). Needs a model route that answers reliably.
2. Measure retry rate and schema failure rate on a real model; adjust prompts or validators from the logged failures.
3. Pin transitive dependencies (a lock file); add CI that runs the offline tests.
4. Add a publishing adapter per platform behind the approval gate. None exists.
5. Optional, only if wanted: Postiz or n8n as a scheduler (check AGPL / Sustainable Use terms first), Metabase or Langfuse for dashboards and traces.
Not claimed: that all twelve projects from the original idea are integrated. Only LangGraph is used.
