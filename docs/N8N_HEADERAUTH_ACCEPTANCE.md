# Header-auth workflow: one real n8n run (2026-11-25)
Source: report from the CommentFlow worker agent, relayed to the author's agent. The author's agent did not run it and has not seen the raw log. Treat as reported, not independently verified.
Workflow: `docs/n8n/handoff-workflow.headerauth.UNTESTED.json` (native Webhook node with Header Auth, Respond node, no Code node, no `$env`), published commit 5c03d00.
Environment: n8n 2.49.6 installed with pnpm, no Docker, no AWS. It needed Node 24.22.3 (Node 22 was refused by this version), a prebuilt sqlite module, about 600 MB observed. Credential: a fresh random test value generated for the test, not a user secret.
Observed (worker's raw output, saved by the author's agent as evidence-6182ffc8.txt, secret redacted; still a relay, not run by the author's agent):
- Runtime: Node v24.22.3, n8n 2.49.6. n8n 2.49.6 on Node 22 refuses to start (requires >=24).
- Setup: `n8n import:credentials` (random 32-hex test secret, header `X-Test-Auth`), `import:workflow`, `publish:workflow`, `n8n start`; then curl POST to `localhost:5678/webhook/social-team`.
- Correct header: HTTP 200, body `{"received":2,"note":"drafts only: nothing is published by this workflow"}`. The request body was the worker's OWN sample `{"items":[{"a":1},{"b":2}]}`, not a social-team handoff payload. `received` only counts the items in that sample.
- Wrong header: HTTP 403, body "Authorization data is wrong!".
- Missing header: HTTP 403, same body.
Run B (worker, relayed raw output evidence-handoff-beda7140.txt): the payload from the author's agent (n8n-real-handoff-payload.TESTFIXTURE.json, 1 synthetic TEST item, publish:false): correct header 200 {"received":1,...}, wrong header 403, missing header 403. `received` equals the item count of that payload.
Run A (same relay): the real client `python -m socialteam n8n-handoff` at commit 5c03d00 on a synthetic TEST item approved with a throwaway token in a sandbox DB (not the real gate): dry run {dry_run, items:1, bytes:626}; --send correct header {status:200}; wrong value {status:403, rejected:true}; different header name {status:403, rejected:true}. The worker used a stub for the langgraph import, so this proves the CLI handoff transport against n8n, not the full pipeline.
Not proven: HTTPS/Caddy, Docker, other n8n versions, any publish step (the workflow has none). Not tested: the `--separate` import form, Docker, Caddy, a public host, the deploy/ template.
Doc consequences (not yet applied publicly): the real handoff payload and client now passed, so the file name can drop "UNTESTED" and the notes about an unobserved bad-header status can change to the observed 403, in the next reviewed delta. Node note: "n8n 2.49.6 required Node >=24".
