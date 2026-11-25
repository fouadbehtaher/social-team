# Deploy template (UNTESTED)

Status: written from vendor docs, never run. Only the header-auth handoff itself was run once, on a local n8n 2.49.6 without Docker or Caddy (docs/N8N_HEADERAUTH_ACCEPTANCE.md). Nothing here was started on any server. No cost is implied.

What it sets up: n8n behind Caddy (HTTPS), only `/webhook/*` reachable, n8n itself not published, secrets in `.env` (mode 600).

Steps (a person or an agent with a console on the server):
1. Point a DNS name at the server. Ubuntu 22.04+ with Docker, 2 vCPU and 4 GB RAM or more (n8n plus Chrome are unproven under 4 GB).
2. `cp .env.example .env`, fill it, `chmod 600 .env`, then `docker compose up -d`.
3. In n8n create a **Header Auth** credential (a name such as `X-ST-Auth` and a random 24+ character value). Import `docs/n8n/handoff-workflow.headerauth.UNTESTED.json`, attach that credential to the Webhook node, activate.
4. On the machine that runs social-team set `N8N_WEBHOOK_URL=https://<host>/webhook/social-team` and `N8N_AUTH_HEADER='X-ST-Auth: <same value>'`, then `python -m socialteam preflight` and `python -m socialteam n8n-handoff` (dry run) before `--send`.

Known limits: the 401/403 behaviour of the native header-auth check was not observed (docs say the node can require Header auth; the exact status for a bad header is unverified). The review web page binds 127.0.0.1 only, so on a server use the chat to approve, or an SSH tunnel. Postiz, TryPost, Langfuse and ComfyUI are not in this template.

## Optional environment variables the code reads (documented so config does not drift)
- `ST_REVIEW_HOST` / `ST_REVIEW_PORT`: where `review-serve` binds. Loopback only; `preflight` FAILs on any other host.
- `ST_CHROME_CHANNEL`: browser channel passed to Crawl4AI (default `chrome`).
- `ST_REPOMIX`: path to the Repomix binary used by `context-pack` (otherwise found on PATH).
