# Integration evidence (2026-11-25). LIVE vs OFFLINE, stated plainly

## Reproducible cycle: `python3 scripts/cycle.py`
MODEL STEP IS MOCK. No model is called. The "writer" text is a fixed fixture labeled TEST. Real deterministic code runs everything else: queue, Arabic/English checks, approval token and content hash, tamper block, export, n8n dry-run, analytics export, ledger refusal, results. Offline, no network, no keys. It includes failure paths that must fail (wrong token, edit after approval, Arabic draft with first-person wording and an unsupported number, ledger without approval ref). Passing means those behaviours hold. It does not mean a live model, publisher or dashboard works.

## Crawl4AI (Apache-2.0): LIVE, verified network behaviour
- Used only by `check-draft --extra-source`, https port 443, public hosts.
- Telemetry check: strace of connect() calls over a local page. The Python process made no external connection. Chrome's own network service contacted Google hosts at start-up. Flags (`--disable-background-networking`, component update, sync, DoH off) did not remove it. `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE <target>` did: the only non-local connect left was an IPv6 reachability probe (unreachable here). Now built into `sources.chrome_args`.
- Side effect: page sub-requests to other hosts fail. cve.org needs its API host (cveawg.mitre.org), allowed by name in `API_HOSTS`. Re-traced live: only cve.org, its API host and the probe. IP pinning added after: each allowed host is resolved first, all addresses must be public, and Chrome is told to use exactly that IP (live-verified on cve.org).
- Live result: CVE record page fetched, numbers in the published Arabic Juniper post were found there. They are reported as NOTES (publisher claims from a non-allowlisted host), not as official-source passes. The post itself had human source review; the source-packet-only failure is a checker coverage gap, not evidence of a wrong post.
- Juniper support portal via Crawl4AI: one error, unreliable. Not used.

## Repomix (MIT): LIVE run
- `context-pack` on the whole brand+playbooks: Repomix 1.19.0 ran, the scanner flags the full playbook files (send wording, publish instruction, shell command). Keyword hits in benign style guides, not an attack finding. Scanner not weakened. Exit 2, marked unusable.
- `context-pack --excerpts`: packs only the capped excerpts that `playbooks.block` already hand-reviewed and hash-pinned. Verdict is per excerpt (same gate and same reviewed-hash allowance; one excerpt, writer-x, is the known reviewed false positive) plus a check that Repomix kept every excerpt verbatim. Repomix's own wrapper text is not scanned (stated in the manifest). Passes. A changed excerpt loses the allowance (test). The pack is not wired into a prompt; playbooks.block stays the only prompt path.

## Remotion: LIVE render
`video/` (Remotion 4 composition, React 19, system Chrome, concurrency 1). 2 s 9:16 1080x1920 h264 clip with Arabic RTL text rendered in 28 s on 1 CPU. TEST FIXTURE text only (banner in the clip). Proof frame: docs/test-clip-ar-frame.png; the clip is /downloads/test-clip-ar.mp4. Not wired to the approval gate yet: `video/render.sh OUT.mp4 headline text` takes text as arguments, so a caller must pass only an APPROVED export. LICENSE: remotion.dev/docs/license/pricing says free for individuals, for-profit organisations up to 3 employees, and non-profits. Whether this use qualifies depends on who the work serves; it is not assumed here.

## Wiring (offline-tested, no model/network)
- `video-export --id ID --out F.mp4`: renders only an item that is APPROVED and whose hash still matches (same `verified_items` gate as publishers). Refused when pending, rejected or edited after approval (tests + cycle). Positive path run once for real on a TEST fixture: /downloads/approved-test-ar.mp4, banner shown because the export marks test fixtures.
- `ST_PLAYBOOKS=pack`: playbook text reaches a prompt only through a Repomix pack whose manifest says scan_ok, whose file still matches the manifest sha256, and which contains the excerpt verbatim; otherwise nothing is added (tests: missing manifest, appended text, scan_ok false). `ST_PLAYBOOKS=1` (direct, reviewed excerpts) still works. The writer-x allowance is by exact body hash only. Pack and playbook text are labeled untrusted style reference and cannot change the deterministic checks. Never ran with a live model.

## n8n: NOT RUN in the first sandbox (measured); see the AWS trial section below for the real run

`npm i n8n` resolves and caches about 1.5 GB of tarballs, then the process is SIGKILLed (exit 137, ~40 s) during install on this 1 CPU / 2 GB sandbox, also with --max-old-space-size=1100, --omit=optional, --ignore-scripts, --maxsockets=4. The earlier 2-minute tool limit also applies, and background jobs are terminated. A partial tree also breaks the next attempt (ENOTEMPTY). Cause is most likely memory. n8n was not run. `n8n-handoff` is verified as dry run and by API-mock tests only: not an integration.

## Not attempted in either environment
Postiz, TryPost, Langfuse, ComfyUI. See COVERAGE.md.

## Arabic review
Checker (digits, diacritics, first-person, KEV hedges), RTL review page, Arabic card render. Screenshot docs/review-test-ar.png (TEST fixture). A human who reads Arabic still reviews and approves every post.

## AWS trial (2026-11-25, one t3.large in us-east-1, about 31 minutes, then terminated). MOCK model, TEST fixtures only
Real results on the instance, from logs seen during the run. The logs and the n8n/Metabase state were NOT preserved (the instance and its disk were deleted); only the MP4 and a frame were copied out. Nothing here is reproducible from stored artifacts, only by re-running.
- 127 unit tests OK; `scripts/cycle.py` all steps PASS (after installing libraqm; the first run failed there and the Arabic-shaping guard refused to draw, as designed).
- Remotion: an APPROVED TEST item rendered to a 2 s 1080x1920 h264 MP4 with Chrome 158 (about 100 s). Remotion warned that it wants glibc 2.35 and the instance had 2.34; the render still completed.
- Metabase OSS (Java 21, 2 GB heap, 127.0.0.1 only): attached analytics.db through its native SQLite connector, synced 6 tables, ran native SQL through the API (funnel returned APPROVED=1). Test data only. No dashboard was built or inspected visually.
- n8n 2.35.7 (needs Node >= 22): header-checked webhook workflow. `n8n-handoff --send` with the right header: HTTP 200, execution recorded as success. Wrong header and no header: HTTP 500 (execution error). 500 is not a proper 401/403: that was a flaw of the test workflow.
- Not run: Postiz, TryPost, Langfuse, ComfyUI, any live model call, any real post or metric.
### Offline fixes made after the trial (NOT verified on AWS or on n8n)
- `send_n8n` now returns `{status, ok: false, rejected: true|false}` for an HTTP error instead of a traceback (unit tested with a faked transport).
- `docs/n8n/handoff-workflow.UNTESTED.json`: a workflow that answers 401 through a Respond-to-Webhook node. It has never been imported into n8n; node parameters may need adjusting.
