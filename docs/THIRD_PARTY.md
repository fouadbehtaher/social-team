# Third-party notes
Direct dependencies (requirements.txt): langgraph (MIT, LICENSE file read 2026-11-25) and Pillow (MIT-CMU per installed package metadata, version 12.3.0).
Installed dependency tree on the build machine (from package metadata, not from each LICENSE file, not a legal review):
MIT: langgraph and its langchain/langsmith packages, pydantic, anyio, h11, urllib3, others. BSD: httpx, idna, websockets, jsonpatch, xxhash, zstandard, uuid-utils.
Apache-2.0 or dual: requests, tenacity, packaging, ormsgpack, sniffio. PSF-2.0: typing-extensions.
MPL-2.0 (file-level copyleft, applies only if you modify those files): certifi, orjson (MPL-2.0 AND Apache-2.0 OR MIT).
Nothing is vendored or copied into this repo. Direct dependencies are pinned in requirements.txt; transitive ones are not locked.

Vendored (read-only, MIT, see playbooks/SOURCES.md): excerpts of coreyhaines31/marketingskills and pavelhov/social-media-skills, used only with ST_PLAYBOOKS=1.
Projects named in the original idea but NOT used as code here (see docs/COVERAGE.md): n8n (Sustainable Use License), Crawl4AI (Apache-2.0), Repomix (MIT), ComfyUI (GPL-3.0),
Remotion (custom license, company license needed above 3 employees), Postiz (AGPL-3.0), TryPost (AGPL-3.0), Metabase (AGPL + commercial), Langfuse (MIT, ee/ excepted).
Copying code from AGPL or GPL projects into this repo would change its license obligations. License read only, no security audit, none of these repos were cloned.

This repository has no LICENSE file yet. Until its owner picks one, the code is all rights reserved by default.

## Added in the private revision (verify each license before any business use)
- Crawl4AI 0.9.6, Apache-2.0 (optional, requirements-optional.txt). Pulls litellm, openai and patchright packages that this project does not use.
- Repomix 1.19.0, MIT (npm, used only by `context-pack`, not vendored).
- Remotion 4 (npm, `video/`): custom license, free for individuals, for-profit organisations up to 3 employees and non-profits (remotion.dev/docs/license/pricing). Not vendored. Check scope before business use.
- fonttools (MIT): font glyph coverage check for Arabic cards. Noto Kufi Arabic (OFL) is used from the system font directory, not shipped.
- Vendored playbooks (MIT): coreyhaines31/marketingskills and pavelhov/social-media-skills, with their LICENSE files, pinned in playbooks/SOURCES.md.
- n8n (Sustainable Use License), Postiz (AGPL-3.0: its repo LICENSE file was fetched in full on 2026-11-25 (34 KB; start, end and size checked as the standard AGPL v3 text, not read line by line); no other terms checked), TryPost, Metabase (AGPL), Langfuse, ComfyUI (GPL): only talked to over HTTP or exported to, never bundled.
