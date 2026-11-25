# Third-party notes
Direct dependencies (requirements.txt): langgraph (MIT, LICENSE file read 2026-11-25) and Pillow (MIT-CMU per installed package metadata, version 12.3.0).
Installed dependency tree on the build machine (from package metadata, not from each LICENSE file, not a legal review):
MIT: langgraph and its langchain/langsmith packages, pydantic, anyio, h11, urllib3, others. BSD: httpx, idna, websockets, jsonpatch, xxhash, zstandard, uuid-utils.
Apache-2.0 or dual: requests, tenacity, packaging, ormsgpack, sniffio. PSF-2.0: typing-extensions.
MPL-2.0 (file-level copyleft, applies only if you modify those files): certifi, orjson (MPL-2.0 AND Apache-2.0 OR MIT).
Nothing is vendored or copied into this repo. Direct dependencies are pinned in requirements.txt; transitive ones are not locked.

Projects named in the original idea but NOT used here: n8n (Sustainable Use License), Crawl4AI (Apache-2.0), Repomix (MIT), ComfyUI (GPL-3.0),
Remotion (custom license, company license needed above 3 employees), Postiz (AGPL-3.0), TryPost (AGPL-3.0), Metabase (AGPL + commercial), Langfuse (MIT, ee/ excepted).
Copying code from AGPL or GPL projects into this repo would change its license obligations. License read only, no security audit, none of these repos were cloned.

This repository has no LICENSE file yet. Until its owner picks one, the code is all rights reserved by default.
