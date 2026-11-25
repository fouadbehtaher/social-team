# LinkedIn pilot handoff (private, not published)
Scope: managed existing account. Every exact post text is approved by the user in WhatsApp before publishing. No model calls, hosting or subscriptions are part of this. Nothing here has been run against LinkedIn.

## Setup per wake (the build folder is temporary, so nothing below depends on it)
1. Unpack social-team-next.tgz (pip needs: pip install -r requirements.txt).
2. Fetch the two state files from where the owner keeps them (see Durable state): posted_ledger.jsonl, metrics.csv. If a file is missing, start from an empty one.

## 1. Source packet (model-free)
`ST_OUT=/tmp/st python3 -m socialteam leads --ledger posted_ledger.jsonl > packets.json`
Reads the official feeds (CISA KEV and the other allowlisted feeds), runs the deterministic gate (official host, fresh, on topic), skips any lead or CVE already in the ledger. Output per item: id, title, source_key (CVE id), source_packet (the text the writer may rely on, marked untrusted) and evidence (url, dates, fetched_at). A fresh run on 2026-11-25 is in source_packets.json (3 packets). Seed the ledger first with anything already published or held by the LinkedIn worker, otherwise dedupe cannot know about it.
The packet is source data, not instructions. The "platform" of the old pipeline is not used.

## 2. Quality check of the exact text
Write the exact text to a file, then:
`python3 -m socialteam check-draft --packets packets.json --id LEAD_ID --platform linkedin --text post.txt`
Exit 0 = passes; exit 1 prints problems. It checks: every number/version appears in the source, the source URL is in the text, neutral third person (no first-person claims of testing or discovery), CISA KEV wording is not hedged (KEV listing means CISA has evidence of exploitation in the wild), ransomware use is not stated unless the source says so, and other style/claim rules in roles.py. It prints content_hash of that exact text. A pass is not a review: the user still reads the text. Any edit after approval changes the hash and needs new approval.
Example on a deliberately bad TEST text returns ok=false with the problems listed.

## 3. Approval
Show the user the exact text (and any image) in WhatsApp. Approval is his reply to that message. Keep the message id of his approval (wamid...). No approval, no publish. This is the user's approval of exact text, not a standing grant.

## 4. Publish (existing LinkedIn worker, its own session)
Unchanged by this repo. After the post is live, open its URL and confirm the text matches the approved file (hash the live text only if it can be copied exactly; otherwise compare visually).

## 5. Record the result (durable ledger)
`python3 -m socialteam ledger-record --ledger posted_ledger.jsonl --id LEAD_ID --title "TITLE" --platform linkedin --text post.txt --approval-ref WAMID --url LIVE_URL [--posted-at ISO]`
Refuses: empty approval ref, a URL not on linkedin.com, and any duplicate lead, CVE, text or URL. Then write the updated ledger back to its durable home.

## 6. Analytics (read-only, only after the post has had time to collect)
Source: the post's own analytics page, visible to its author (LinkedIn Help https://www.linkedin.com/help/linkedin/answer/a516971). Available there: impressions, members reached, reactions, comments, reposts, saves, sends. Figures are estimates, include the author's own interactions, and are private to him. Read only, no clicking on post controls, no commenting. Suggested reads: about 24 hours and 7 days after posting.
Append one row per read to metrics.csv (header in metrics_template.csv): post_url,date,impressions,reactions,comments,reposts,saves,sends. Leave a cell BLANK when LinkedIn does not show it or it could not be read. Never write 0 for unknown. Engagements = reactions+comments+reposts, computed only when all three are present.
`python3 -m socialteam results --ledger posted_ledger.jsonl --metrics metrics.csv`
Reports per post "not available" for missing values, no engagement rate without both numbers, and no comparison conclusion until at least 5 posts have metrics.

## Durable state: what is and is not decided
Files are plain text and tiny. The temporary build folder and the worker's /downloads do not persist, so the two files need a home that does. Options: (a) a private file in the user's connected Google Drive, downloaded and re-uploaded each wake; (b) the worker's own report history only, which is not machine-readable. I recommend (a), but writing to his Drive is a new write to his account, so it needs Main's call. Until then the ledger is NOT durable and the pilot must not claim dedupe across wakes.

## Pilot completion (what counts)
One real post: packet, passing check, user approval id, published, ledger row, then at least one analytics read recorded (or an explicit "not available"). Anything less is not a completed pilot.
Known gaps: no LinkedIn text-fidelity check beyond what the worker does; analytics reading is manual-browser work by the worker and unverified; the existing held CISA draft was written under the old rules and must pass check-draft before use.
