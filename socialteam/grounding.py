"""Verifies a lead against its own page. HN headlines are leads only; nothing is drafted without fetched evidence."""
import re, time, urllib.parse, html, datetime
from . import net
from .models import Evidence

class GroundingError(Exception): pass

def fetch(url, tries=3, getter=None):
    getter = getter or net.get; last = None
    for i in range(tries):
        try: return getter(url)
        except net.NetError as e: raise GroundingError(f"refused: {e}")   # policy failures are not retried
        except Exception as e: last = e; time.sleep(0.5 * 2 ** i)
    raise GroundingError(f"fetch failed: {last}")

BOILER = re.compile(r"(min read|minutes? read|share:|subscribe|newsletter|cookie|all rights reserved|is a (long[- ]time )?(tech )?(writer|editor|journalist)|\bwrites? for\b|follow us|sign up|privacy policy)", re.I)
MAX_AGE_DAYS = 45
META = [r'property="article:published_time"\s+content="([^"]+)"', r'content="([^"]+)"\s+property="article:published_time"',
        r"""<time[^>]+datetime=["']([^"']+)["']""", r'name="date"\s+content="([^"]+)"', r'"datePublished"\s*:\s*"([^"]+)"']
def extract(url, status, final, body, now=None):
    t = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
    title = html.unescape(re.sub(r"\s+", " ", t.group(1))).strip() if t else ""
    published = next((m.group(1)[:10] for p in META if (m := re.search(p, body, re.I))), None)
    text = re.sub(r"<(script|style|nav|footer|header|aside|form)[^>]*>.*?</\1>", " ", body, flags=re.S | re.I)
    m = re.search(r"<(article|main)[^>]*>(.*?)</\1>", text, re.S | re.I)
    if m: text = m.group(2)
    paras = [re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", p))).strip() for p in re.findall(r"<p[^>]*>(.*?)</p>", text, re.S | re.I)]
    excerpt = " ".join(p for p in paras if len(p) > 60 and not BOILER.search(p))[:2500]
    if status != 200 or not title or len(excerpt) < 200:
        raise GroundingError(f"insufficient primary text (status={status}, title={bool(title)}, chars={len(excerpt)})")
    return Evidence(url, final, urllib.parse.urlparse(final).hostname or "", title, published, excerpt,
                    datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), status)

def verify(url, **kw):
    s, f, b = fetch(url, **kw); return extract(url, s, f, b)

NUM = re.compile(r"\b\d[\d.,]*\b")
def check_claims(draft_text, evidence):
    """Every number/version in the draft must appear in the evidence; no source = fail. Returns problems."""
    from . import lang
    draft_text = re.sub(r"(?<=[\u0600-\u06FF])(?=\d)|(?<=\d)(?=[\u0600-\u06FF])", " ", lang.normalize(draft_text)) if lang.is_arabic(draft_text) else draft_text   # Arabic-Indic digits and diacritics must not hide a number from the source check
    problems = []
    src = evidence.title + " " + evidence.excerpt + " " + (evidence.published or "")
    for n in NUM.findall(draft_text):
        n = n.rstrip(".,")
        if n and n not in src and n not in evidence.url: problems.append(f"number not in source: {n}")
    if evidence.url not in draft_text and evidence.final_url not in draft_text: problems.append("source URL missing")
    return problems

def freshness_problem(ev, today=None, max_age=MAX_AGE_DAYS, allow_undated=False):
    """Judges the NEWEST of published/updated, so an old advisory with a recent update stays eligible; both dates stay on the evidence."""
    today = today or datetime.date.today()
    ds = [d for d in (ev.published, ev.updated) if d]
    if not ds: return None if allow_undated else "no publication date on page"
    try: newest = max(datetime.date.fromisoformat(d) for d in ds)
    except ValueError: return "unparseable date"
    age = (today - newest).days
    return f"stale (newest date {newest}, {age} days old, limit {max_age})" if age > max_age else (f"future date {newest}" if age < -1 else None)

def from_feed(meta, fetched_at=None):
    """Evidence for feed-native sources (CISA KEV): the official record itself, no page scrape."""
    from . import feeds
    return Evidence(meta["url"], meta["url"], urllib.parse.urlparse(meta["url"]).hostname or "", meta["title"], meta["published"], meta["summary"][:2500],
                    fetched_at or datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), 200, meta.get("updated"), meta["source"], feeds.is_primary(meta["source"], meta["url"]))

def verify_feed_item(meta, getter=None):
    """Feed-listed page: fetch it, require final host to stay on the source's allowlist, keep feed dates if the page has none."""
    from . import feeds
    if meta["source"] == "cisa-kev": return from_feed(meta)
    s, f, b = fetch(meta["url"], getter=getter); ev = extract(meta["url"], s, f, b)
    if not feeds.is_primary(meta["source"], f): raise GroundingError(f"redirected off the official host: {ev.domain}")
    ev.source_kind, ev.primary = meta["source"], True
    fd = [d for d in (ev.published, meta.get("published")) if d]
    if fd:
        ev.published = min(fd)
        if max(fd) != min(fd): ev.updated = max(fd)    # two different dates: keep original and later one
    return ev
