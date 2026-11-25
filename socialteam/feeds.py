"""Official primary-source feeds. No scraping around blocks: a 403 is a refusal and is logged, not circumvented.
PRIMARY is an allowlist of exact hosts per source; 'primary' on evidence is computed from it, never from a label."""
import json, re, html, datetime, email.utils, xml.etree.ElementTree as ET
from . import net

UA = "socialteam-research/0.2"
SOURCES = {
    "cisa-kev": {"feed": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "hosts": {"www.cisa.gov"}, "page": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
    "aws-bulletins": {"feed": "https://aws.amazon.com/security/security-bulletins/rss/feed/", "hosts": {"aws.amazon.com"}},
    "github-blog-security": {"feed": "https://github.blog/security/feed/", "hosts": {"github.blog"}},
}
def is_primary(source, final_url):
    import urllib.parse; h = urllib.parse.urlparse(final_url).hostname
    return bool(h) and h in SOURCES.get(source, {}).get("hosts", set())
def _date(s):
    try: return email.utils.parsedate_to_datetime(s).date().isoformat()
    except Exception: return None
def parse_kev(text, today, days=14, limit=10):
    d = json.loads(text); out = []
    cutoff = (today - datetime.timedelta(days=days)).isoformat()
    for v in sorted(d["vulnerabilities"], key=lambda x: x["dateAdded"], reverse=True):
        if v["dateAdded"] < cutoff or len(out) >= limit: break
        summary = f"{v['vulnerabilityName']}. {v['shortDescription']} Vendor/product: {v['vendorProject']} {v['product']}. Required action: {v['requiredAction']}"
        out.append({"id": ("cisa-kev", v["cveID"]), "source": "cisa-kev", "title": f"{v['cveID']}: {v['vulnerabilityName']} (added to CISA KEV {v['dateAdded']})",
                    "url": SOURCES["cisa-kev"]["page"], "published": v["dateAdded"], "updated": None, "summary": summary, "kev_catalog_version": d.get("catalogVersion")})
    return out
def parse_rss(text, source, limit=10):
    root = ET.fromstring(text); out = []
    for it in list(root.iter("item"))[:limit]:
        g = {c.tag.split("}")[-1]: (c.text or "") for c in it}
        if g.get("link") and g.get("title"):
            out.append({"id": (source, g["link"]), "source": source, "title": html.unescape(g["title"]).strip(), "url": g["link"], "published": _date(g.get("pubDate", "")), "updated": None,
                        "summary": re.sub(r"<[^>]+>", " ", html.unescape(g.get("description", ""))).strip()})
    return out
def collect(getter=None, today=None, log=lambda **k: None):
    getter = getter or (lambda u: net.get(u, max_bytes=5_000_000)); today = today or datetime.date.today(); leads = []
    for name, cfg in SOURCES.items():
        try:
            st, _, body = getter(cfg["feed"])
            if st != 200: log(feed=name, refused=st); continue        # respect denials (e.g. 403), do not work around
            leads += parse_kev(body, today) if name == "cisa-kev" else parse_rss(body, name)
        except Exception as e: log(feed=name, error=str(e))
    return leads
