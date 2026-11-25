"""Supplementary sources for a draft whose facts come from more than the lead's primary page (e.g. a vendor bulletin, the CVE record).
Fetch order: the SSRF-pinned plain fetch (net.get) first. Only when that gives too little text (JavaScript pages) and Crawl4AI is installed, fall back to Crawl4AI (Apache-2.0, real browser).
Crawl4AI does not pin the connection IP like net.get does, so it is limited: https only, port 443, the host must resolve to public addresses before AND after redirects, text capped.
Residual risk: sub-requests made by page scripts are not filtered. Do not point this at pages you do not already trust to be public advisories.
What comes back is supporting text, labelled with how it was fetched. It never becomes the lead's evidence and never lifts the 'official host' flag."""
import asyncio, datetime, os, urllib.parse
from . import net, grounding
MAX_CHARS = 30000
def _check_url(url):
    p = urllib.parse.urlparse(url)
    if p.scheme != "https" or not p.hostname or p.port not in (None, 443) or p.username or p.password: raise net.NetError("https, port 443 and no credentials only")
    net.resolve(p.hostname)
    return p
API_HOSTS = {"www.cve.org": ["cveawg.mitre.org"]}   # the cve.org page is a script app that loads its record from this API host; add other hosts only after observing the need
def chrome_args(url):
    """Verified by strace (docs/INTEGRATION_EVIDENCE.md): without these, Chrome's own network service contacts Google hosts at startup. With them the only non-local connect left is an IPv6 reachability probe.
    Only the validated target host can be resolved, so redirects and page sub-requests to other hosts fail (stricter than before, and some script-heavy pages may come back thin)."""
    host = urllib.parse.urlparse(url).hostname
    # IP pinning: each allowed host is resolved HERE, every address must be public (net.resolve), and Chrome is told to use exactly that address, so a later DNS answer cannot move it to a private/metadata address.
    maps = ", ".join(f"MAP {h} {net.resolve(h)}" for h in [host] + API_HOSTS.get(host, []))
    return ["--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-pings", "--disable-domain-reliability", "--disable-client-side-phishing-detection", "--disable-default-apps", "--no-first-run",
            "--disable-features=OptimizationHints,Translate,MediaRouter,DnsOverHttps,NetworkTimeServiceQuerying,AsyncDns", f"--host-resolver-rules={maps}, MAP * ~NOTFOUND"]
async def _crawl(url, timeout_ms):
    from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig
    bc = BrowserConfig(headless=True, chrome_channel=os.environ.get("ST_CHROME_CHANNEL", "chrome"), channel=os.environ.get("ST_CHROME_CHANNEL", "chrome"), verbose=False, extra_args=chrome_args(url))
    async with AsyncWebCrawler(config=bc) as c:
        r = await c.arun(url=url, config=CrawlerRunConfig(page_timeout=timeout_ms, wait_until="domcontentloaded", delay_before_return_html=2.0))
        if not r.success: raise grounding.GroundingError(f"crawl4ai failed: {(r.error_message or '')[:120]}")
        return r.url or url, str(r.markdown or "")
def fetch_text(url, getter=None, crawler=None, timeout_ms=45000):
    """Returns {url, final_url, domain, method, fetched_at, text}. Raises GroundingError or net.NetError with the reason."""
    _check_url(url); now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    try:
        ev = grounding.verify(url, **({"getter": getter} if getter else {}))
        return {"url": url, "final_url": ev.final_url, "domain": ev.domain, "method": "plain-http", "fetched_at": now, "text": (ev.title + " " + ev.excerpt)[:MAX_CHARS]}
    except grounding.GroundingError as e: plain_err = str(e)
    if "refused" in plain_err: raise
    try:
        if crawler: final, md = crawler(url, timeout_ms)
        else:
            try: import crawl4ai  # noqa
            except ImportError: raise grounding.GroundingError(f"{plain_err}; Crawl4AI not installed")
            final, md = asyncio.run(_crawl(url, timeout_ms))
    except net.NetError: raise
    except grounding.GroundingError: raise
    except Exception as e: raise grounding.GroundingError(f"{plain_err}; crawl4ai error: {type(e).__name__}")
    _check_url(final)
    if len(md.strip()) < 200: raise grounding.GroundingError("crawl4ai returned too little text")
    return {"url": url, "final_url": final, "domain": urllib.parse.urlparse(final).hostname, "method": "crawl4ai", "fetched_at": now, "text": md[:MAX_CHARS]}
