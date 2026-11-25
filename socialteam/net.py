"""SSRF-safe fetch: every hop (incl. redirects) resolved and validated; connection pinned to the validated IP (no re-resolution => no DNS rebinding); http(s) only; size cap."""
import socket, ssl, ipaddress, http.client, urllib.parse
class NetError(Exception): pass
def ip_ok(ip):
    ip = ipaddress.ip_address(ip)
    if getattr(ip, "ipv4_mapped", None): ip = ip.ipv4_mapped
    if getattr(ip, "sixtofour", None) and ip.sixtofour and not ip.sixtofour.is_global: return False
    return ip.is_global and not ip.is_multicast
def resolve(host, getaddrinfo=socket.getaddrinfo):
    try: infos = getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as e: raise NetError(f"dns: {e}")
    ips = [i[4][0] for i in infos]
    if not ips or not all(ip_ok(i) for i in ips): raise NetError(f"non-public address for {host}")
    return ips[0]
class _Pinned(http.client.HTTPSConnection):
    def __init__(self, host, ip, **kw): super().__init__(host, **kw); self._ip = ip
    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host)
class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, **kw): super().__init__(host, **kw); self._ip = ip
    def connect(self): self.sock = socket.create_connection((self._ip, self.port), self.timeout)
def get(url, max_redirects=4, max_bytes=600_000, timeout=20, getaddrinfo=socket.getaddrinfo, conn_factory=None):
    for _ in range(max_redirects + 1):
        p = urllib.parse.urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname: raise NetError("scheme/host not allowed")
        if p.port not in (None, 80, 443): raise NetError("port not allowed")
        ip = resolve(p.hostname, getaddrinfo)
        mk = conn_factory or (_Pinned if p.scheme == "https" else _PinnedHTTP)
        c = mk(p.hostname, ip, timeout=timeout)
        try:
            c.request("GET", (p.path or "/") + (f"?{p.query}" if p.query else ""), headers={"Host": p.hostname, "User-Agent": "socialteam-research/0.2", "Accept": "text/html"})
            r = c.getresponse()
            if r.status in (301, 302, 303, 307, 308):
                loc = r.getheader("Location");
                if not loc: raise NetError("redirect without location")
                url = urllib.parse.urljoin(url, loc); continue
            body = r.read(max_bytes).decode(r.headers.get_content_charset() or "utf-8", "replace")
            return r.status, url, body
        finally: c.close()
    raise NetError("too many redirects")
