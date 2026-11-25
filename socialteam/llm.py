"""Providers. Grok is the real writer; DemoExtractive exists only so the pipeline can be tested without a key and is labelled."""
import json, os, urllib.request, urllib.error, time
from .models import Draft

PRICES = {"grok-4.7": (2.00, 6.00), "grok-4.3": (1.25, 2.50)}  # USD per 1M tokens in/out, docs.x.ai/docs/models (checked 2026-11-25)

from .budget import Budget, BudgetExceeded
MAX_OUT = 600
FREE_MAX_OUT = 6000   # reasoning models spend output tokens on thinking; 600 can be consumed before any answer text

class GrokProvider:
    def __init__(self, budget: Budget, model="grok-4.7", key=None, post=None, max_prompt_chars=12000):
        self.key = key or os.environ.get("XAI_API_KEY"); self.model = model; self.budget = budget; self._post = post; self.max_chars = max_prompt_chars
        if not self.key: raise RuntimeError("XAI_API_KEY not set")
        if model not in PRICES: raise RuntimeError(f"no verified price for {model}; refusing")
        self.name = f"grok:{model}"
    def _call(self, body):
        if self._post: return self._post(body)
        req = urllib.request.Request("https://api.x.ai/v1/responses", data=json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"})
        return json.load(urllib.request.urlopen(req, timeout=90))
    def complete(self, system, user, role):
        """One role call: same reservation/settle/fail-closed rules as write()."""
        prompt = (system + "\n\n" + user)[: self.max_chars]; pi, po = PRICES[self.model]
        worst = ((len(prompt) * 1.25 + 200) * pi + MAX_OUT * po) / 1e6
        rid = self.budget.reserve(f"{self.name}:{role}", worst)
        r = self._call({"model": self.model, "input": prompt, "max_output_tokens": MAX_OUT})
        u = r.get("usage") or {}
        if "input_tokens" not in u or "output_tokens" not in u: raise RuntimeError("usage missing in response; reservation kept at worst case")
        cost = (u["input_tokens"] * pi + u["output_tokens"] * po) / 1e6; self.budget.settle(rid, cost)
        return r.get("output_text") or "".join(c.get("text", "") for o in r.get("output", []) for c in o.get("content", [])), cost

class DemoExtractive:
    """Not an LLM. Quotes the first source sentences verbatim. For tests and dry runs only."""
    name = "demo-extractive"
    def write(self, platform, brand, ev, angle) -> Draft:
        sents = [s.strip() for s in ev.excerpt.replace("\n", " ").split(". ") if len(s) > 40][:2]
        body = ". ".join(sents).rstrip(".") + "."
        return Draft(platform, f"[DEMO, not Grok] From {ev.domain}: \"{body}\"\n{ev.final_url}", self.name)


class OpenRouterFreeProvider:
    """Zero-spend route. NOT Grok: a different model must be chosen by the user. Refuses any model whose live public price is not exactly zero,
    and caps requests locally under OpenRouter's documented 50/day no-credit free-model limit."""
    def __init__(self, store_db_path, model, key=None, daily_requests=40, get_models=None, post=None, allow_retention=False, stream=False, idle_timeout=30, total_timeout=100, stream_open=None, first_event_timeout=30, pin=None):
        self.pin = pin;
        self.first_event_timeout = first_event_timeout; self.stream = stream; self.idle = idle_timeout; self.total = total_timeout; self._open = stream_open; self.last_meta = None
        self.key = key or os.environ.get("OPENROUTER_API_KEY"); self.model = model; self.name = f"openrouter-free:{model}"; self.cap = daily_requests; self._post = post; self.allow_retention = allow_retention
        if not self.key: raise RuntimeError("OPENROUTER_API_KEY not set")
        from .budget import Budget
        self.ledger = Budget(store_db_path, daily_requests, window=86400)     # reuse the atomic ledger: 1 unit = 1 request
        data = (get_models or self._models)()
        m = next((x for x in data if x["id"] == model), None)
        if not m: raise RuntimeError(f"{model} not in OpenRouter model list")
        om = (m.get("architecture") or {}).get("output_modalities")
        if om is not None and om != ["text"]: raise RuntimeError(f"{model} outputs {om}, not text only; refusing")
        pr = m.get("pricing", {})
        if any(float(pr.get(k, "1") or 0) != 0 for k in ("prompt", "completion", "request", "image", "web_search", "internal_reasoning", "input_cache_read") if k in pr) or "prompt" not in pr:
            raise RuntimeError(f"{model} is not free at list price; refusing")
    @staticmethod
    def _models():
        return json.load(urllib.request.urlopen("https://openrouter.ai/api/v1/models", timeout=30))["data"]
    def _stream_call(self, body):
        """SSE per OpenRouter Responses streaming docs: `data: {json}` lines, `[DONE]` end, terminal response.completed / response.incomplete carries the full response + usage.
        Lines starting with ':' are keep-alive comments. Idle timeout per read plus an absolute deadline; the timeline is kept so a stall shows WHERE it stopped."""
        import time as _t
        t0 = _t.monotonic(); tl = {"first_byte_s": None, "first_event": None, "events": {}, "keepalive_comments": 0, "deltas_chars": 0, "last_event_s": None}
        def fail(why): raise RuntimeError(f"stream {why} after {round(_t.monotonic()-t0,1)}s: " + json.dumps(tl))
        body = dict(body, stream=True)
        req = urllib.request.Request("https://openrouter.ai/api/v1/responses", data=json.dumps(body).encode(), headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json", "Accept": "text/event-stream"})
        resp = None; final = None; text = []
        try:
            resp = (self._open or urllib.request.urlopen)(req, timeout=self.idle)
            for raw in resp:
                now = _t.monotonic() - t0
                if tl["first_byte_s"] is None: tl["first_byte_s"] = round(now, 2)
                if now > self.total: fail("total deadline exceeded")
                if tl["first_event"] is None and now > self.first_event_timeout: fail(f"no model output event within {self.first_event_timeout}s (route stalled)")
                line = raw.decode("utf-8", "replace").strip()
                if not line: continue
                if line.startswith(":"): tl["keepalive_comments"] += 1; continue
                if not line.startswith("data:"): continue
                d = line[5:].strip()
                if d == "[DONE]": break
                try: ev = json.loads(d)
                except ValueError: tl["events"]["unparsable"] = tl["events"].get("unparsable", 0) + 1; continue
                t = ev.get("type") or ("error" if "error" in ev else "?")
                if tl["first_event"] is None: tl["first_event"] = t
                tl["events"][t] = tl["events"].get(t, 0) + 1; tl["last_event_s"] = round(now, 2)
                if t == "response.output_text.delta": text.append(ev.get("delta") or ""); tl["deltas_chars"] += len(ev.get("delta") or "")
                if t in ("response.completed", "response.incomplete", "response.failed"): final = ev.get("response") or {}
                if t == "error": fail("error event: " + json.dumps(ev.get("error"))[:300])
        except urllib.error.HTTPError as e:
            try: b = " ".join(e.read(600).decode("utf-8", "replace").split())[:400]
            except Exception: b = ""
            fail(f"HTTP Error {e.code}: {b}")
        except (TimeoutError, OSError) as e:
            fail("idle/read error " + type(e).__name__)
        finally:
            if resp is not None: resp.close()
        self.stream_timeline = dict(tl, total_s=round(_t.monotonic() - t0, 1))
        if final is None: fail("ended without a terminal response event")
        if not (final.get("output_text") or any(o.get("type") == "message" for o in final.get("output", []))) and text:
            final = dict(final, output_text="".join(text))
        return final
    def complete(self, system, user, role):
        rid = self.ledger.reserve(self.name, 1)             # before the request; stays held on any error (fail closed)
        body = {"model": self.model, "input": (system + "\n\n" + user)[:12000], "max_output_tokens": FREE_MAX_OUT, "reasoning": {"effort": "low"}}
        if self.pin: body["provider"] = {"only": [self.pin], "allow_fallbacks": False, **({} if self.allow_retention else {"data_collection": "deny"})}   # exactly this provider, never a silent other one
        elif not self.allow_retention: body["provider"] = {"data_collection": "deny"}   # per-request: only providers that do not store/collect data; no endpoint => request fails closed
        if self.stream and not self._post: r = self._stream_call(body)
        elif self._post: r = self._post(body)
        else:
            req = urllib.request.Request("https://openrouter.ai/api/v1/responses", data=json.dumps(body).encode(), headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"})
            r = json.load(urllib.request.urlopen(req, timeout=90))
        self.ledger.settle(rid, 1)
        u = r.get("usage") or {}
        if u.get("cost") not in (None, 0, 0.0): raise RuntimeError(f"unexpected nonzero cost reported: {u.get('cost')}")   # halt loudly if a charge ever appears
        text = r.get("output_text") or "".join(c.get("text", "") for o in r.get("output", []) if o.get("type") == "message" for c in o.get("content", []))
        self.last_meta = {"status": r.get("status"), "incomplete": r.get("incomplete_details"), "error": r.get("error"), "output_types": [o.get("type") for o in r.get("output", [])],
                          "usage": {k: u.get(k) for k in ("input_tokens", "output_tokens", "total_tokens")}, "reasoning_tokens": (u.get("output_tokens_details") or {}).get("reasoning_tokens"), "text_chars": len(text), "stream": getattr(self, "stream_timeline", None) if self.stream else None}
        if r.get("status") not in (None, "completed") or not text.strip():
            raise RuntimeError("provider returned no usable text: " + json.dumps(self.last_meta))   # truncated/empty is a provider-limit problem, not a validation one
        return text, 0.0


class RouteError(RuntimeError):
    """Transport-level failure of one route (stall, timeout, HTTP 429/5xx, no output). Safe to fall through to the next route. Validation rejections are NOT RouteErrors."""

def is_route_failure(e):
    t = str(e)
    if isinstance(e, urllib.error.HTTPError): return e.code in (408, 429) or e.code >= 500
    if "HTTP Error " in t: return any(f"HTTP Error {c}" in t for c in ("408", "429", "500", "502", "503", "504"))   # 4xx other than 408/429 is OUR request or config: falling through would only repeat it
    return isinstance(e, (TimeoutError, OSError)) or any(k in t for k in ("route stalled", "total deadline", "idle/read error", "without a terminal", "no usable text"))

class RoutedFreeProvider:
    """Ordered list of zero-price routes. Each attempt reserves one request in the shared ledger first (an unanswered request stays counted).
    Falls to the next route only on a transport-level failure, never on a validation rejection, and never loops: at most one attempt per route per call.
    Every attempt is kept in `attempts` and `name` always names the model that actually answered, so provenance on drafts is true. If all routes fail it raises, and strict mode halts."""
    def __init__(self, providers, on_attempt=None):
        if not providers: raise RuntimeError("no routes configured")
        pins = [getattr(p, "pin", None) for p in providers]
        if len(providers) > 1 and (None in pins or len(set(pins)) != len(pins)): raise RuntimeError("every route in a fallback list must be pinned to a distinct provider (a throttled provider must not be retried under another model alias)")
        self.providers = providers; self.attempts = []; self.name = providers[0].name; self._on = on_attempt
    def complete(self, system, user, role):
        last = None
        for p in self.providers:
            try:
                out = p.complete(system, user, role); self.name = p.name
                self._note(role, p.name, "ok", ""); return out
            except Exception as e:
                self._note(role, p.name, "route_failure" if is_route_failure(e) else "rejected", str(e)[:300])
                if not is_route_failure(e): raise
                last = e
        raise RouteError(f"all {len(self.providers)} route(s) failed for {role}: {str(last)[:300]}")
    def _note(self, role, name, result, err):
        self.attempts.append({"role": role, "route": name, "result": result, "error": err})
        if self._on: self._on(role, name, result, err)


def endpoint_slug(model, get=None):
    """Provider slug of the single live endpoint for a model, from OpenRouter's endpoints metadata (tag prefix). Refuses models that do not have exactly one endpoint."""
    d = (get or (lambda m: json.load(urllib.request.urlopen(f"https://openrouter.ai/api/v1/models/{m}/endpoints", timeout=20))["data"]))(model)
    eps = d["endpoints"]
    if len(eps) != 1: raise RuntimeError(f"{model} has {len(eps)} endpoints; refusing to guess the provider")
    return eps[0]["tag"].split("/")[0]
