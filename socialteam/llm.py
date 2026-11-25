"""Providers. Grok is the real writer; DemoExtractive exists only so the pipeline can be tested without a key and is labelled."""
import json, os, urllib.request, time
from .models import Draft

PRICES = {"grok-4.7": (2.00, 6.00), "grok-4.3": (1.25, 2.50)}  # USD per 1M tokens in/out, docs.x.ai/docs/models (checked 2026-11-25)

from .budget import Budget, BudgetExceeded
MAX_OUT = 600

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
    def __init__(self, store_db_path, model, key=None, daily_requests=40, get_models=None, post=None, allow_retention=False):
        self.key = key or os.environ.get("OPENROUTER_API_KEY"); self.model = model; self.name = f"openrouter-free:{model}"; self.cap = daily_requests; self._post = post; self.allow_retention = allow_retention
        if not self.key: raise RuntimeError("OPENROUTER_API_KEY not set")
        from .budget import Budget
        self.ledger = Budget(store_db_path, daily_requests, window=86400)     # reuse the atomic ledger: 1 unit = 1 request
        data = (get_models or self._models)()
        m = next((x for x in data if x["id"] == model), None)
        if not m: raise RuntimeError(f"{model} not in OpenRouter model list")
        pr = m.get("pricing", {})
        if any(float(pr.get(k, "1") or 0) != 0 for k in ("prompt", "completion", "request", "image", "web_search", "internal_reasoning", "input_cache_read") if k in pr) or "prompt" not in pr:
            raise RuntimeError(f"{model} is not free at list price; refusing")
    @staticmethod
    def _models():
        return json.load(urllib.request.urlopen("https://openrouter.ai/api/v1/models", timeout=30))["data"]
    def complete(self, system, user, role):
        rid = self.ledger.reserve(self.name, 1)             # before the request; stays held on any error (fail closed)
        body = {"model": self.model, "input": (system + "\n\n" + user)[:12000], "max_output_tokens": MAX_OUT}
        if not self.allow_retention: body["provider"] = {"data_collection": "deny"}   # per-request: only providers that do not store/collect data; no endpoint => request fails closed
        if self._post: r = self._post(body)
        else:
            req = urllib.request.Request("https://openrouter.ai/api/v1/responses", data=json.dumps(body).encode(), headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"})
            r = json.load(urllib.request.urlopen(req, timeout=90))
        self.ledger.settle(rid, 1)
        u = r.get("usage") or {}
        if u.get("cost") not in (None, 0, 0.0): raise RuntimeError(f"unexpected nonzero cost reported: {u.get('cost')}")   # halt loudly if a charge ever appears
        return r.get("output_text") or "".join(c.get("text", "") for o in r.get("output", []) for c in o.get("content", [])), 0.0
