"""MOCK-TEST-ONLY role model. Deterministic stand-in so the real graph can be exercised offline. It is NOT Grok and says nothing about real model quality."""
import json, re
class MockLLM:
    name = "MOCK-TEST-ONLY"
    def __init__(self, break_role=None, bad_output=None): self.calls = []; self.break_role = break_role; self.bad = bad_output
    def complete(self, system, user, role):
        self.calls.append(role)
        if role == self.break_role and self.bad is not None: return self.bad, 0.0
        body = re.search(r'<source[^>]*>\n(.*?)\n</source>', user, re.S); text = body.group(1) if body else ""
        title = text.split("\n")[0]; url = re.search(r'url="([^"]+)"', user); url = url.group(1) if url else ""
        sent = next((x for x in re.split(r"(?<=\.)\s", "\n".join(text.split("\n")[1:])) if len(x) > 30), "")[:200]
        out = {"trend_scout": {"relevance": 4, "reason": f"Mock: matches security niche ({title[:60]})", "audience_fit": "practitioner"},
               "strategist": {"angle": "Mock angle: practitioner takeaway", "key_points": [sent[:150] or title[:150], "Check your own exposure"], "do_not_say": []},
               "writer": {"text": f"[MOCK TEXT, not Grok] {title[:100]}. {sent}\n{url}"},
               "designer": {"headline": title[:80], "subline": "Mock design brief", "alt_text": "Card with source headline"},
               "scheduler": {"suggested_slot": "evening Cairo time", "risk_note": "Mock: verify vendor advisory before posting", "needs_human_check": ["source claims"]},
               "analyst": {"summary": "insufficient data", "insufficient_data": True}}[role]
        return json.dumps(out), 0.0
