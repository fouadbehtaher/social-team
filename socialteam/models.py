from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional, List
import hashlib

PLATFORMS = ("linkedin", "medium", "tiktok", "x")
# state machine: LEAD -> VERIFIED | REJECTED_LEAD ; VERIFIED -> DRAFTED -> PENDING_REVIEW -> APPROVED | REJECTED
TRANSITIONS = {
    "LEAD": {"VERIFIED", "REJECTED_LEAD"},
    "VERIFIED": {"DRAFTED"},
    "DRAFTED": {"PENDING_REVIEW", "DRAFT_FAILED", "VERIFIED"},   # DRAFTED/PENDING_REVIEW -> VERIFIED only via `recheck`, when saved output fails newer checks
    "DRAFT_FAILED": {"DRAFTED"},
    "PENDING_REVIEW": {"APPROVED", "REJECTED", "VERIFIED"},
}

def key(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16]

@dataclass
class Evidence:
    url: str
    final_url: str
    domain: str
    title: str
    published: Optional[str]
    excerpt: str            # text the writer may rely on
    fetched_at: str
    http_status: int
    updated: Optional[str] = None      # page/feed 'updated' date if different from first publication
    source_kind: str = "web"
    primary: bool = False              # computed from host allowlist (feeds.is_primary)

@dataclass
class Draft:
    platform: str
    text: str
    provider: str           # "grok:<model>" or "demo-extractive"
    cost_usd: float = 0.0
    problems: List[str] = field(default_factory=list)

def to_dict(o): return asdict(o)
