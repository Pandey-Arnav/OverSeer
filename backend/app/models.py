from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

EventType = Literal[
    "page_load",
    "popup_open",
    "redirect",
    "fetch_request",
    "xhr_request",
    "dom_mutation_iframe",
    "notification_request",
    "cookie_access",
    "clipboard_write",
]


class RawEvent(BaseModel):
    """What the extension sends over the WebSocket for a single observed action."""

    tab_id: int
    url: str
    type: EventType
    detail: dict[str, Any] = Field(default_factory=dict)
    ts: Optional[float] = None
    """Client-side epoch seconds; server fills this in if omitted."""


class NormalizedEvent(BaseModel):
    ts: float
    type: EventType
    detail: dict[str, Any]


class RuleFinding(BaseModel):
    rule: str
    score: int
    reason: str


class AIFinding(BaseModel):
    available: bool
    risk_score: int = 0
    confidence: int = 0
    explanation: str = ""
    owasp_category: str = ""
    suggested_mitigation: str = ""


class Verdict(BaseModel):
    tab_id: int
    url: str
    risk_score: int
    verdict: Literal["allow", "warn", "block"]
    rule_findings: list[RuleFinding]
    ai: AIFinding
    stage: Literal["rules_only", "ai_enhanced"]
