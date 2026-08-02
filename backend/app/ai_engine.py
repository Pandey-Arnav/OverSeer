"""AI Risk Engine — summarizes the behavior graph and asks an LLM to
reason about intent, producing an explanation a human can actually read.

Runs debounced (see main.py) rather than on every single event, both to
control latency/cost and because a few hundred milliseconds of extra
context makes for a much better summary than reacting to one event at a
time.
"""
import json
import os

from openai import OpenAI, OpenAIError

from .models import AIFinding, RuleFinding
from .state import TabState

MODEL = os.getenv("OPENAI_MODEL", "gpt-5.5")

SCHEMA = {
    "type": "object",
    "properties": {
        "risk_score": {"type": "integer"},
        "confidence": {"type": "integer"},
        "explanation": {"type": "string"},
        "owasp_category": {"type": "string"},
        "suggested_mitigation": {"type": "string"},
    },
    "required": ["risk_score", "confidence", "explanation", "owasp_category", "suggested_mitigation"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = """You are a browser runtime security analyst. You are given a chronological \
sequence of runtime behaviors a website performed after loading (popups, redirects, hidden \
iframes, network requests, notification/clipboard permission requests, cookie access), plus \
any fast rule-engine findings already triggered.

Reason about the *intent* behind the sequence, not just individual events in isolation — \
the same event can be benign or malicious depending on what surrounds it. Return:
- risk_score: 0-100, how likely this behavior sequence is malicious.
- confidence: 0-100, how confident you are in that score given the available signal.
- explanation: 1-3 plain-English sentences a non-technical user could understand. Describe \
  the sequence of what happened, not jargon.
- owasp_category: the closest-fitting OWASP Top 10 (or OWASP Top 10 Client-Side) category. \
  If nothing fits well, say "N/A".
- suggested_mitigation: one concrete, short sentence on what the user or browser should do."""


def _client() -> OpenAI | None:
    if not os.getenv("OPENAI_API_KEY", "").strip():
        return None
    return OpenAI()


def _summarize_events(state: TabState) -> str:
    lines = []
    for e in state.events:
        rel = e.ts - state.page_load_ts
        detail_str = ", ".join(f"{k}={v}" for k, v in e.detail.items())
        lines.append(f"[t+{rel:.2f}s] {e.type}" + (f" ({detail_str})" if detail_str else ""))
    return "\n".join(lines) if lines else "(no events recorded yet)"


def analyze(url: str, state: TabState, rule_findings: list[RuleFinding]) -> AIFinding:
    client = _client()
    if client is None:
        return AIFinding(available=False)

    rules_summary = (
        "\n".join(f"- {f.rule}: {f.reason}" for f in rule_findings)
        if rule_findings
        else "(no rule-engine findings yet)"
    )

    user_content = (
        f"URL: {url}\n\n"
        f"Behavior sequence since page load:\n{_summarize_events(state)}\n\n"
        f"Rule-engine findings so far:\n{rules_summary}"
    )

    try:
        response = client.chat.completions.create(
            model=MODEL,
            max_tokens=500,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {"name": "risk_assessment", "schema": SCHEMA, "strict": True},
            },
        )
    except OpenAIError as e:
        print(f"[ai_engine] OpenAI call failed: {e}")
        return AIFinding(available=False)

    try:
        data = json.loads(response.choices[0].message.content)
    except (json.JSONDecodeError, IndexError, AttributeError) as e:
        print(f"[ai_engine] failed to parse response: {e}")
        return AIFinding(available=False)

    return AIFinding(
        available=True,
        risk_score=max(0, min(100, int(data.get("risk_score", 0)))),
        confidence=max(0, min(100, int(data.get("confidence", 0)))),
        explanation=data.get("explanation", ""),
        owasp_category=data.get("owasp_category", "N/A"),
        suggested_mitigation=data.get("suggested_mitigation", ""),
    )
