"""Decision Engine — combines rule-engine and AI-engine findings into one
verdict. Transparent fixed formula, same philosophy as the rule engine:
explainability over black-box scoring.

  - Rules-only stage (before the AI debounce fires): verdict is just the
    rule engine's combined score.
  - AI-enhanced stage: take the max of the rule score and the AI score.
    A confident AI read of malicious intent should be able to escalate a
    verdict even if no individual rule tripped, but a strong rule hit
    should never be diluted by a wishy-washy AI read either.
"""
from .models import AIFinding, RuleFinding, Verdict

BLOCK_THRESHOLD = 70
WARN_THRESHOLD = 35


def _verdict_for_score(score: int) -> str:
    if score >= BLOCK_THRESHOLD:
        return "block"
    if score >= WARN_THRESHOLD:
        return "warn"
    return "allow"


def rules_only(tab_id: int, url: str, rule_findings: list[RuleFinding], rule_score: int) -> Verdict:
    return Verdict(
        tab_id=tab_id,
        url=url,
        risk_score=rule_score,
        verdict=_verdict_for_score(rule_score),
        rule_findings=rule_findings,
        ai=AIFinding(available=False),
        stage="rules_only",
    )


def ai_enhanced(
    tab_id: int,
    url: str,
    rule_findings: list[RuleFinding],
    rule_score: int,
    ai: AIFinding,
) -> Verdict:
    combined = max(rule_score, ai.risk_score) if ai.available else rule_score
    return Verdict(
        tab_id=tab_id,
        url=url,
        risk_score=combined,
        verdict=_verdict_for_score(combined),
        rule_findings=rule_findings,
        ai=ai,
        stage="ai_enhanced",
    )
