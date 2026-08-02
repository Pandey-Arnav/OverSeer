"""Fast, transparent rule-based detectors.

These run synchronously on every event and don't wait on the AI engine —
the point is instant detection of obvious attack patterns, with the AI
engine adding deeper reasoning and explanation a moment later.
"""
from .models import RuleFinding
from .state import TabState, now

RAPID_REDIRECT_COUNT = 5
RAPID_REDIRECT_WINDOW = 2.0

POPUP_SPAM_COUNT = 2
POPUP_SPAM_WINDOW = 2.0

NOTIFICATION_AFTER_LOAD_SECONDS = 1.5


def _events_of_type(state: TabState, event_type: str, within_seconds: float | None = None):
    cutoff = now() - within_seconds if within_seconds is not None else None
    return [e for e in state.events if e.type == event_type and (cutoff is None or e.ts >= cutoff)]


def evaluate(state: TabState) -> list[RuleFinding]:
    findings: list[RuleFinding] = []

    redirects = _events_of_type(state, "redirect", RAPID_REDIRECT_WINDOW)
    if len(redirects) >= RAPID_REDIRECT_COUNT:
        findings.append(
            RuleFinding(
                rule="rapid_redirects",
                score=60,
                reason=f"{len(redirects)} redirects happened within {RAPID_REDIRECT_WINDOW:.0f} seconds.",
            )
        )

    popups = _events_of_type(state, "popup_open", POPUP_SPAM_WINDOW)
    if len(popups) >= POPUP_SPAM_COUNT:
        findings.append(
            RuleFinding(
                rule="popup_spam",
                score=45,
                reason=f"{len(popups)} popup windows were opened within {POPUP_SPAM_WINDOW:.0f} seconds.",
            )
        )

    hidden_iframes = _events_of_type(state, "dom_mutation_iframe")
    hidden_iframes = [e for e in hidden_iframes if e.detail.get("hidden")]
    if hidden_iframes:
        findings.append(
            RuleFinding(
                rule="hidden_iframe",
                score=30,
                reason="A hidden (zero-size or off-screen) iframe was injected into the page.",
            )
        )
        if redirects:
            findings.append(
                RuleFinding(
                    rule="hidden_iframe_plus_redirect",
                    score=50,
                    reason="A hidden iframe appeared together with a page redirect — a common cloaking pattern.",
                )
            )

    notification_requests = _events_of_type(state, "notification_request")
    for e in notification_requests:
        if e.ts - state.page_load_ts <= NOTIFICATION_AFTER_LOAD_SECONDS:
            findings.append(
                RuleFinding(
                    rule="notification_immediately_after_load",
                    score=35,
                    reason="The page asked for notification permission almost immediately after loading, "
                    "before any user interaction.",
                )
            )
            break

    return findings


def combined_score(findings: list[RuleFinding]) -> int:
    return min(sum(f.score for f in findings), 100)
