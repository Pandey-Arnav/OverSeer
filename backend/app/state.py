"""In-memory per-tab behavior state.

This is the "behavior graph" data (no visualization yet — that's dashboard
work for later): an ordered, bounded sequence of normalized events per tab,
scoped to the current page load. A fresh "page_load" event resets the
window so a new navigation doesn't inherit the previous page's history.
"""
import time
from collections import deque
from dataclasses import dataclass, field

from .models import NormalizedEvent

WINDOW_MAXLEN = 200


@dataclass
class TabState:
    url: str
    page_load_ts: float
    events: deque[NormalizedEvent] = field(default_factory=lambda: deque(maxlen=WINDOW_MAXLEN))


class BehaviorStore:
    def __init__(self) -> None:
        self._tabs: dict[tuple[str, int], TabState] = {}

    def _key(self, session_id: str, tab_id: int) -> tuple[str, int]:
        return (session_id, tab_id)

    def record(
        self, session_id: str, tab_id: int, url: str, event: NormalizedEvent
    ) -> TabState:
        key = self._key(session_id, tab_id)
        state = self._tabs.get(key)

        if event.type == "page_load" or state is None or state.url != url:
            state = TabState(url=url, page_load_ts=event.ts)
            self._tabs[key] = state

        state.events.append(event)
        return state

    def get(self, session_id: str, tab_id: int) -> TabState | None:
        return self._tabs.get(self._key(session_id, tab_id))

    def clear(self, session_id: str, tab_id: int) -> None:
        self._tabs.pop(self._key(session_id, tab_id), None)


store = BehaviorStore()


def now() -> float:
    return time.time()
