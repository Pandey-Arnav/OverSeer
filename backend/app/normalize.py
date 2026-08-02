from .models import NormalizedEvent, RawEvent
from .state import now


def normalize(raw: RawEvent) -> NormalizedEvent:
    return NormalizedEvent(
        ts=raw.ts if raw.ts is not None else now(),
        type=raw.type,
        detail=raw.detail,
    )
