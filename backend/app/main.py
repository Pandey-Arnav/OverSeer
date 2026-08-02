import asyncio
import os
import uuid
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from . import ai_engine, db, decision, rule_engine
from .models import RawEvent, Verdict
from .normalize import normalize
from .state import store

AI_DEBOUNCE_SECONDS = float(os.getenv("SENTINEL_AI_DEBOUNCE_SECONDS", "0.8"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="Sentinel Backend", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pending debounced AI-analysis tasks, keyed by (session_id, tab_id) — a new
# event for the same tab cancels and reschedules rather than stacking calls.
_debounce_tasks: dict[tuple[str, int], asyncio.Task] = {}


def _schedule_ai_pass(session_id: str, tab_id: int, websocket: WebSocket) -> None:
    key = (session_id, tab_id)
    existing = _debounce_tasks.get(key)
    if existing and not existing.done():
        existing.cancel()

    async def _run():
        try:
            await asyncio.sleep(AI_DEBOUNCE_SECONDS)
        except asyncio.CancelledError:
            return

        state = store.get(session_id, tab_id)
        if state is None:
            return

        rule_findings = rule_engine.evaluate(state)
        rule_score = rule_engine.combined_score(rule_findings)
        ai_finding = await asyncio.to_thread(ai_engine.analyze, state.url, state, rule_findings)
        verdict = decision.ai_enhanced(tab_id, state.url, rule_findings, rule_score, ai_finding)

        db.insert_verdict(session_id, verdict)
        try:
            await websocket.send_json({"type": "verdict", **verdict.model_dump()})
        except Exception:
            pass  # socket likely closed; nothing to do

    _debounce_tasks[key] = asyncio.create_task(_run())


@app.websocket("/ws")
async def ws_events(websocket: WebSocket):
    session_id = websocket.query_params.get("session_id") or str(uuid.uuid4())
    await websocket.accept()
    await websocket.send_json({"type": "hello", "session_id": session_id})

    try:
        while True:
            payload = await websocket.receive_json()
            try:
                raw = RawEvent.model_validate(payload)
            except ValidationError as e:
                await websocket.send_json({"type": "error", "detail": str(e)})
                continue

            normalized = normalize(raw)
            state = store.record(session_id, raw.tab_id, raw.url, normalized)

            rule_findings = rule_engine.evaluate(state)
            rule_score = rule_engine.combined_score(rule_findings)
            verdict: Verdict = decision.rules_only(raw.tab_id, raw.url, rule_findings, rule_score)

            await websocket.send_json({"type": "verdict", **verdict.model_dump()})
            _schedule_ai_pass(session_id, raw.tab_id, websocket)
    except WebSocketDisconnect:
        pass


@app.get("/verdicts")
async def list_verdicts(session_id: str | None = None, limit: int = 100):
    return db.list_verdicts(session_id=session_id, limit=limit)


@app.get("/health")
async def health():
    return {"status": "ok"}
