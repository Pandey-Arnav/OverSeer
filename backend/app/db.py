import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .models import Verdict

DB_PATH = Path(os.getenv("SENTINEL_DB_PATH", "sentinel.db"))
if not DB_PATH.is_absolute():
    DB_PATH = Path(__file__).resolve().parent.parent / DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    session_id TEXT NOT NULL,
    tab_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    stage TEXT NOT NULL,
    rule_findings TEXT NOT NULL,
    ai_finding TEXT NOT NULL
);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.execute(SCHEMA)


def insert_verdict(session_id: str, verdict: Verdict) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO verdicts
               (timestamp, session_id, tab_id, url, risk_score, verdict, stage, rule_findings, ai_finding)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                session_id,
                verdict.tab_id,
                verdict.url,
                verdict.risk_score,
                verdict.verdict,
                verdict.stage,
                json.dumps([f.model_dump() for f in verdict.rule_findings]),
                json.dumps(verdict.ai.model_dump()),
            ),
        )
        return cur.lastrowid


def list_verdicts(session_id: str | None = None, limit: int = 100) -> list[dict]:
    with get_conn() as conn:
        if session_id:
            rows = conn.execute(
                "SELECT * FROM verdicts WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                (session_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM verdicts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["rule_findings"] = json.loads(d["rule_findings"])
            d["ai_finding"] = json.loads(d["ai_finding"])
            out.append(d)
        return out
