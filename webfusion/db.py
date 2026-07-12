"""SQLite-backed traffic history.

A new connection is opened per operation so the store is safe to use from both
the API thread and the proxy thread without a shared-connection lock.
"""
from __future__ import annotations

import json
import sqlite3
import time
from typing import Any, Optional

from . import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    REAL,
    method       TEXT,
    scheme       TEXT,
    host         TEXT,
    port         INTEGER,
    path         TEXT,
    url          TEXT,
    req_headers  TEXT,
    req_body     TEXT,
    status       INTEGER,
    resp_headers TEXT,
    resp_body    TEXT,
    resp_length  INTEGER,
    duration_ms  REAL,
    in_scope     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_flows_host ON flows(host);
"""


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init() -> None:
    with _conn() as conn:
        conn.executescript(_SCHEMA)


def insert_flow(rec: dict[str, Any]) -> int:
    cols = (
        "timestamp", "method", "scheme", "host", "port", "path", "url",
        "req_headers", "req_body", "status", "resp_headers", "resp_body",
        "resp_length", "duration_ms", "in_scope",
    )
    rec.setdefault("timestamp", time.time())
    values = [rec.get(c) for c in cols]
    placeholders = ",".join("?" for _ in cols)
    with _conn() as conn:
        cur = conn.execute(
            f"INSERT INTO flows ({','.join(cols)}) VALUES ({placeholders})", values
        )
        return int(cur.lastrowid)


def list_flows(
    limit: int = 200, offset: int = 0, host: Optional[str] = None
) -> list[dict[str, Any]]:
    q = (
        "SELECT id, timestamp, method, host, port, path, url, status, "
        "resp_length, duration_ms, in_scope FROM flows"
    )
    args: list[Any] = []
    if host:
        q += " WHERE host LIKE ?"
        args.append(f"%{host}%")
    q += " ORDER BY id DESC LIMIT ? OFFSET ?"
    args += [limit, offset]
    with _conn() as conn:
        return [dict(r) for r in conn.execute(q, args).fetchall()]


def get_flow(flow_id: int) -> Optional[dict[str, Any]]:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
    if not row:
        return None
    rec = dict(row)
    for k in ("req_headers", "resp_headers"):
        try:
            rec[k] = json.loads(rec[k]) if rec[k] else {}
        except (json.JSONDecodeError, TypeError):
            rec[k] = {}
    return rec


def clear() -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM flows")
