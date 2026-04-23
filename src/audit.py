"""SQLite-backed audit log.

Every action dispatched -- whether successful, failed, or blocked on approval
-- produces exactly one row. `incident_id` is the single key for
reconstructing what happened during an incident.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    playbook_name TEXT NOT NULL,
    playbook_version INTEGER NOT NULL,
    action_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    action_params TEXT NOT NULL,
    status TEXT NOT NULL,
    error TEXT,
    response TEXT,
    latency_ms REAL,
    actor TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit_events(incident_id);
CREATE INDEX IF NOT EXISTS idx_audit_playbook ON audit_events(playbook_name);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
"""


class AuditLog:
    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self.db_path = str(db_path)
        # A persistent connection is required for :memory: so the schema
        # survives across record() calls.
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        cursor = self._conn.cursor()
        try:
            yield cursor
            self._conn.commit()
        finally:
            cursor.close()

    def record(
        self,
        *,
        incident_id: str,
        playbook_name: str,
        playbook_version: int,
        action_id: str,
        action_type: str,
        action_params: dict[str, Any],
        status: str,
        error: str | None = None,
        response: dict[str, Any] | None = None,
        latency_ms: float | None = None,
        actor: str = "rules_engine",
    ) -> str:
        event_id = str(uuid.uuid4())
        with self._cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO audit_events (
                    id, incident_id, playbook_name, playbook_version,
                    action_id, action_type, action_params, status, error,
                    response, latency_ms, actor, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    incident_id,
                    playbook_name,
                    playbook_version,
                    action_id,
                    action_type,
                    json.dumps(action_params),
                    status,
                    error,
                    json.dumps(response) if response is not None else None,
                    latency_ms,
                    actor,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        return event_id

    def events_for_incident(self, incident_id: str) -> list[dict[str, Any]]:
        with self._cursor() as cursor:
            rows = cursor.execute(
                "SELECT * FROM audit_events WHERE incident_id = ? ORDER BY timestamp",
                (incident_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def all_events(self) -> list[dict[str, Any]]:
        with self._cursor() as cursor:
            rows = cursor.execute(
                "SELECT * FROM audit_events ORDER BY timestamp"
            ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        self._conn.close()
