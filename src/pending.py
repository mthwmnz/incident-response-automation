"""SQLite-backed store for pending approvals.

When a playbook hits an action with `requires_approval: true` and the engine
is configured for out-of-band approval, execution suspends and the pending
state is written here. The engine can be resumed later via `engine.resume()`
once the approver hits the approval endpoint.

Persisting this state means pending approvals survive server restarts -- a
critical property for an IR tool, where an analyst might be hours away from
deciding.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_approvals (
    token TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    playbook_name TEXT NOT NULL,
    playbook_version INTEGER NOT NULL,
    action_index INTEGER NOT NULL,
    action_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    rendered_params TEXT NOT NULL,
    alert TEXT NOT NULL,
    escalate_to TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    approver TEXT,
    decision_reason TEXT,
    created_at TEXT NOT NULL,
    decided_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_approvals(status);
CREATE INDEX IF NOT EXISTS idx_pending_incident ON pending_approvals(incident_id);
"""


class PendingApprovalStore:
    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cursor = self._conn.cursor()
            try:
                yield cursor
                self._conn.commit()
            finally:
                cursor.close()

    def create(
        self,
        *,
        incident_id: str,
        playbook_name: str,
        playbook_version: int,
        action_index: int,
        action_id: str,
        action_type: str,
        rendered_params: dict[str, Any],
        alert: dict[str, Any],
        escalate_to: str | None = None,
    ) -> str:
        token = str(uuid.uuid4())
        with self._cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO pending_approvals (
                    token, incident_id, playbook_name, playbook_version,
                    action_index, action_id, action_type, rendered_params,
                    alert, escalate_to, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
                """,
                (
                    token,
                    incident_id,
                    playbook_name,
                    playbook_version,
                    action_index,
                    action_id,
                    action_type,
                    json.dumps(rendered_params),
                    json.dumps(alert),
                    escalate_to,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        return token

    def get(self, token: str) -> dict[str, Any] | None:
        with self._cursor() as cursor:
            row = cursor.execute(
                "SELECT * FROM pending_approvals WHERE token = ?", (token,)
            ).fetchone()
        if row is None:
            return None
        record = dict(row)
        record["rendered_params"] = json.loads(record["rendered_params"])
        record["alert"] = json.loads(record["alert"])
        return record

    def resolve(
        self,
        token: str,
        *,
        approved: bool,
        approver: str,
        reason: str,
    ) -> bool:
        new_status = "approved" if approved else "denied"
        with self._cursor() as cursor:
            cursor.execute(
                """
                UPDATE pending_approvals
                   SET status = ?, approver = ?, decision_reason = ?, decided_at = ?
                 WHERE token = ? AND status = 'pending'
                """,
                (
                    new_status,
                    approver,
                    reason,
                    datetime.now(timezone.utc).isoformat(),
                    token,
                ),
            )
            return cursor.rowcount == 1

    def list_pending(self) -> list[dict[str, Any]]:
        with self._cursor() as cursor:
            rows = cursor.execute(
                "SELECT * FROM pending_approvals WHERE status = 'pending' "
                "ORDER BY created_at"
            ).fetchall()
        out = []
        for row in rows:
            record = dict(row)
            record["rendered_params"] = json.loads(record["rendered_params"])
            record["alert"] = json.loads(record["alert"])
            out.append(record)
        return out

    def close(self) -> None:
        self._conn.close()
