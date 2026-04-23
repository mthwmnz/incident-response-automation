"""Mock Active Directory client.

Response shapes mirror typical LDAP / Microsoft Graph user operations.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


class MockActiveDirectory:
    def __init__(self) -> None:
        self.disabled_users: dict[str, dict[str, Any]] = {}
        self.password_resets: list[dict[str, Any]] = []

    def disable_user(self, username: str, reason: str) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        self.disabled_users[username] = {"reason": reason, "disabled_at": now}
        return {
            "status": "success",
            "operation_id": str(uuid.uuid4()),
            "user": username,
            "account_enabled": False,
            "timestamp": now,
        }

    def force_password_reset(self, username: str) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        self.password_resets.append({"user": username, "timestamp": now})
        return {
            "status": "success",
            "operation_id": str(uuid.uuid4()),
            "user": username,
            "force_change_password_next_sign_in": True,
            "timestamp": now,
        }
