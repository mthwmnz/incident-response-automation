"""Mock Palo Alto firewall client.

Response shapes mirror the real Palo Alto PAN-OS XML API so swapping in the
real SDK is straightforward.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


class MockPaloAlto:
    def __init__(self) -> None:
        self.blocked: dict[str, dict[str, Any]] = {}

    def block_ip(self, ip: str, reason: str) -> dict[str, Any]:
        entry_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        self.blocked[ip] = {
            "id": entry_id,
            "ip": ip,
            "reason": reason,
            "created_at": now,
        }
        return {
            "status": "success",
            "rule_id": entry_id,
            "ip": ip,
            "action": "block",
            "committed_at": now,
        }

    def unblock_ip(self, ip: str) -> dict[str, Any]:
        if ip not in self.blocked:
            return {"status": "noop", "ip": ip, "message": "not blocked"}
        del self.blocked[ip]
        return {"status": "success", "ip": ip, "action": "unblock"}
