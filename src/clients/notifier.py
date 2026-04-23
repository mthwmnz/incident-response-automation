"""Mock Slack notifier.

Prints formatted messages to stdout so demos are visible without a real
webhook. Swapping in a real Slack client (slack_sdk.WebClient) is a drop-in
replacement.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


_SEVERITY_TAG = {
    "low": "[LOW]",
    "medium": "[MED]",
    "high": "[HIGH]",
    "critical": "[CRIT]",
}


class MockSlack:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    def send(
        self, channel: str, message: str, severity: str = "medium"
    ) -> dict[str, Any]:
        ts = datetime.now(timezone.utc).isoformat()
        tag = _SEVERITY_TAG.get(severity, "[INFO]")
        print(f"\n{tag} slack {channel} @ {ts}")
        for line in message.strip().splitlines():
            print(f"    {line}")
        self.sent.append(
            {
                "channel": channel,
                "message": message,
                "severity": severity,
                "timestamp": ts,
            }
        )
        return {
            "ok": True,
            "channel": channel,
            "ts": ts,
            "message_id": str(uuid.uuid4()),
        }
