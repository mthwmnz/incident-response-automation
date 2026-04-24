"""Slack notifier clients.

`MockSlack` prints to stdout so demos are visible without a real webhook.
`SlackWebhook` posts to a real Slack incoming webhook URL.

Use `build_notifier()` to pick automatically based on the SLACK_WEBHOOK_URL
environment variable -- present means real Slack, absent means mock. Lets
the demo run without credentials and the production deploy run without
code changes.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

from .base import Notifier


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


class SlackWebhook:
    """Posts messages to a Slack incoming webhook URL.

    Webhooks are channel-bound at creation time, so the `channel` argument
    is informational only -- it appears in the message header but does not
    route the message. Use multiple webhooks (one per channel) if you need
    separate routing.
    """

    def __init__(self, webhook_url: str, timeout_seconds: float = 5.0) -> None:
        self.webhook_url = webhook_url
        self.timeout_seconds = timeout_seconds
        self.sent: list[dict[str, Any]] = []

    def send(
        self, channel: str, message: str, severity: str = "medium"
    ) -> dict[str, Any]:
        ts = datetime.now(timezone.utc).isoformat()
        tag = _SEVERITY_TAG.get(severity, "[INFO]")
        text = f"{tag} {channel}\n{message.strip()}"

        response = httpx.post(
            self.webhook_url,
            json={"text": text},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()

        record = {
            "channel": channel,
            "message": message,
            "severity": severity,
            "timestamp": ts,
        }
        self.sent.append(record)
        return {
            "ok": True,
            "channel": channel,
            "ts": ts,
            "message_id": str(uuid.uuid4()),
            "transport": "slack_webhook",
        }


def build_notifier() -> Notifier:
    """Pick a notifier based on environment.

    SLACK_WEBHOOK_URL set -> real Slack via incoming webhook
    Otherwise              -> MockSlack (stdout only)
    """
    url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if url:
        return SlackWebhook(webhook_url=url)
    return MockSlack()
