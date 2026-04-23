"""Mock CrowdStrike Falcon EDR client.

Response shapes approximate the CrowdStrike Falcon Hosts / Real Time Response
(RTR) APIs so the adapter swap for real integration is minimal.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


class MockCrowdStrike:
    def __init__(self) -> None:
        self.killed_processes: list[dict[str, Any]] = []
        self.quarantined_files: list[dict[str, Any]] = []
        self.isolated_hosts: dict[str, dict[str, Any]] = {}

    def kill_process(
        self, host: str, process_id: str | int, reason: str
    ) -> dict[str, Any]:
        batch_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        self.killed_processes.append(
            {
                "batch_id": batch_id,
                "host": host,
                "process_id": str(process_id),
                "reason": reason,
                "timestamp": now,
            }
        )
        return {
            "status": "success",
            "resources": {
                "host_id": host,
                "session_id": batch_id,
                "stdout": f"Process {process_id} terminated",
                "stderr": "",
                "complete": True,
            },
        }

    def quarantine_file(
        self, host: str, file_hash: str, reason: str
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        self.quarantined_files.append(
            {"host": host, "sha256": file_hash, "reason": reason, "timestamp": now}
        )
        return {
            "status": "success",
            "resources": {
                "host_id": host,
                "sha256": file_hash,
                "action": "quarantine",
                "timestamp": now,
            },
        }

    def isolate_host(self, host: str, reason: str) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        self.isolated_hosts[host] = {"reason": reason, "isolated_at": now}
        return {
            "status": "success",
            "resources": {
                "host_id": host,
                "action": "contain",
                "state": "contained",
                "timestamp": now,
            },
        }
