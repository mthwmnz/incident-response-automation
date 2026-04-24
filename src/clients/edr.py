"""CrowdStrike Falcon EDR clients.

`MockCrowdStrike` keeps in-memory state for demos and tests without
credentials. `FalconCrowdStrike` is the real integration -- OAuth2 client
credentials, token caching, and three production-shaped endpoints:

  - isolate_host         -> POST /devices/entities/devices-actions/v2
                            (Falcon Containment API)
  - kill_process         -> POST /real-time-response/entities/sessions/v1 +
                            POST /real-time-response/entities/admin-command/v1
                            (Falcon RTR session + admin `kill <pid>`)
  - quarantine_file      -> POST /iocs/entities/indicators/v1
                            (Falcon Custom IOC -- adds the hash as a global
                            preventive indicator, blocking it on every Falcon-
                            managed host. The Falcon API doesn't expose
                            single-host quarantine cleanly; this is the
                            closer real-world action.)

`build_edr()` picks Falcon if FALCON_CLIENT_ID + FALCON_CLIENT_SECRET are
set, otherwise falls back to the mock so demos run without credentials.
"""
from __future__ import annotations

import os
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

from .base import EDRClient


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


# Default to US-1 commercial cloud. Override with FALCON_BASE_URL for other
# regions: https://api.us-2.crowdstrike.com, https://api.eu-1.crowdstrike.com,
# https://api.laggar.gcw.crowdstrike.com (Gov).
DEFAULT_FALCON_BASE_URL = "https://api.crowdstrike.com"

# Refresh the token slightly before its real expiry so a long request can't
# fail mid-flight on a stale token.
_TOKEN_EXPIRY_GRACE_SECONDS = 30


class FalconCrowdStrike:
    """Real CrowdStrike Falcon EDR client.

    Authenticates via OAuth2 client credentials, caches the access token until
    near-expiry, and exposes the three EDR actions the engine uses. Each method
    returns the raw Falcon response so the audit log captures vendor-side IDs
    (host_id, batch_id, IOC id) for traceability.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = DEFAULT_FALCON_BASE_URL,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._token: str | None = None
        self._token_expires_at: float = 0.0
        self._token_lock = threading.Lock()

    # ---------- OAuth2 ----------

    def _get_token(self) -> str:
        with self._token_lock:
            now = time.time()
            if self._token and now < self._token_expires_at - _TOKEN_EXPIRY_GRACE_SECONDS:
                return self._token

            response = httpx.post(
                f"{self.base_url}/oauth2/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            payload = response.json()
            self._token = payload["access_token"]
            # expires_in is seconds from now; store the absolute expiry.
            self._token_expires_at = now + int(payload.get("expires_in", 1800))
            return self._token

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Accept": "application/json",
        }

    # ---------- EDR actions ----------

    def isolate_host(self, host: str, reason: str) -> dict[str, Any]:
        """Network-contain a host via Falcon Containment.

        `host` is the Falcon device_id (AID). `reason` is recorded in our
        audit log; Falcon's API doesn't accept a reason field on this action.
        """
        response = httpx.post(
            f"{self.base_url}/devices/entities/devices-actions/v2",
            params={"action_name": "contain"},
            json={"ids": [host]},
            headers={**self._auth_headers(), "Content-Type": "application/json"},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        body = response.json()
        body["_local_reason"] = reason  # audit-log-only; not sent to Falcon
        return body

    def kill_process(
        self, host: str, process_id: str | int, reason: str
    ) -> dict[str, Any]:
        """Kill a process on a host via Falcon RTR (Real Time Response).

        Two-step: open an RTR session against the device, then run the
        admin `kill <pid>` command. Returns the second response with the
        session id added so the audit log can correlate. Result polling is
        not implemented (Falcon admin commands are typically fire-and-forget
        for kill); production would add a poll on the cloud_request_id.
        """
        # Step 1: init session
        session_resp = httpx.post(
            f"{self.base_url}/real-time-response/entities/sessions/v1",
            json={"device_id": host},
            headers={**self._auth_headers(), "Content-Type": "application/json"},
            timeout=self.timeout_seconds,
        )
        session_resp.raise_for_status()
        session_body = session_resp.json()
        session_id = session_body["resources"][0]["session_id"]

        # Step 2: run admin kill
        cmd_resp = httpx.post(
            f"{self.base_url}/real-time-response/entities/admin-command/v1",
            json={
                "session_id": session_id,
                "base_command": "kill",
                "command_string": f"kill {process_id}",
            },
            headers={**self._auth_headers(), "Content-Type": "application/json"},
            timeout=self.timeout_seconds,
        )
        cmd_resp.raise_for_status()
        cmd_body = cmd_resp.json()
        cmd_body["_session_id"] = session_id
        cmd_body["_local_reason"] = reason
        return cmd_body

    def quarantine_file(
        self, host: str, file_hash: str, reason: str
    ) -> dict[str, Any]:
        """Block a file hash globally via Falcon Custom IOC.

        Note: Falcon doesn't expose per-host quarantine via API. The closer
        real-world action is registering the SHA256 as a custom IOC with
        `action: prevent`, which blocks the file on every Falcon-managed
        host. The `host` parameter is recorded in the audit log so we know
        which host triggered the IOC, but does not constrain the IOC scope.
        """
        response = httpx.post(
            f"{self.base_url}/iocs/entities/indicators/v1",
            json={
                "indicators": [
                    {
                        "type": "sha256",
                        "value": file_hash,
                        "action": "prevent",
                        "platforms": ["windows", "mac", "linux"],
                        "severity": "high",
                        "source": "playbook-engine",
                        "description": (
                            f"auto-quarantined from host {host}: {reason}"
                        ),
                        "applied_globally": True,
                    }
                ]
            },
            headers={**self._auth_headers(), "Content-Type": "application/json"},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        body = response.json()
        body["_originating_host"] = host
        body["_local_reason"] = reason
        return body


def build_edr() -> EDRClient:
    """Pick an EDR client based on environment.

    FALCON_CLIENT_ID + FALCON_CLIENT_SECRET set -> real Falcon
    Otherwise                                   -> MockCrowdStrike
    """
    client_id = os.environ.get("FALCON_CLIENT_ID", "").strip()
    client_secret = os.environ.get("FALCON_CLIENT_SECRET", "").strip()
    if client_id and client_secret:
        base_url = (
            os.environ.get("FALCON_BASE_URL", "").strip() or DEFAULT_FALCON_BASE_URL
        )
        return FalconCrowdStrike(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
        )
    return MockCrowdStrike()
