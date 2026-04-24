"""Tests for the EDR client factory and the FalconCrowdStrike real client.

Hermetic: httpx.post is monkeypatched to return canned responses. We verify
the factory selects the right client based on env vars, OAuth token
caching, and that each EDR action sends the request the Falcon API expects.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from src.clients.edr import (
    DEFAULT_FALCON_BASE_URL,
    FalconCrowdStrike,
    MockCrowdStrike,
    build_edr,
)


# ---------- factory ----------


def test_build_edr_defaults_to_mock(monkeypatch):
    monkeypatch.delenv("FALCON_CLIENT_ID", raising=False)
    monkeypatch.delenv("FALCON_CLIENT_SECRET", raising=False)
    assert isinstance(build_edr(), MockCrowdStrike)


def test_build_edr_returns_falcon_when_creds_set(monkeypatch):
    monkeypatch.setenv("FALCON_CLIENT_ID", "test-client")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "test-secret")
    monkeypatch.delenv("FALCON_BASE_URL", raising=False)
    edr = build_edr()
    assert isinstance(edr, FalconCrowdStrike)
    assert edr.client_id == "test-client"
    assert edr.base_url == DEFAULT_FALCON_BASE_URL


def test_build_edr_honors_base_url_override(monkeypatch):
    monkeypatch.setenv("FALCON_CLIENT_ID", "id")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "secret")
    monkeypatch.setenv("FALCON_BASE_URL", "https://api.eu-1.crowdstrike.com")
    edr = build_edr()
    assert isinstance(edr, FalconCrowdStrike)
    assert edr.base_url == "https://api.eu-1.crowdstrike.com"


def test_build_edr_treats_partial_creds_as_unset(monkeypatch):
    monkeypatch.setenv("FALCON_CLIENT_ID", "only-id")
    monkeypatch.delenv("FALCON_CLIENT_SECRET", raising=False)
    assert isinstance(build_edr(), MockCrowdStrike)


# ---------- httpx mocking helper ----------


def _stub_response(
    status: int = 200, json_body: Any = None
) -> httpx.Response:
    request = httpx.Request("POST", "https://stub")
    return httpx.Response(status, json=json_body or {}, request=request)


@pytest.fixture
def captured_calls(monkeypatch):
    """Captures every httpx.post call made by the client under test."""
    calls: list[dict[str, Any]] = []

    def fake_post(url, **kwargs):
        calls.append({"url": url, **kwargs})
        return _stub_response(200, _next_response(url))

    # The test sets these per-test by mutating the dict.
    response_map: dict[str, Any] = {}

    def _next_response(url: str) -> Any:
        for prefix, body in response_map.items():
            if prefix in url:
                return body
        return {}

    monkeypatch.setattr(httpx, "post", fake_post)
    return calls, response_map


# ---------- OAuth + token caching ----------


def test_falcon_obtains_oauth_token_on_first_call(captured_calls):
    calls, responses = captured_calls
    responses["/oauth2/token"] = {"access_token": "tok-abc", "expires_in": 1800}
    responses["/devices/entities/devices-actions"] = {
        "resources": [{"id": "host-1"}]
    }

    falcon = FalconCrowdStrike(
        client_id="cid", client_secret="csec", base_url="https://api.test"
    )
    falcon.isolate_host(host="HOST-1", reason="test")

    oauth_call = next(c for c in calls if "/oauth2/token" in c["url"])
    assert oauth_call["data"]["client_id"] == "cid"
    assert oauth_call["data"]["client_secret"] == "csec"

    action_call = next(c for c in calls if "/devices-actions" in c["url"])
    assert action_call["headers"]["Authorization"] == "Bearer tok-abc"


def test_falcon_caches_token_across_calls(captured_calls):
    calls, responses = captured_calls
    responses["/oauth2/token"] = {"access_token": "tok-1", "expires_in": 1800}
    responses["/devices-actions"] = {"resources": []}

    falcon = FalconCrowdStrike(
        client_id="cid", client_secret="csec", base_url="https://api.test"
    )
    falcon.isolate_host(host="A", reason="x")
    falcon.isolate_host(host="B", reason="y")
    falcon.isolate_host(host="C", reason="z")

    oauth_calls = [c for c in calls if "/oauth2/token" in c["url"]]
    assert len(oauth_calls) == 1, "token should be cached, not refetched per call"


# ---------- isolate_host ----------


def test_isolate_host_posts_correct_payload(captured_calls):
    calls, responses = captured_calls
    responses["/oauth2/token"] = {"access_token": "T", "expires_in": 1800}
    responses["/devices-actions"] = {"resources": [{"id": "host-42"}]}

    falcon = FalconCrowdStrike("c", "s", "https://api.test")
    result = falcon.isolate_host(host="HOST-42", reason="exfil suspected")

    action_call = next(c for c in calls if "/devices-actions" in c["url"])
    assert action_call["params"] == {"action_name": "contain"}
    assert action_call["json"] == {"ids": ["HOST-42"]}
    assert result["_local_reason"] == "exfil suspected"


# ---------- kill_process (RTR two-step) ----------


def test_kill_process_opens_session_then_runs_admin_command(captured_calls):
    calls, responses = captured_calls
    responses["/oauth2/token"] = {"access_token": "T", "expires_in": 1800}
    responses["/real-time-response/entities/sessions"] = {
        "resources": [{"session_id": "sess-xyz"}]
    }
    responses["/real-time-response/entities/admin-command"] = {
        "resources": [{"cloud_request_id": "req-789"}]
    }

    falcon = FalconCrowdStrike("c", "s", "https://api.test")
    result = falcon.kill_process(host="HOST-99", process_id=4821, reason="EDR alert")

    session_call = next(c for c in calls if "/sessions/v1" in c["url"])
    assert session_call["json"] == {"device_id": "HOST-99"}

    admin_call = next(c for c in calls if "/admin-command/v1" in c["url"])
    assert admin_call["json"]["session_id"] == "sess-xyz"
    assert admin_call["json"]["base_command"] == "kill"
    assert admin_call["json"]["command_string"] == "kill 4821"

    assert result["_session_id"] == "sess-xyz"
    assert result["_local_reason"] == "EDR alert"


# ---------- quarantine_file ----------


def test_quarantine_file_registers_global_ioc(captured_calls):
    calls, responses = captured_calls
    responses["/oauth2/token"] = {"access_token": "T", "expires_in": 1800}
    responses["/iocs/entities/indicators"] = {
        "resources": [{"id": "ioc-555"}]
    }

    falcon = FalconCrowdStrike("c", "s", "https://api.test")
    sha = "a" * 64
    result = falcon.quarantine_file(
        host="HOST-1", file_hash=sha, reason="dropped by killed process"
    )

    ioc_call = next(c for c in calls if "/iocs/entities/indicators" in c["url"])
    indicator = ioc_call["json"]["indicators"][0]
    assert indicator["type"] == "sha256"
    assert indicator["value"] == sha
    assert indicator["action"] == "prevent"
    assert "prevent" in indicator["action"]
    assert set(indicator["platforms"]) == {"windows", "mac", "linux"}
    assert result["_originating_host"] == "HOST-1"
    assert result["_local_reason"] == "dropped by killed process"


# ---------- error propagation ----------


def test_falcon_raises_on_oauth_failure(monkeypatch):
    def fake_post(url, **kwargs):
        if "/oauth2/token" in url:
            request = httpx.Request("POST", url)
            return httpx.Response(401, json={"errors": ["bad creds"]}, request=request)
        request = httpx.Request("POST", url)
        return httpx.Response(200, json={}, request=request)

    monkeypatch.setattr(httpx, "post", fake_post)
    falcon = FalconCrowdStrike("bad", "bad", "https://api.test")
    with pytest.raises(httpx.HTTPStatusError):
        falcon.isolate_host(host="X", reason="y")


def test_falcon_raises_on_action_failure(monkeypatch):
    state = {"oauth_done": False}

    def fake_post(url, **kwargs):
        request = httpx.Request("POST", url)
        if "/oauth2/token" in url:
            state["oauth_done"] = True
            return httpx.Response(
                200,
                json={"access_token": "T", "expires_in": 1800},
                request=request,
            )
        return httpx.Response(
            500, json={"errors": ["upstream"]}, request=request
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    falcon = FalconCrowdStrike("c", "s", "https://api.test")
    with pytest.raises(httpx.HTTPStatusError):
        falcon.isolate_host(host="X", reason="y")
    assert state["oauth_done"]
