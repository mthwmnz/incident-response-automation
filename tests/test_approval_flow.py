"""Tests for the suspend/resume execution model and the approval HTTP flow.

Covers:
- engine.execute() suspends when an action requires approval
- engine.resume() with `approved=True` runs the suspended action and continues
- engine.resume() with `approved=False` records denial and aborts (per playbook)
- POST /alerts triggers and persists pending state when suspended
- POST /approvals/{token} resumes execution and returns final result
- audit trail captures pending_approval -> approved/denied lifecycle
"""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api import create_app
from src.approvals import (
    ApprovalDecision,
    ApprovalRequired,
    auto_approve,
    webhook_approval_required,
)
from src.audit import AuditLog
from src.clients.base import Clients
from src.clients.directory import MockActiveDirectory
from src.clients.edr import MockCrowdStrike
from src.clients.firewall import MockPaloAlto
from src.clients.notifier import MockSlack
from src.engine import PlaybookEngine
from src.playbook import load_playbook


PLAYBOOKS = Path(__file__).parent.parent / "playbooks"
EXFIL = PLAYBOOKS / "data_exfiltration.yml"


def _engine(approval=webhook_approval_required):
    clients = Clients(
        firewall=MockPaloAlto(),
        edr=MockCrowdStrike(),
        directory=MockActiveDirectory(),
        notifier=MockSlack(),
    )
    return clients, PlaybookEngine(
        clients=clients,
        audit=AuditLog(":memory:"),
        approval_provider=approval,
    )


# ---------- engine-level suspend/resume ----------


def test_webhook_provider_raises_approval_required():
    with pytest.raises(ApprovalRequired):
        webhook_approval_required("isolate_host", {"escalate_to": "#ir-oncall"})


def test_execute_suspends_when_action_requires_approval():
    clients, engine = _engine()
    pb = load_playbook(EXFIL)
    alert = {
        "incident_id": "INC-SUSP-1",
        "host": "WIN-FIN-03",
        "destination_ip": "203.0.113.42",
        "bytes_transferred": 2_000_000_000,
    }

    result = engine.execute(pb, alert)

    assert result.is_suspended
    assert result.status == "suspended_pending_approval"
    assert result.suspended_at_action_id == "isolate_host"
    assert result.suspended_action_type == "edr.isolate_host"
    assert result.suspended_escalate_to == "#ir-oncall"
    # Pre-approval actions should have already run.
    assert "203.0.113.42" in clients.firewall.blocked
    # The gated action must NOT have run.
    assert "WIN-FIN-03" not in clients.edr.isolated_hosts


def test_resume_with_approval_runs_suspended_action_and_remaining():
    clients, engine = _engine()
    pb = load_playbook(EXFIL)
    alert = {
        "incident_id": "INC-SUSP-2",
        "host": "WIN-FIN-04",
        "destination_ip": "203.0.113.43",
        "bytes_transferred": 1_500_000_000,
    }

    suspended = engine.execute(pb, alert)
    assert suspended.is_suspended

    result = engine.resume(
        playbook=pb,
        alert=alert,
        from_action_index=suspended.suspended_at_action_index,
        decision=ApprovalDecision(
            approved=True, approver="@alice", reason="legit incident response"
        ),
    )

    assert result.status == "complete"
    assert "WIN-FIN-04" in clients.edr.isolated_hosts
    # The notify_containment action that follows isolate_host should run too.
    notify_messages = [m for m in clients.notifier.sent if "isolated" in m["message"]]
    assert len(notify_messages) == 1


def test_resume_with_denial_aborts_remaining_actions():
    clients, engine = _engine()
    pb = load_playbook(EXFIL)
    alert = {
        "incident_id": "INC-SUSP-3",
        "host": "WIN-FIN-05",
        "destination_ip": "203.0.113.44",
        "bytes_transferred": 900_000_000,
    }

    suspended = engine.execute(pb, alert)
    result = engine.resume(
        playbook=pb,
        alert=alert,
        from_action_index=suspended.suspended_at_action_index,
        decision=ApprovalDecision(
            approved=False, approver="@bob", reason="false positive"
        ),
    )

    assert result.status == "aborted"
    assert "WIN-FIN-05" not in clients.edr.isolated_hosts
    # Denial recorded in the resume's outcomes
    assert any(
        o.action_id == "isolate_host" and o.status == "denied" for o in result.outcomes
    )


def test_audit_captures_pending_then_approved_lifecycle():
    _, engine = _engine()
    pb = load_playbook(EXFIL)
    alert = {
        "incident_id": "INC-SUSP-4",
        "host": "WIN-FIN-06",
        "destination_ip": "203.0.113.45",
        "bytes_transferred": 1_000_000_000,
    }

    suspended = engine.execute(pb, alert)
    engine.resume(
        playbook=pb,
        alert=alert,
        from_action_index=suspended.suspended_at_action_index,
        decision=ApprovalDecision(approved=True, approver="@carol", reason="ok"),
    )

    events = engine.audit.events_for_incident("INC-SUSP-4")
    isolate_events = [e for e in events if e["action_id"] == "isolate_host"]
    statuses = [e["status"] for e in isolate_events]
    assert "pending_approval" in statuses
    assert "success" in statuses
    success_event = next(e for e in isolate_events if e["status"] == "success")
    assert success_event["actor"] == "approval:@carol"


# ---------- API-level approval flow ----------


@pytest.fixture
def api_client():
    return TestClient(create_app())


def test_post_alerts_returns_suspended_with_token(api_client):
    response = api_client.post(
        "/alerts/data_exfiltration",
        json={
            "incident_id": "INC-API-EXFIL-1",
            "host": "WIN-FIN-10",
            "destination_ip": "203.0.113.10",
            "bytes_transferred": 5_000_000_000,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "suspended_pending_approval"
    assert body["suspended_at_action_id"] == "isolate_host"
    assert "pending_approval_token" in body
    assert body["approval_url"].endswith(f"/approvals/{body['pending_approval_token']}")


def test_pending_approvals_listed_and_individually_fetchable(api_client):
    api_client.post(
        "/alerts/data_exfiltration",
        json={
            "incident_id": "INC-API-EXFIL-2",
            "host": "WIN-FIN-11",
            "destination_ip": "203.0.113.11",
            "bytes_transferred": 1_000_000,
        },
    )

    listing = api_client.get("/approvals").json()
    assert listing["count"] == 1
    token = listing["pending"][0]["token"]

    detail = api_client.get(f"/approvals/{token}").json()
    assert detail["incident_id"] == "INC-API-EXFIL-2"
    assert detail["action_id"] == "isolate_host"
    assert detail["status"] == "pending"


def test_approve_resumes_and_completes_playbook(api_client):
    triggered = api_client.post(
        "/alerts/data_exfiltration",
        json={
            "incident_id": "INC-API-EXFIL-3",
            "host": "WIN-FIN-12",
            "destination_ip": "203.0.113.12",
            "bytes_transferred": 2_000_000_000,
        },
    ).json()
    token = triggered["pending_approval_token"]

    approve = api_client.post(
        f"/approvals/{token}",
        json={"approved": True, "approver": "@alice", "reason": "verified"},
    )
    assert approve.status_code == 200
    body = approve.json()
    assert body["status"] == "complete"
    # isolate_host + notify_containment = 2 outcomes from the resume
    assert body["actions_succeeded"] == 2


def test_deny_resumes_and_aborts(api_client):
    triggered = api_client.post(
        "/alerts/data_exfiltration",
        json={
            "incident_id": "INC-API-EXFIL-4",
            "host": "WIN-FIN-13",
            "destination_ip": "203.0.113.13",
            "bytes_transferred": 800_000_000,
        },
    ).json()
    token = triggered["pending_approval_token"]

    deny = api_client.post(
        f"/approvals/{token}",
        json={"approved": False, "approver": "@bob", "reason": "false positive"},
    )
    assert deny.status_code == 200
    body = deny.json()
    assert body["status"] == "aborted"


def test_double_decision_returns_409(api_client):
    triggered = api_client.post(
        "/alerts/data_exfiltration",
        json={
            "incident_id": "INC-API-EXFIL-5",
            "host": "WIN-FIN-14",
            "destination_ip": "203.0.113.14",
            "bytes_transferred": 600_000_000,
        },
    ).json()
    token = triggered["pending_approval_token"]

    api_client.post(
        f"/approvals/{token}",
        json={"approved": True, "approver": "@alice", "reason": "ok"},
    )
    second = api_client.post(
        f"/approvals/{token}",
        json={"approved": False, "approver": "@bob", "reason": "changed mind"},
    )
    assert second.status_code == 409


def test_unknown_token_returns_404(api_client):
    response = api_client.post(
        "/approvals/00000000-0000-0000-0000-000000000000",
        json={"approved": True, "approver": "@x", "reason": ""},
    )
    assert response.status_code == 404


def test_auto_approve_override_skips_suspension():
    """Test injection: passing auto_approve as approval_provider lets the
    happy path run end-to-end without any approval flow."""
    app = create_app(approval_provider=auto_approve)
    client = TestClient(app)
    response = client.post(
        "/alerts/data_exfiltration",
        json={
            "incident_id": "INC-AUTOAPPROVE-1",
            "host": "WIN-FIN-99",
            "destination_ip": "203.0.113.99",
            "bytes_transferred": 100_000,
        },
    ).json()
    assert response["status"] == "complete"
