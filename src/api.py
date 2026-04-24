"""HTTP service exposing the playbook engine.

Endpoints:
    GET  /                              -- service health + index
    GET  /playbooks                     -- list loaded playbooks + metadata
    GET  /playbooks/{name}              -- get a single playbook definition
    POST /alerts/{playbook_name}        -- trigger a playbook (body = alert)
    GET  /incidents/{incident_id}/audit -- audit trail for one incident
    GET  /approvals                     -- list pending approvals
    GET  /approvals/{token}             -- get one pending approval
    POST /approvals/{token}             -- decide on a pending approval

Designed as the natural integration target for SIEM webhooks (Splunk, ELK,
CrowdStrike) -- the SIEM POSTs the alert payload, the engine fires the matching
playbook, and the audit trail is queryable by incident id afterwards.

High-risk actions in a playbook (`requires_approval: true`) suspend execution
and emit a Slack notification with a callback URL. An analyst POSTs to the
approval endpoint to approve or deny; the engine resumes from where it paused.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .approvals import (
    ApprovalDecision,
    ApprovalProvider,
    webhook_approval_required,
)
from .audit import AuditLog
from .clients.base import Clients
from .clients.directory import MockActiveDirectory
from .clients.edr import build_edr
from .clients.firewall import MockPaloAlto
from .clients.notifier import build_notifier
from .engine import ExecutionResult, PlaybookEngine
from .pending import PendingApprovalStore
from .playbook import Playbook, load_playbooks


PLAYBOOKS_DIR = Path(__file__).parent.parent / "playbooks"


class ApprovalBody(BaseModel):
    approved: bool
    approver: str
    reason: str = ""


def _serialize_playbook(pb: Playbook) -> dict[str, Any]:
    return {
        "name": pb.name,
        "version": pb.version,
        "severity": pb.severity,
        "description": pb.description,
        "mttc_target_seconds": pb.mttc_target_seconds,
        "trigger": {
            "type": pb.trigger.type,
            "signal": pb.trigger.signal,
            "threshold": pb.trigger.threshold,
            "window_seconds": pb.trigger.window_seconds,
        },
        "actions": [
            {
                "id": a.id,
                "type": a.type,
                "requires_approval": a.requires_approval,
                "on_failure": a.on_failure,
            }
            for a in pb.actions
        ],
    }


def _serialize_result(result: ExecutionResult) -> dict[str, Any]:
    return {
        "incident_id": result.incident_id,
        "playbook": result.playbook_name,
        "status": result.status,
        "total_latency_ms": round(result.total_latency_ms, 2),
        "actions_succeeded": result.success_count,
        "actions_total": len(result.outcomes),
        "outcomes": [
            {
                "action_id": o.action_id,
                "action_type": o.action_type,
                "status": o.status,
                "latency_ms": round(o.latency_ms, 2),
                "error": o.error,
            }
            for o in result.outcomes
        ],
        "suspended_at_action_id": result.suspended_at_action_id,
    }


def create_app(
    playbooks_dir: Path | str = PLAYBOOKS_DIR,
    audit_db: str = ":memory:",
    pending_db: str | None = None,
    clients: Clients | None = None,
    approval_provider: ApprovalProvider | None = None,
    approval_base_url: str = "http://127.0.0.1:8000",
) -> FastAPI:
    """Build the FastAPI app. Test-friendly: caller can inject playbooks dir,
    audit/pending DB paths, a custom client bundle, and an approval provider.

    By default high-risk actions defer to out-of-band approval -- pass
    `approval_provider=auto_approve` to short-circuit that for tests of the
    happy path.
    """
    app = FastAPI(
        title="Incident Response Automation",
        description="Automated SOC playbook engine -- HTTP service",
        version="0.3.0",
    )

    playbooks = load_playbooks(playbooks_dir)
    audit = AuditLog(audit_db)
    pending = PendingApprovalStore(pending_db or audit_db)

    if clients is None:
        clients = Clients(
            firewall=MockPaloAlto(),
            edr=build_edr(),
            directory=MockActiveDirectory(),
            notifier=build_notifier(),
        )
    if approval_provider is None:
        approval_provider = webhook_approval_required

    engine = PlaybookEngine(
        clients=clients,
        audit=audit,
        approval_provider=approval_provider,
    )

    app.state.playbooks = playbooks
    app.state.audit = audit
    app.state.pending = pending
    app.state.clients = clients
    app.state.engine = engine
    app.state.approval_base_url = approval_base_url

    def _persist_pending_and_notify(
        result: ExecutionResult, playbook: Playbook, alert: dict[str, Any]
    ) -> str:
        """When the engine suspends, persist the pending state and notify the
        on-call channel with a callback URL."""
        token = pending.create(
            incident_id=result.incident_id,
            playbook_name=result.playbook_name,
            playbook_version=playbook.version,
            action_index=result.suspended_at_action_index or 0,
            action_id=result.suspended_at_action_id or "",
            action_type=result.suspended_action_type or "",
            rendered_params=result.suspended_rendered_params or {},
            alert=alert,
            escalate_to=result.suspended_escalate_to,
        )

        approval_url = f"{approval_base_url}/approvals/{token}"
        message = (
            f"[APPROVAL REQUIRED] {playbook.name} suspended on action "
            f"'{result.suspended_at_action_id}' "
            f"({result.suspended_action_type})\n"
            f"Incident: {result.incident_id}\n"
            f"Params:   {result.suspended_rendered_params}\n"
            f"\n"
            f"Approve: curl -X POST {approval_url} "
            f'-H "Content-Type: application/json" '
            f'-d \'{{"approved":true,"approver":"@you","reason":"reviewed"}}\'\n'
            f"Deny:    curl -X POST {approval_url} "
            f'-H "Content-Type: application/json" '
            f'-d \'{{"approved":false,"approver":"@you","reason":"false-positive"}}\''
        )
        try:
            clients.notifier.send(
                channel=result.suspended_escalate_to or "#ir-oncall",
                message=message,
                severity="critical",
            )
        except Exception:
            # Notification failure must not block the approval flow itself.
            # The pending state is already persisted; an analyst can poll
            # GET /approvals to find it.
            pass
        return token

    @app.get("/")
    def index() -> dict[str, Any]:
        return {
            "service": "incident-response-automation",
            "version": app.version,
            "playbooks_loaded": len(playbooks),
            "endpoints": {
                "list_playbooks": "GET /playbooks",
                "trigger_playbook": "POST /alerts/{playbook_name}",
                "incident_audit": "GET /incidents/{incident_id}/audit",
                "list_pending_approvals": "GET /approvals",
                "decide_approval": "POST /approvals/{token}",
            },
        }

    @app.get("/playbooks")
    def list_playbooks() -> dict[str, Any]:
        return {
            "count": len(playbooks),
            "playbooks": [_serialize_playbook(pb) for pb in playbooks.values()],
        }

    @app.get("/playbooks/{name}")
    def get_playbook(name: str) -> dict[str, Any]:
        if name not in playbooks:
            raise HTTPException(status_code=404, detail=f"playbook '{name}' not found")
        return _serialize_playbook(playbooks[name])

    @app.post("/alerts/{playbook_name}")
    def trigger_playbook(
        playbook_name: str, alert: dict[str, Any]
    ) -> dict[str, Any]:
        if playbook_name not in playbooks:
            raise HTTPException(
                status_code=404,
                detail=f"playbook '{playbook_name}' not found",
            )
        try:
            result = engine.execute(playbooks[playbook_name], alert)
        except KeyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        body = _serialize_result(result)
        if result.is_suspended:
            token = _persist_pending_and_notify(
                result, playbooks[playbook_name], alert
            )
            body["pending_approval_token"] = token
            body["approval_url"] = f"{approval_base_url}/approvals/{token}"
        return body

    @app.get("/incidents/{incident_id}/audit")
    def incident_audit(incident_id: str) -> dict[str, Any]:
        events = audit.events_for_incident(incident_id)
        if not events:
            raise HTTPException(
                status_code=404,
                detail=f"no audit events for incident '{incident_id}'",
            )
        return {"incident_id": incident_id, "event_count": len(events), "events": events}

    @app.get("/approvals")
    def list_pending() -> dict[str, Any]:
        items = pending.list_pending()
        return {"count": len(items), "pending": items}

    @app.get("/approvals/{token}")
    def get_pending(token: str) -> dict[str, Any]:
        record = pending.get(token)
        if record is None:
            raise HTTPException(
                status_code=404, detail=f"approval token '{token}' not found"
            )
        return record

    @app.post("/approvals/{token}")
    def decide_approval(token: str, body: ApprovalBody) -> dict[str, Any]:
        record = pending.get(token)
        if record is None:
            raise HTTPException(
                status_code=404, detail=f"approval token '{token}' not found"
            )
        if record["status"] != "pending":
            raise HTTPException(
                status_code=409,
                detail=(
                    f"approval already decided ({record['status']} by "
                    f"{record['approver']} at {record['decided_at']})"
                ),
            )

        ok = pending.resolve(
            token,
            approved=body.approved,
            approver=body.approver,
            reason=body.reason,
        )
        if not ok:
            # race -- another caller resolved it between get() and resolve()
            raise HTTPException(status_code=409, detail="approval already decided")

        decision = ApprovalDecision(
            approved=body.approved, approver=body.approver, reason=body.reason
        )
        playbook = playbooks[record["playbook_name"]]
        result = engine.resume(
            playbook=playbook,
            alert=record["alert"],
            from_action_index=record["action_index"],
            decision=decision,
        )

        response = _serialize_result(result)
        if result.is_suspended:
            new_token = _persist_pending_and_notify(result, playbook, record["alert"])
            response["pending_approval_token"] = new_token
            response["approval_url"] = f"{approval_base_url}/approvals/{new_token}"
        return response

    return app


app = create_app()
