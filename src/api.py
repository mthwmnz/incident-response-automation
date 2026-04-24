"""HTTP service exposing the playbook engine.

Endpoints:
    GET  /                              -- service health + index
    GET  /playbooks                     -- list loaded playbooks + metadata
    POST /alerts/{playbook_name}        -- trigger a playbook (body = alert)
    GET  /incidents/{incident_id}/audit -- audit trail for one incident

Designed as the natural integration target for SIEM webhooks (Splunk, ELK,
CrowdStrike) -- the SIEM POSTs the alert payload, the engine fires the matching
playbook, and the audit trail is queryable by incident id afterwards.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException

from .audit import AuditLog
from .clients.base import Clients
from .clients.directory import MockActiveDirectory
from .clients.edr import MockCrowdStrike
from .clients.firewall import MockPaloAlto
from .clients.notifier import build_notifier
from .engine import PlaybookEngine
from .playbook import Playbook, load_playbooks


PLAYBOOKS_DIR = Path(__file__).parent.parent / "playbooks"


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


def create_app(
    playbooks_dir: Path | str = PLAYBOOKS_DIR,
    audit_db: str = ":memory:",
    clients: Clients | None = None,
) -> FastAPI:
    """Build the FastAPI app. Test-friendly: caller can inject playbooks dir,
    audit DB path, and a custom client bundle."""
    app = FastAPI(
        title="Incident Response Automation",
        description="Automated SOC playbook engine -- HTTP service",
        version="0.2.0",
    )

    playbooks = load_playbooks(playbooks_dir)
    audit = AuditLog(audit_db)
    if clients is None:
        clients = Clients(
            firewall=MockPaloAlto(),
            edr=MockCrowdStrike(),
            directory=MockActiveDirectory(),
            notifier=build_notifier(),
        )
    engine = PlaybookEngine(clients=clients, audit=audit)

    # Make components reachable from tests via app.state.
    app.state.playbooks = playbooks
    app.state.audit = audit
    app.state.clients = clients
    app.state.engine = engine

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

        return {
            "incident_id": result.incident_id,
            "playbook": result.playbook_name,
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
        }

    @app.get("/incidents/{incident_id}/audit")
    def incident_audit(incident_id: str) -> dict[str, Any]:
        events = audit.events_for_incident(incident_id)
        if not events:
            raise HTTPException(
                status_code=404,
                detail=f"no audit events for incident '{incident_id}'",
            )
        return {"incident_id": incident_id, "event_count": len(events), "events": events}

    return app


app = create_app()
