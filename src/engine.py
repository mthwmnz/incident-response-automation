"""Playbook execution engine.

Loads playbooks, dispatches actions in declared order, gates high-risk actions
behind an approval provider, and records every step to the audit log. A single
run produces one `ExecutionResult` summarising per-action outcomes and total
MTTC for the playbook.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .actions import get_handler
from .approvals import ApprovalProvider, auto_approve
from .audit import AuditLog
from .clients.base import Clients
from .playbook import Action, Playbook
from .templating import render


@dataclass
class ActionOutcome:
    action_id: str
    action_type: str
    status: str  # "success" | "failed" | "denied"
    latency_ms: float
    response: dict[str, Any] | None = None
    error: str | None = None


@dataclass
class ExecutionResult:
    incident_id: str
    playbook_name: str
    total_latency_ms: float
    outcomes: list[ActionOutcome] = field(default_factory=list)

    @property
    def all_succeeded(self) -> bool:
        return all(o.status == "success" for o in self.outcomes)

    @property
    def success_count(self) -> int:
        return sum(1 for o in self.outcomes if o.status == "success")


class PlaybookEngine:
    def __init__(
        self,
        clients: Clients,
        audit: AuditLog,
        approval_provider: ApprovalProvider = auto_approve,
    ) -> None:
        self.clients = clients
        self.audit = audit
        self.approval_provider = approval_provider

    def execute(self, playbook: Playbook, alert: dict[str, Any]) -> ExecutionResult:
        incident_id = alert.get("incident_id") or str(uuid.uuid4())
        scopes = {
            "alert": alert,
            "playbook": {"name": playbook.name, "version": playbook.version},
        }

        result = ExecutionResult(
            incident_id=incident_id,
            playbook_name=playbook.name,
            total_latency_ms=0.0,
        )
        run_start = time.perf_counter()

        for action in playbook.actions:
            outcome = self._run_action(action, scopes, incident_id, playbook)
            result.outcomes.append(outcome)
            if outcome.status in {"failed", "denied"} and action.on_failure == "abort":
                break

        result.total_latency_ms = (time.perf_counter() - run_start) * 1000
        return result

    def _run_action(
        self,
        action: Action,
        scopes: dict[str, Any],
        incident_id: str,
        playbook: Playbook,
    ) -> ActionOutcome:
        rendered_params = render(action.params, scopes)

        if action.requires_approval:
            decision = self.approval_provider(
                action.id,
                {"type": action.type, "params": rendered_params},
            )
            if not decision.approved:
                self.audit.record(
                    incident_id=incident_id,
                    playbook_name=playbook.name,
                    playbook_version=playbook.version,
                    action_id=action.id,
                    action_type=action.type,
                    action_params=rendered_params,
                    status="denied",
                    error=f"approval denied by {decision.approver}: {decision.reason}",
                    actor=f"approval:{decision.approver}",
                )
                return ActionOutcome(
                    action_id=action.id,
                    action_type=action.type,
                    status="denied",
                    latency_ms=0.0,
                    error=decision.reason,
                )

        handler = get_handler(action.type)
        start = time.perf_counter()
        try:
            response = handler(rendered_params, self.clients)
        except Exception as exc:
            latency_ms = (time.perf_counter() - start) * 1000
            self.audit.record(
                incident_id=incident_id,
                playbook_name=playbook.name,
                playbook_version=playbook.version,
                action_id=action.id,
                action_type=action.type,
                action_params=rendered_params,
                status="failed",
                error=str(exc),
                latency_ms=latency_ms,
            )
            return ActionOutcome(
                action_id=action.id,
                action_type=action.type,
                status="failed",
                latency_ms=latency_ms,
                error=str(exc),
            )

        latency_ms = (time.perf_counter() - start) * 1000
        self.audit.record(
            incident_id=incident_id,
            playbook_name=playbook.name,
            playbook_version=playbook.version,
            action_id=action.id,
            action_type=action.type,
            action_params=rendered_params,
            status="success",
            response=response,
            latency_ms=latency_ms,
        )
        return ActionOutcome(
            action_id=action.id,
            action_type=action.type,
            status="success",
            latency_ms=latency_ms,
            response=response,
        )
