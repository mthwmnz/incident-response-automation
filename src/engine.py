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
from typing import Any, Callable

from .actions import get_handler
from .approvals import (
    ApprovalDecision,
    ApprovalProvider,
    ApprovalRequired,
    auto_approve,
)
from .audit import AuditLog
from .clients.base import Clients
from .playbook import Action, Playbook
from .templating import render


ActionStartHook = Callable[[Action, dict[str, Any]], None]
ActionEndHook = Callable[["ActionOutcome"], None]


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
    status: str = "complete"  # complete | suspended_pending_approval | aborted
    outcomes: list[ActionOutcome] = field(default_factory=list)

    # Only populated when status == "suspended_pending_approval"
    suspended_at_action_index: int | None = None
    suspended_at_action_id: str | None = None
    suspended_action_type: str | None = None
    suspended_rendered_params: dict[str, Any] | None = None
    suspended_escalate_to: str | None = None

    @property
    def all_succeeded(self) -> bool:
        return self.status == "complete" and all(
            o.status == "success" for o in self.outcomes
        )

    @property
    def success_count(self) -> int:
        return sum(1 for o in self.outcomes if o.status == "success")

    @property
    def is_suspended(self) -> bool:
        return self.status == "suspended_pending_approval"


class PlaybookEngine:
    def __init__(
        self,
        clients: Clients,
        audit: AuditLog,
        approval_provider: ApprovalProvider = auto_approve,
        on_action_start: ActionStartHook | None = None,
        on_action_end: ActionEndHook | None = None,
    ) -> None:
        self.clients = clients
        self.audit = audit
        self.approval_provider = approval_provider
        self.on_action_start = on_action_start
        self.on_action_end = on_action_end

    def execute(self, playbook: Playbook, alert: dict[str, Any]) -> ExecutionResult:
        incident_id = alert.get("incident_id") or str(uuid.uuid4())
        return self._run_from_index(
            playbook=playbook,
            alert=alert,
            incident_id=incident_id,
            start_index=0,
            prior_outcomes=[],
        )

    def resume(
        self,
        playbook: Playbook,
        alert: dict[str, Any],
        *,
        from_action_index: int,
        decision: ApprovalDecision,
    ) -> ExecutionResult:
        """Resume a suspended playbook by applying an out-of-band decision to
        the action that was waiting for approval, then continuing with any
        remaining actions.
        """
        incident_id = alert.get("incident_id") or str(uuid.uuid4())
        scopes = {
            "alert": alert,
            "playbook": {"name": playbook.name, "version": playbook.version},
        }
        action = playbook.actions[from_action_index]
        rendered_params = render(action.params, scopes)

        if self.on_action_start is not None:
            self.on_action_start(action, rendered_params)

        run_start = time.perf_counter()

        if not decision.approved:
            outcome = self._record_denial(
                action, rendered_params, incident_id, playbook, decision
            )
            if self.on_action_end is not None:
                self.on_action_end(outcome)
            if action.on_failure == "abort":
                return ExecutionResult(
                    incident_id=incident_id,
                    playbook_name=playbook.name,
                    status="aborted",
                    total_latency_ms=(time.perf_counter() - run_start) * 1000,
                    outcomes=[outcome],
                )
            return self._run_from_index(
                playbook=playbook,
                alert=alert,
                incident_id=incident_id,
                start_index=from_action_index + 1,
                prior_outcomes=[outcome],
                run_start=run_start,
            )

        # Approved -- run the handler directly (skip the approval check).
        outcome = self._run_handler(
            action, rendered_params, incident_id, playbook,
            actor=f"approval:{decision.approver}",
        )
        if self.on_action_end is not None:
            self.on_action_end(outcome)
        if outcome.status == "failed" and action.on_failure == "abort":
            return ExecutionResult(
                incident_id=incident_id,
                playbook_name=playbook.name,
                status="aborted",
                total_latency_ms=(time.perf_counter() - run_start) * 1000,
                outcomes=[outcome],
            )
        return self._run_from_index(
            playbook=playbook,
            alert=alert,
            incident_id=incident_id,
            start_index=from_action_index + 1,
            prior_outcomes=[outcome],
            run_start=run_start,
        )

    def _run_from_index(
        self,
        *,
        playbook: Playbook,
        alert: dict[str, Any],
        incident_id: str,
        start_index: int,
        prior_outcomes: list[ActionOutcome],
        run_start: float | None = None,
    ) -> ExecutionResult:
        scopes = {
            "alert": alert,
            "playbook": {"name": playbook.name, "version": playbook.version},
        }
        if run_start is None:
            run_start = time.perf_counter()
        outcomes = list(prior_outcomes)

        for index in range(start_index, len(playbook.actions)):
            action = playbook.actions[index]
            try:
                outcome = self._run_action(action, scopes, incident_id, playbook)
            except ApprovalRequired as suspend:
                rendered_params = render(action.params, scopes)
                self._audit_suspend(
                    action, rendered_params, incident_id, playbook
                )
                return ExecutionResult(
                    incident_id=incident_id,
                    playbook_name=playbook.name,
                    status="suspended_pending_approval",
                    total_latency_ms=(time.perf_counter() - run_start) * 1000,
                    outcomes=outcomes,
                    suspended_at_action_index=index,
                    suspended_at_action_id=action.id,
                    suspended_action_type=action.type,
                    suspended_rendered_params=rendered_params,
                    suspended_escalate_to=(
                        suspend.escalate_to
                        or (action.approval.escalate_to if action.approval else None)
                    ),
                )
            outcomes.append(outcome)
            if outcome.status in {"failed", "denied"} and action.on_failure == "abort":
                return ExecutionResult(
                    incident_id=incident_id,
                    playbook_name=playbook.name,
                    status="aborted",
                    total_latency_ms=(time.perf_counter() - run_start) * 1000,
                    outcomes=outcomes,
                )

        return ExecutionResult(
            incident_id=incident_id,
            playbook_name=playbook.name,
            status="complete",
            total_latency_ms=(time.perf_counter() - run_start) * 1000,
            outcomes=outcomes,
        )

    def _audit_suspend(
        self,
        action: Action,
        rendered_params: dict[str, Any],
        incident_id: str,
        playbook: Playbook,
    ) -> None:
        self.audit.record(
            incident_id=incident_id,
            playbook_name=playbook.name,
            playbook_version=playbook.version,
            action_id=action.id,
            action_type=action.type,
            action_params=rendered_params,
            status="pending_approval",
            actor="rules_engine",
        )

    def _record_denial(
        self,
        action: Action,
        rendered_params: dict[str, Any],
        incident_id: str,
        playbook: Playbook,
        decision: ApprovalDecision,
    ) -> ActionOutcome:
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

    def _run_handler(
        self,
        action: Action,
        rendered_params: dict[str, Any],
        incident_id: str,
        playbook: Playbook,
        actor: str = "rules_engine",
    ) -> ActionOutcome:
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
                actor=actor,
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
            actor=actor,
        )
        return ActionOutcome(
            action_id=action.id,
            action_type=action.type,
            status="success",
            latency_ms=latency_ms,
            response=response,
        )

    def _run_action(
        self,
        action: Action,
        scopes: dict[str, Any],
        incident_id: str,
        playbook: Playbook,
    ) -> ActionOutcome:
        rendered_params = render(action.params, scopes)
        if self.on_action_start is not None:
            self.on_action_start(action, rendered_params)
        outcome = self._dispatch(action, rendered_params, incident_id, playbook)
        if self.on_action_end is not None:
            self.on_action_end(outcome)
        return outcome

    def _dispatch(
        self,
        action: Action,
        rendered_params: dict[str, Any],
        incident_id: str,
        playbook: Playbook,
    ) -> ActionOutcome:
        if action.requires_approval:
            # The approval provider may raise ApprovalRequired -- that
            # propagates up to _run_from_index which converts it into a
            # suspended ExecutionResult.
            decision = self.approval_provider(
                action.id,
                {
                    "type": action.type,
                    "params": rendered_params,
                    "escalate_to": (
                        action.approval.escalate_to if action.approval else None
                    ),
                },
            )
            if not decision.approved:
                return self._record_denial(
                    action, rendered_params, incident_id, playbook, decision
                )

        return self._run_handler(action, rendered_params, incident_id, playbook)
