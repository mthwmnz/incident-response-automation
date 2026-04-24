"""Approval gates for high-risk actions.

Synchronous providers (return an `ApprovalDecision` immediately):
- `auto_approve`         -- used in tests and non-interactive runs
- `auto_deny`            -- used in tests to prove the abort path works
- `cli_prompt`           -- used in interactive demos

Asynchronous provider (raises `ApprovalRequired` to suspend execution):
- `webhook_approval_required` -- the engine catches the exception and returns
  a suspended ExecutionResult so the caller (typically an HTTP API) can
  persist pending state and resume later via `engine.resume()`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class ApprovalDecision:
    approved: bool
    approver: str
    reason: str


ApprovalProvider = Callable[[str, dict[str, Any]], ApprovalDecision]


def auto_approve(action_id: str, context: dict[str, Any]) -> ApprovalDecision:
    return ApprovalDecision(
        approved=True, approver="auto", reason="auto-approved (non-interactive)"
    )


def auto_deny(action_id: str, context: dict[str, Any]) -> ApprovalDecision:
    return ApprovalDecision(
        approved=False, approver="auto", reason="auto-denied (non-interactive)"
    )


def cli_prompt(action_id: str, context: dict[str, Any]) -> ApprovalDecision:
    print(f"\n[APPROVAL REQUIRED] action: {action_id}")
    for k, v in context.items():
        print(f"  {k}: {v}")
    response = input("Approve? [y/N]: ").strip().lower()
    approved = response in {"y", "yes"}
    return ApprovalDecision(
        approved=approved,
        approver="cli_user",
        reason="approved via CLI" if approved else "denied via CLI",
    )


class ApprovalRequired(Exception):
    """Raised by an approval provider to signal that the decision must be made
    out-of-band. The engine catches this, suspends execution, and returns an
    ExecutionResult with status='suspended_pending_approval'.
    """

    def __init__(self, escalate_to: str | None = None) -> None:
        super().__init__(
            f"approval required (escalate_to={escalate_to!r})"
        )
        self.escalate_to = escalate_to


def webhook_approval_required(
    action_id: str, context: dict[str, Any]
) -> ApprovalDecision:
    """Approval provider that always defers to out-of-band approval.

    Use with the HTTP service: hitting an action with `requires_approval: true`
    suspends the playbook. The decision arrives later via POST /approvals/{token}.
    """
    raise ApprovalRequired(escalate_to=context.get("escalate_to"))
