"""Approval gates for high-risk actions.

Phase 1 ships three providers:
- `auto_approve` -- used in tests and non-interactive runs
- `auto_deny`    -- used in tests to prove the abort path works
- `cli_prompt`   -- used in interactive demos

A webhook/UI-backed provider is a drop-in replacement for Phase 2.
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
