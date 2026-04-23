"""Playbook schema + YAML loader."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Trigger:
    type: str
    signal: str
    threshold: int | None = None
    window_seconds: int | None = None
    group_by: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ApprovalConfig:
    timeout_seconds: int = 300
    escalate_to: str | None = None


@dataclass(frozen=True)
class Action:
    id: str
    type: str
    params: dict[str, Any]
    timeout_seconds: int = 10
    on_failure: str = "continue"
    requires_approval: bool = False
    approval: ApprovalConfig | None = None


@dataclass(frozen=True)
class Playbook:
    name: str
    version: int
    description: str
    severity: str
    mttc_target_seconds: int
    trigger: Trigger
    actions: list[Action]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Playbook":
        trigger_data = data["trigger"]
        trigger = Trigger(
            type=trigger_data["type"],
            signal=trigger_data["signal"],
            threshold=trigger_data.get("threshold"),
            window_seconds=trigger_data.get("window_seconds"),
            group_by=list(trigger_data.get("group_by", [])),
        )
        actions: list[Action] = []
        for a in data["actions"]:
            approval = None
            if a.get("approval"):
                approval = ApprovalConfig(
                    timeout_seconds=a["approval"].get("timeout_seconds", 300),
                    escalate_to=a["approval"].get("escalate_to"),
                )
            actions.append(
                Action(
                    id=a["id"],
                    type=a["type"],
                    params=a.get("params", {}),
                    timeout_seconds=a.get("timeout_seconds", 10),
                    on_failure=a.get("on_failure", "continue"),
                    requires_approval=a.get("requires_approval", False),
                    approval=approval,
                )
            )
        return cls(
            name=data["name"],
            version=data["version"],
            description=data.get("description", "").strip(),
            severity=data["severity"],
            mttc_target_seconds=data.get("mttc_target_seconds", 60),
            trigger=trigger,
            actions=actions,
        )


def load_playbook(path: Path | str) -> Playbook:
    with open(path) as f:
        return Playbook.from_dict(yaml.safe_load(f))


def load_playbooks(directory: Path | str) -> dict[str, Playbook]:
    directory = Path(directory)
    playbooks: dict[str, Playbook] = {}
    for yml_file in sorted(directory.glob("*.yml")):
        pb = load_playbook(yml_file)
        playbooks[pb.name] = pb
    return playbooks
