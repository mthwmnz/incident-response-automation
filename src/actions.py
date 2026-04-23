"""Action registry.

Maps playbook `action.type` strings (e.g. `firewall.block_ip`) to handler
callables. Handlers take the rendered params and the client bundle, and return
the raw vendor response so it can be stored in the audit log.
"""
from __future__ import annotations

from typing import Any, Callable

from .clients.base import Clients


ActionHandler = Callable[[dict[str, Any], Clients], dict[str, Any]]


def _block_ip(params: dict[str, Any], clients: Clients) -> dict[str, Any]:
    return clients.firewall.block_ip(ip=params["ip"], reason=params["reason"])


def _kill_process(params: dict[str, Any], clients: Clients) -> dict[str, Any]:
    return clients.edr.kill_process(
        host=params["host"],
        process_id=params["process_id"],
        reason=params["reason"],
    )


def _quarantine_file(params: dict[str, Any], clients: Clients) -> dict[str, Any]:
    return clients.edr.quarantine_file(
        host=params["host"],
        file_hash=params["file_hash"],
        reason=params["reason"],
    )


def _isolate_host(params: dict[str, Any], clients: Clients) -> dict[str, Any]:
    return clients.edr.isolate_host(host=params["host"], reason=params["reason"])


def _disable_user(params: dict[str, Any], clients: Clients) -> dict[str, Any]:
    return clients.directory.disable_user(
        username=params["username"], reason=params["reason"]
    )


def _force_password_reset(params: dict[str, Any], clients: Clients) -> dict[str, Any]:
    return clients.directory.force_password_reset(username=params["username"])


def _notify(params: dict[str, Any], clients: Clients) -> dict[str, Any]:
    return clients.notifier.send(
        channel=params["channel"],
        message=params["message"],
        severity=params.get("severity", "medium"),
    )


REGISTRY: dict[str, ActionHandler] = {
    "firewall.block_ip": _block_ip,
    "edr.kill_process": _kill_process,
    "edr.quarantine_file": _quarantine_file,
    "edr.isolate_host": _isolate_host,
    "directory.disable_user": _disable_user,
    "directory.force_password_reset": _force_password_reset,
    "notifier.send": _notify,
}


def get_handler(action_type: str) -> ActionHandler:
    if action_type not in REGISTRY:
        raise KeyError(f"unknown action type: '{action_type}'")
    return REGISTRY[action_type]
