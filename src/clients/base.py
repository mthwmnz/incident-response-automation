"""Vendor client interfaces.

Mocks implement these for local demos and tests; real SDK adapters drop in
for production without any engine-side changes.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class FirewallClient(Protocol):
    def block_ip(self, ip: str, reason: str) -> dict[str, Any]: ...
    def unblock_ip(self, ip: str) -> dict[str, Any]: ...


@runtime_checkable
class EDRClient(Protocol):
    def kill_process(
        self, host: str, process_id: str | int, reason: str
    ) -> dict[str, Any]: ...
    def quarantine_file(
        self, host: str, file_hash: str, reason: str
    ) -> dict[str, Any]: ...
    def isolate_host(self, host: str, reason: str) -> dict[str, Any]: ...


@runtime_checkable
class DirectoryClient(Protocol):
    def disable_user(self, username: str, reason: str) -> dict[str, Any]: ...
    def force_password_reset(self, username: str) -> dict[str, Any]: ...


@runtime_checkable
class Notifier(Protocol):
    def send(
        self, channel: str, message: str, severity: str
    ) -> dict[str, Any]: ...


class Clients:
    """Bundle of vendor clients passed to action handlers."""

    def __init__(
        self,
        firewall: FirewallClient,
        edr: EDRClient,
        directory: DirectoryClient,
        notifier: Notifier,
    ) -> None:
        self.firewall = firewall
        self.edr = edr
        self.directory = directory
        self.notifier = notifier
