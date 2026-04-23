"""End-to-end demo: simulates a brute force attack and runs the playbook.

Run:
    python demo.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.audit import AuditLog
from src.clients.base import Clients
from src.clients.directory import MockActiveDirectory
from src.clients.edr import MockCrowdStrike
from src.clients.firewall import MockPaloAlto
from src.clients.notifier import MockSlack
from src.engine import PlaybookEngine
from src.playbook import load_playbook


def _banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main() -> None:
    _banner("INCIDENT RESPONSE AUTOMATION -- DEMO")
    print("Scenario: 53 failed logins from 185.220.101.42 against user 'jsmith'")
    print("in a 300-second window. Brute force playbook will now fire.")

    playbook_path = Path(__file__).parent / "playbooks" / "brute_force_attack.yml"
    playbook = load_playbook(playbook_path)
    print(
        f"\nLoaded playbook: {playbook.name} v{playbook.version} "
        f"(severity={playbook.severity}, target MTTC={playbook.mttc_target_seconds}s)"
    )

    firewall = MockPaloAlto()
    edr = MockCrowdStrike()
    directory = MockActiveDirectory()
    slack = MockSlack()
    clients = Clients(
        firewall=firewall, edr=edr, directory=directory, notifier=slack
    )

    audit = AuditLog(":memory:")
    engine = PlaybookEngine(clients=clients, audit=audit)

    alert = {
        "incident_id": "INC-2026-04-21-0001",
        "source_ip": "185.220.101.42",
        "target_user": "jsmith",
        "event_count": 53,
        "window_seconds": 300,
    }

    _banner("EXECUTING PLAYBOOK")
    result = engine.execute(playbook, alert)

    _banner("EXECUTION SUMMARY")
    print(f"Incident:   {result.incident_id}")
    print(f"Playbook:   {result.playbook_name}")
    print(
        f"Total MTTC: {result.total_latency_ms:.1f} ms "
        f"(target: {playbook.mttc_target_seconds * 1000} ms)"
    )
    print(f"Actions:    {result.success_count}/{len(result.outcomes)} succeeded")
    for o in result.outcomes:
        print(
            f"  - {o.action_id:<25} {o.status:<10} {o.latency_ms:>7.1f} ms"
        )

    _banner("AUDIT TRAIL")
    for event in audit.events_for_incident(alert["incident_id"]):
        print(
            f"[{event['timestamp']}] {event['action_id']} "
            f"({event['action_type']}) -> {event['status']}"
        )
        params = json.loads(event["action_params"])
        for k, v in params.items():
            v_display = str(v).replace("\n", " / ")
            if len(v_display) > 80:
                v_display = v_display[:77] + "..."
            print(f"    {k}: {v_display}")

    _banner("VENDOR SIDE EFFECTS")
    print(f"Palo Alto blocked IPs:     {list(firewall.blocked.keys())}")
    print(f"AD disabled users:         {list(directory.disabled_users.keys())}")
    print(
        f"AD password resets forced: "
        f"{[r['user'] for r in directory.password_resets]}"
    )
    print(f"Slack messages sent:       {len(slack.sent)}")


if __name__ == "__main__":
    main()
