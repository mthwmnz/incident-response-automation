"""End-to-end demo: simulates a brute force attack and runs the playbook.

Run:
    python demo.py            # full speed (test mode, < 1 second)
    python demo.py --slow     # paced for screen recording / video walkthrough
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.audit import AuditLog
from src.clients.base import Clients
from src.clients.directory import MockActiveDirectory
from src.clients.edr import MockCrowdStrike
from src.clients.firewall import MockPaloAlto
from src.clients.notifier import MockSlack
from src.engine import ActionOutcome, PlaybookEngine
from src.playbook import Action, load_playbook


def _banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--slow",
        action="store_true",
        help="add deliberate pauses so the demo is recordable as a video",
    )
    args = parser.parse_args()

    section_pause = 1.5 if args.slow else 0.0
    action_pause = 1.5 if args.slow else 0.0
    line_pause = 0.4 if args.slow else 0.0

    def pause(seconds: float) -> None:
        if seconds:
            time.sleep(seconds)

    _banner("INCIDENT RESPONSE AUTOMATION -- DEMO")
    print("Scenario: 53 failed logins from 185.220.101.42 against user 'jsmith'")
    print("in a 300-second window. Brute force playbook will now fire.")
    pause(section_pause)

    playbook_path = Path(__file__).parent / "playbooks" / "brute_force_attack.yml"
    playbook = load_playbook(playbook_path)
    print(
        f"\nLoaded playbook: {playbook.name} v{playbook.version} "
        f"(severity={playbook.severity}, target MTTC={playbook.mttc_target_seconds}s)"
    )
    pause(section_pause)

    firewall = MockPaloAlto()
    edr = MockCrowdStrike()
    directory = MockActiveDirectory()
    slack = MockSlack()
    clients = Clients(
        firewall=firewall, edr=edr, directory=directory, notifier=slack
    )
    audit = AuditLog(":memory:")

    counter = {"i": 0, "n": len(playbook.actions)}

    def on_start(action: Action, params: dict) -> None:
        counter["i"] += 1
        print(f"\n[{counter['i']}/{counter['n']}] {action.id}  ({action.type})")
        for k, v in params.items():
            v_display = str(v).replace("\n", " / ")
            if len(v_display) > 70:
                v_display = v_display[:67] + "..."
            print(f"      {k}: {v_display}")
        pause(line_pause)

    def on_end(outcome: ActionOutcome) -> None:
        marker = {
            "success": "OK",
            "failed": "FAIL",
            "denied": "DENIED",
        }.get(outcome.status, outcome.status.upper())
        print(f"      --> {marker} ({outcome.latency_ms:.1f} ms)")
        pause(action_pause)

    engine = PlaybookEngine(
        clients=clients,
        audit=audit,
        on_action_start=on_start,
        on_action_end=on_end,
    )

    alert = {
        "incident_id": "INC-2026-04-21-0001",
        "source_ip": "185.220.101.42",
        "target_user": "jsmith",
        "event_count": 53,
        "window_seconds": 300,
    }

    _banner("EXECUTING PLAYBOOK")
    pause(section_pause)
    result = engine.execute(playbook, alert)
    pause(section_pause)

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
    pause(section_pause)

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
        pause(line_pause)
    pause(section_pause)

    _banner("VENDOR SIDE EFFECTS")
    print(f"Palo Alto blocked IPs:     {list(firewall.blocked.keys())}")
    pause(line_pause)
    print(f"AD disabled users:         {list(directory.disabled_users.keys())}")
    pause(line_pause)
    print(
        f"AD password resets forced: "
        f"{[r['user'] for r in directory.password_resets]}"
    )
    pause(line_pause)
    print(f"Slack messages sent:       {len(slack.sent)}")


if __name__ == "__main__":
    main()
