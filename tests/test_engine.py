from pathlib import Path

from src.approvals import auto_approve, auto_deny
from src.audit import AuditLog
from src.clients.base import Clients
from src.clients.directory import MockActiveDirectory
from src.clients.edr import MockCrowdStrike
from src.clients.firewall import MockPaloAlto
from src.clients.notifier import MockSlack
from src.engine import PlaybookEngine
from src.playbook import load_playbook


PLAYBOOKS = Path(__file__).parent.parent / "playbooks"


def _engine(approval=auto_approve):
    clients = Clients(
        firewall=MockPaloAlto(),
        edr=MockCrowdStrike(),
        directory=MockActiveDirectory(),
        notifier=MockSlack(),
    )
    engine = PlaybookEngine(
        clients=clients,
        audit=AuditLog(":memory:"),
        approval_provider=approval,
    )
    return clients, engine


def test_brute_force_playbook_blocks_ip_and_locks_user():
    clients, engine = _engine()
    pb = load_playbook(PLAYBOOKS / "brute_force_attack.yml")
    alert = {
        "incident_id": "INC-TEST-1",
        "source_ip": "1.2.3.4",
        "target_user": "alice",
        "event_count": 75,
        "window_seconds": 300,
    }

    result = engine.execute(pb, alert)

    assert result.all_succeeded
    assert "1.2.3.4" in clients.firewall.blocked
    assert "alice" in clients.directory.disabled_users
    assert any(r["user"] == "alice" for r in clients.directory.password_resets)
    assert len(clients.notifier.sent) == 1


def test_suspicious_process_kills_and_quarantines():
    clients, engine = _engine()
    pb = load_playbook(PLAYBOOKS / "suspicious_process.yml")
    alert = {
        "incident_id": "INC-TEST-2",
        "host": "WIN-ACCT-07",
        "process_id": 4821,
        "process_name": "svchosst.exe",
        "file_hash": "a" * 64,
    }

    result = engine.execute(pb, alert)

    assert result.all_succeeded
    assert len(clients.edr.killed_processes) == 1
    assert clients.edr.killed_processes[0]["host"] == "WIN-ACCT-07"
    assert len(clients.edr.quarantined_files) == 1


def test_data_exfiltration_approval_denied_aborts_isolation():
    clients, engine = _engine(approval=auto_deny)
    pb = load_playbook(PLAYBOOKS / "data_exfiltration.yml")
    alert = {
        "incident_id": "INC-TEST-3",
        "host": "WIN-FIN-03",
        "destination_ip": "203.0.113.7",
        "bytes_transferred": 2_400_000_000,
    }

    result = engine.execute(pb, alert)

    assert "203.0.113.7" in clients.firewall.blocked
    assert "WIN-FIN-03" not in clients.edr.isolated_hosts
    isolate = next(o for o in result.outcomes if o.action_id == "isolate_host")
    assert isolate.status == "denied"
    # abort on denial -> notify_containment never runs
    assert not any(o.action_id == "notify_containment" for o in result.outcomes)


def test_data_exfiltration_approval_granted_isolates_host():
    clients, engine = _engine(approval=auto_approve)
    pb = load_playbook(PLAYBOOKS / "data_exfiltration.yml")
    alert = {
        "incident_id": "INC-TEST-4",
        "host": "WIN-FIN-03",
        "destination_ip": "203.0.113.8",
        "bytes_transferred": 2_400_000_000,
    }

    result = engine.execute(pb, alert)

    assert result.all_succeeded
    assert "WIN-FIN-03" in clients.edr.isolated_hosts


def test_audit_log_records_every_action():
    clients, engine = _engine()
    pb = load_playbook(PLAYBOOKS / "brute_force_attack.yml")
    alert = {
        "incident_id": "INC-AUDIT-1",
        "source_ip": "9.9.9.9",
        "target_user": "bob",
        "event_count": 60,
        "window_seconds": 300,
    }

    engine.execute(pb, alert)

    events = engine.audit.events_for_incident("INC-AUDIT-1")
    assert len(events) == 4
    assert {e["action_id"] for e in events} == {
        "block_source_ip",
        "lock_user_account",
        "force_password_reset",
        "notify_soc_channel",
    }
    assert all(e["status"] == "success" for e in events)


def test_mttc_is_recorded_for_each_action():
    _, engine = _engine()
    pb = load_playbook(PLAYBOOKS / "brute_force_attack.yml")
    alert = {
        "incident_id": "INC-MTTC-1",
        "source_ip": "8.8.8.8",
        "target_user": "carol",
        "event_count": 55,
        "window_seconds": 300,
    }

    result = engine.execute(pb, alert)

    assert result.total_latency_ms > 0
    for outcome in result.outcomes:
        assert outcome.latency_ms >= 0
