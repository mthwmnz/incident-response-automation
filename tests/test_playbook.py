from pathlib import Path

from src.playbook import load_playbook, load_playbooks


PLAYBOOKS = Path(__file__).parent.parent / "playbooks"


def test_load_brute_force_playbook():
    pb = load_playbook(PLAYBOOKS / "brute_force_attack.yml")

    assert pb.name == "brute_force_attack"
    assert pb.severity == "high"
    assert pb.trigger.threshold == 50
    assert pb.trigger.window_seconds == 300
    assert len(pb.actions) == 4
    assert pb.actions[0].type == "firewall.block_ip"


def test_load_all_playbooks():
    pbs = load_playbooks(PLAYBOOKS)
    assert set(pbs) == {
        "brute_force_attack",
        "suspicious_process",
        "data_exfiltration",
    }


def test_data_exfiltration_has_approval_gate():
    pb = load_playbook(PLAYBOOKS / "data_exfiltration.yml")
    gated = [a for a in pb.actions if a.requires_approval]

    assert len(gated) == 1
    assert gated[0].id == "isolate_host"
    assert gated[0].approval is not None
    assert gated[0].approval.escalate_to == "#ir-oncall"


def test_suspicious_process_kill_aborts_on_failure():
    pb = load_playbook(PLAYBOOKS / "suspicious_process.yml")
    kill = next(a for a in pb.actions if a.id == "kill_process")
    assert kill.on_failure == "abort"
