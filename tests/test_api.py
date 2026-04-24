from fastapi.testclient import TestClient

from src.api import create_app


def _client():
    return TestClient(create_app())


def test_index_lists_endpoints():
    response = _client().get("/")
    assert response.status_code == 200
    body = response.json()
    assert body["service"] == "incident-response-automation"
    assert body["playbooks_loaded"] == 3


def test_list_playbooks_returns_three():
    response = _client().get("/playbooks")
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 3
    names = {pb["name"] for pb in body["playbooks"]}
    assert names == {
        "brute_force_attack",
        "suspicious_process",
        "data_exfiltration",
    }


def test_get_single_playbook():
    response = _client().get("/playbooks/brute_force_attack")
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "brute_force_attack"
    assert body["severity"] == "high"
    assert body["trigger"]["threshold"] == 50


def test_get_unknown_playbook_returns_404():
    response = _client().get("/playbooks/does_not_exist")
    assert response.status_code == 404


def test_trigger_brute_force_runs_playbook_and_returns_outcomes():
    client = _client()
    alert = {
        "incident_id": "INC-API-1",
        "source_ip": "8.8.8.8",
        "target_user": "alice",
        "event_count": 60,
        "window_seconds": 300,
    }

    response = client.post("/alerts/brute_force_attack", json=alert)

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == "INC-API-1"
    assert body["playbook"] == "brute_force_attack"
    assert body["actions_succeeded"] == 4
    assert body["actions_total"] == 4
    assert {o["action_id"] for o in body["outcomes"]} == {
        "block_source_ip",
        "lock_user_account",
        "force_password_reset",
        "notify_soc_channel",
    }


def test_trigger_unknown_playbook_returns_404():
    response = _client().post("/alerts/no_such_playbook", json={})
    assert response.status_code == 404


def test_audit_trail_for_completed_incident():
    client = _client()
    alert = {
        "incident_id": "INC-API-2",
        "source_ip": "9.9.9.9",
        "target_user": "bob",
        "event_count": 75,
        "window_seconds": 300,
    }
    client.post("/alerts/brute_force_attack", json=alert)

    response = client.get("/incidents/INC-API-2/audit")

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == "INC-API-2"
    assert body["event_count"] == 4
    assert all(e["status"] == "success" for e in body["events"])


def test_audit_trail_for_unknown_incident_returns_404():
    response = _client().get("/incidents/INC-NOTHING/audit")
    assert response.status_code == 404


def test_trigger_with_missing_template_field_returns_400():
    client = _client()
    # missing target_user -- the playbook references {{ alert.target_user }}
    bad_alert = {
        "incident_id": "INC-API-3",
        "source_ip": "1.1.1.1",
        "event_count": 60,
        "window_seconds": 300,
    }
    response = client.post("/alerts/brute_force_attack", json=bad_alert)
    assert response.status_code == 400
