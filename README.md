# Incident Response Automation

Automated SOC playbook engine. Ingests alerts, runs YAML-defined response playbooks against firewall / EDR / directory APIs, and produces a full audit trail. Built to reduce mean time to contain (MTTC) from 45 minutes of manual work to under 2 minutes.

## What it does

- Loads playbooks declared in plain YAML — readable by analysts, not just engineers
- Dispatches actions to swappable vendor clients (Palo Alto firewall, CrowdStrike EDR, Active Directory, Slack)
- Gates high-risk actions behind an approval step
- Writes every decision and API call to a SQLite audit log
- Ships with a demo that simulates a brute force attack end-to-end

## Playbooks included

| Playbook | Trigger | Response |
|---|---|---|
| `brute_force_attack` | 50+ failed logins in 5 min | Block IP, lock account, force password reset, notify SOC |
| `suspicious_process` | EDR flag on unknown binary in temp | Kill process, quarantine file, notify |
| `data_exfiltration` | Large outbound transfer to unknown IP | *Approval gate* → isolate host, block destination, page IR |

## Quick start

```bash
pip install -e .
python demo.py
```

The demo loads the brute force playbook and simulates 53 failed logins from `185.220.101.42` against `jsmith`. You'll see each action dispatched, each mock API call, and the final audit log.

Run the tests:

```bash
pip install -e ".[dev]"
pytest
```

## Real Slack notifications

By default the engine prints Slack messages to stdout (mock mode). To send to a real Slack channel, set `SLACK_WEBHOOK_URL` before launching:

```bash
# bash / git-bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T0XXX/B0XXX/XXXX"
python serve.py

# PowerShell
$env:SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T0XXX/B0XXX/XXXX"
python serve.py
```

To create a webhook URL: <https://api.slack.com/messaging/webhooks> → "Create New App" → enable Incoming Webhooks → "Add New Webhook to Workspace" → pick a channel → copy the URL.

The engine logs which notifier it's using at startup. No code changes are required to switch between mock and real -- the [build_notifier()](src/clients/notifier.py) factory checks the env var.

## Running as an HTTP service

The engine also runs as a FastAPI service so SIEMs (Splunk, ELK, CrowdStrike) can POST alerts and trigger playbooks via webhook:

```bash
python serve.py
```

Then in another terminal:

```bash
# list loaded playbooks
curl http://127.0.0.1:8000/playbooks

# trigger the brute force playbook
curl -X POST http://127.0.0.1:8000/alerts/brute_force_attack \
    -H "Content-Type: application/json" \
    -d '{"incident_id":"INC-001","source_ip":"1.2.3.4","target_user":"jsmith","event_count":75,"window_seconds":300}'

# read the audit trail for an incident
curl http://127.0.0.1:8000/incidents/INC-001/audit
```

Interactive Swagger / OpenAPI docs auto-generated at <http://127.0.0.1:8000/docs>.

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Service health + endpoint index |
| `/playbooks` | GET | List loaded playbooks with metadata |
| `/playbooks/{name}` | GET | Get a single playbook definition |
| `/alerts/{playbook_name}` | POST | Trigger a playbook with an alert payload |
| `/incidents/{id}/audit` | GET | Audit trail for one incident |
| `/approvals` | GET | List pending approvals |
| `/approvals/{token}` | GET | Get a single pending approval |
| `/approvals/{token}` | POST | Decide on a pending approval (approve / deny) |

## Approval workflow for high-risk actions

Playbook actions can declare `requires_approval: true` (see [data_exfiltration.yml](playbooks/data_exfiltration.yml) for the canonical example). When the engine reaches such an action, it:

1. Records a `pending_approval` event in the audit log
2. Persists the suspended state in the `pending_approvals` table (survives restarts)
3. Sends a Slack notification to the action's `escalate_to` channel with the approval URL embedded
4. Returns immediately to the caller with `status: "suspended_pending_approval"` and a token

An analyst then approves (or denies) by POSTing to the callback URL:

```bash
# Trigger the playbook -- get back a token
curl -X POST http://127.0.0.1:8000/alerts/data_exfiltration \
    -H "Content-Type: application/json" \
    -d '{"incident_id":"INC-EXFIL-1","host":"WIN-FIN-03","destination_ip":"203.0.113.42","bytes_transferred":2400000000}'

# Response includes a token + approval_url:
# { "status":"suspended_pending_approval", "pending_approval_token":"abc-123-...",
#   "approval_url":"http://127.0.0.1:8000/approvals/abc-123-..." }

# Approve -- engine resumes, runs the gated action, runs any actions after it
curl -X POST http://127.0.0.1:8000/approvals/abc-123-... \
    -H "Content-Type: application/json" \
    -d '{"approved":true,"approver":"@alice","reason":"verified incident"}'

# Or deny -- engine aborts the playbook
curl -X POST http://127.0.0.1:8000/approvals/abc-123-... \
    -H "Content-Type: application/json" \
    -d '{"approved":false,"approver":"@alice","reason":"false positive"}'
```

The audit trail captures the full lifecycle: `pending_approval` -> `success` (or `denied`), with the approver's name and reason recorded as the `actor` of the resolving event. Pending approvals are queryable any time via `GET /approvals`.

This design is the production shape of approval-gated automation -- a Slack-buttons UI is a thin wrapper on top (the button click POSTs to the same endpoint).

## Architecture

```
  Alert  ->  Rules Engine  ->  Actions  ->  Vendor APIs
                 |                |              |
                 v                v              v
        +-----------------------------------------------+
        |            SQLite Audit Log                   |
        +-----------------------------------------------+
                 |
                 v
            Slack / Jira
```

- **Rules engine** ([src/engine.py](src/engine.py)) — loads YAML playbooks, dispatches actions in order, respects approval gates, writes audit events.
- **Action registry** ([src/actions.py](src/actions.py)) — maps `firewall.block_ip`, `edr.kill_process`, etc. to handler functions that call the right client.
- **Client adapters** ([src/clients/](src/clients/)) — `Protocol`-based interfaces with mock implementations. Real SDK calls drop in as a direct swap.
- **Audit log** ([src/audit.py](src/audit.py)) — SQLite schema with one row per action dispatched, including inputs, outputs, latency, and status.
- **Approval gates** ([src/approvals.py](src/approvals.py)) — pluggable approval providers (auto-approve for tests, CLI prompt for demos, webhook for production).

## Why mocks first

Every vendor integration is behind a `Protocol` interface with a mock implementation. This means:

1. The project runs end-to-end without any vendor credentials
2. Swapping `MockPaloAlto` for a real `PaloAltoClient` is a one-line change in [demo.py](demo.py)
3. Tests stay fast and hermetic — no network, no sandbox setup

Real CrowdStrike Falcon / Palo Alto PAN-OS / AD integrations go in Phase 2 once there's sandbox access.

## Design decisions worth calling out

- **Plain YAML, no Jinja.** Playbooks use a restricted `{{ alert.field }}` template syntax — no expressions, no code execution. This keeps playbooks safe for analysts to edit without opening a code-injection surface.
- **Every action emits exactly one audit row**, including approvals, denials, and failures. `audit_events.incident_id` is the single key for reconstructing what happened.
- **Approvals are data, not hardcoded.** A playbook action marks `requires_approval: true` and provides an escalation channel; the engine calls a pluggable `ApprovalProvider`. Swappable for a webhook-based UI in Phase 2.
- **on_failure is per-action.** Some actions are independent (notifying Slack after blocking an IP — the block still matters if Slack is down). Others are dependent (don't quarantine a file if the process it belonged to wasn't killed). YAML declares the policy.

## Roadmap

- **Phase 1 (done):** single-process engine, YAML playbooks, mock clients, SQLite audit, CLI demo
- **Phase 2 (in progress):** ~~FastAPI service with SIEM webhook target~~, ~~real Slack notifications~~, ~~webhook approval flow with persistent pending state~~, real vendor SDK calls (CrowdStrike Falcon next), PostgreSQL audit
- **Phase 3:** Celery task queue, Prometheus metrics, Docker Compose, retry/backoff policies

## Project structure

```
incident-response-automation/
  playbooks/               # YAML playbook definitions (analyst-editable)
  src/
    engine.py              # rules engine — orchestration
    playbook.py            # YAML loader + schema
    actions.py             # action registry
    audit.py               # SQLite audit log
    approvals.py           # manual approval gates
    templating.py          # safe parameter substitution
    api.py                 # FastAPI HTTP service
    clients/
      base.py              # Protocol interfaces
      firewall.py          # Palo Alto (mock)
      edr.py               # CrowdStrike (mock)
      directory.py         # Active Directory (mock)
      notifier.py          # Slack (mock)
  tests/
  demo.py                  # CLI demo
  serve.py                 # HTTP service entrypoint
```
