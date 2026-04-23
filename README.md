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

The demo loads the brute force playbook and simulates 50 failed logins from `185.220.101.42` against `jsmith`. You'll see each action dispatched, each mock API call, and the final audit log.

Run the tests:

```bash
pip install -e ".[dev]"
pytest
```

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

- **Phase 1 (this):** single-process engine, YAML playbooks, mock clients, SQLite audit, CLI demo
- **Phase 2:** SIEM ingestion (Splunk/ELK), real vendor SDK calls, PostgreSQL audit, webhook approval UI
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
    clients/
      base.py              # Protocol interfaces
      firewall.py          # Palo Alto (mock)
      edr.py               # CrowdStrike (mock)
      directory.py         # Active Directory (mock)
      notifier.py          # Slack (mock)
  tests/
  demo.py
```
