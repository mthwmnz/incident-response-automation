"""Run the playbook engine HTTP service.

Run:
    python serve.py

Then in another terminal:
    curl http://127.0.0.1:8000/
    curl http://127.0.0.1:8000/playbooks
    curl -X POST http://127.0.0.1:8000/alerts/brute_force_attack \
        -H "Content-Type: application/json" \
        -d '{"incident_id":"INC-001","source_ip":"1.2.3.4","target_user":"jsmith","event_count":75,"window_seconds":300}'
    curl http://127.0.0.1:8000/incidents/INC-001/audit

Interactive API docs at http://127.0.0.1:8000/docs
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import uvicorn

from src.api import create_app


AUDIT_DB = Path(__file__).parent / "audit.db"


if __name__ == "__main__":
    import os
    print(f"Audit log: {AUDIT_DB} (persisted across restarts)")
    if os.environ.get("SLACK_WEBHOOK_URL", "").strip():
        print("Notifier:  SlackWebhook (real -- SLACK_WEBHOOK_URL is set)")
    else:
        print("Notifier:  MockSlack (set SLACK_WEBHOOK_URL to use real Slack)")
    app = create_app(audit_db=str(AUDIT_DB))
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
