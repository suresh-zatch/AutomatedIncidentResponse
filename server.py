#!/usr/bin/env python3
"""
Automated Incident Response Pipeline - Interactive Web API Server
-----------------------------------------------------------------
Flask REST API that powers the live interactive demo in demo_video.html.
Wraps MultiCloudIncidentResponder so the browser can trigger real
containment runs and stream back structured JSON results.
"""

import sys
import json
import datetime

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

try:
    from flask import Flask, request, jsonify
    from flask_cors import CORS
except ImportError:
    print("[ERROR] Flask not installed. Run: pip install flask flask-cors")
    sys.exit(1)

from incident_responder import MultiCloudIncidentResponder

app = Flask(__name__)
CORS(app)  # Allow demo_video.html (file://) to call localhost

# ── Preset scenarios matching test_manual.py ──────────────────────────────────

PRESET_SCENARIOS = {
    "1": {
        "label": "AWS — EC2 Malware Isolation",
        "cloud_provider": "aws",
        "type": "GUARDDUTY_MALWARE_EXECUTION",
        "resource_type": "compute",
        "resource_id": "i-0a8b9c1d2e3f45678",
        "account_id": "123456789012",
        "region": "us-west-2",
    },
    "2": {
        "label": "AWS — IAM Credential Revocation",
        "cloud_provider": "aws",
        "type": "UNAUTHORIZED_CREDENTIAL_EXFILTRATION",
        "resource_type": "iam",
        "resource_id": "sec-analyst-temp",
        "account_id": "123456789012",
        "region": "global",
    },
    "3": {
        "label": "GCP — GCE Firewall Quarantine",
        "cloud_provider": "gcp",
        "type": "SCC_SUSPICIOUS_EXECUTION",
        "resource_type": "compute",
        "resource_id": "gce-prod-app-01",
        "project_id": "gcp-prod-sec-project",
        "region": "us-central1-a",
    },
    "4": {
        "label": "GCP — Service Account Role Stripping",
        "cloud_provider": "gcp",
        "type": "SCC_EXPOSED_SERVICE_ACCOUNT_KEY",
        "resource_type": "iam",
        "resource_id": "svc-deploy@gcp-prod.iam.gserviceaccount.com",
        "project_id": "gcp-prod-sec-project",
    },
    "5": {
        "label": "Azure — VM NSG Isolation",
        "cloud_provider": "azure",
        "type": "SENTINEL_MALICIOUS_C2_TRAFFIC",
        "resource_type": "compute",
        "resource_id": "vm-az-prod-web-01",
        "subscription_id": "00000000-0000-0000-0000-000000000000",
        "location": "eastus",
    },
    "6": {
        "label": "Azure — Entra ID Account Lockout",
        "cloud_provider": "azure",
        "type": "SENTINEL_IMPOSSIBLE_TRAVEL",
        "resource_type": "iam",
        "resource_id": "alex.analyst@company.com",
        "subscription_id": "00000000-0000-0000-0000-000000000000",
    },
}


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "pipeline": "AutomatedIncidentResponse",
        "version": "2.0.0-multi-cloud-enterprise",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "supported_clouds": ["AWS", "GCP", "AZURE"],
    })


@app.route("/api/scenarios", methods=["GET"])
def scenarios():
    return jsonify(PRESET_SCENARIOS)


@app.route("/api/trigger", methods=["POST"])
def trigger():
    """
    Trigger a containment run.

    Body (JSON):
      scenario_id: "1"-"6"  (use preset) OR
      alert: { cloud_provider, resource_type, resource_id, ... } (custom)
      resource_id: optional override for the preset resource_id
    """
    data = request.get_json(force=True, silent=True) or {}

    scenario_id = str(data.get("scenario_id", ""))
    custom_alert = data.get("alert")
    resource_id_override = data.get("resource_id", "").strip()

    # Build the alert payload
    if custom_alert and isinstance(custom_alert, dict):
        alert = custom_alert
    elif scenario_id in PRESET_SCENARIOS:
        alert = dict(PRESET_SCENARIOS[scenario_id])
        alert.pop("label", None)
        if resource_id_override:
            alert["resource_id"] = resource_id_override
    else:
        return jsonify({"error": "Provide scenario_id (1-6) or a custom alert payload."}), 400

    # Auto-generate incident ID
    import uuid
    alert.setdefault("id", f"WEB-{uuid.uuid4().hex[:8].upper()}")

    try:
        engine = MultiCloudIncidentResponder(dry_run=True)
        result = engine.process_alert(alert)
        return jsonify({
            "ok": True,
            "trigger_payload": alert,
            "containment_result": result,
            "server_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        })
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 422
    except Exception as e:
        return jsonify({"ok": False, "error": f"Internal engine error: {e}"}), 500


if __name__ == "__main__":
    print("=" * 70)
    print("  Automated Incident Response — Interactive API Server")
    print("  Listening at: http://localhost:5001")
    print("  Open demo_video.html in your browser to use the live terminal.")
    print("=" * 70)
    app.run(host="0.0.0.0", port=5001, debug=False)
