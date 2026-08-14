#!/usr/bin/env python3
"""
Automated Incident Response Pipeline - Interactive Manual Testing CLI
---------------------------------------------------------------------
Allows security engineers to manually trigger containment logic with
custom resource IDs, alert types, and execution modes.
"""

import json
import sys
from incident_responder import IncidentResponder


def main():
    print("==========================================================================")
    print(" 🛡️ AUTOMATED INCIDENT RESPONSE PIPELINE - MANUAL TEST BENCH")
    print("==========================================================================")
    print("Choose an incident type to test:\n")
    print("  [1] Compute Instance Isolation (e.g., Malware on EC2 / GCE Instance)")
    print("  [2] IAM User Session Revocation (e.g., Compromised Access Keys)")
    print("  [3] Custom Alert Payload (JSON Input)")
    print("  [4] Exit")
    print("--------------------------------------------------------------------------")

    choice = input("\nSelect option [1-4]: ").strip()

    if choice == "1":
        instance_id = input("Enter target Instance ID (default: i-0a8b9c1d2e3f45678): ").strip() or "i-0a8b9c1d2e3f45678"
        region = input("Enter AWS Region (default: us-west-2): ").strip() or "us-west-2"
        dry_run_input = input("Enable Dry-Run mode? (y/n, default: n): ").strip().lower()
        dry_run = dry_run_input != "n"

        alert = {
            "id": "MANUAL-TEST-ALERT-001",
            "severity": "CRITICAL",
            "type": "MALWARE_EXECUTION_DETECTED",
            "resource_type": "compute",
            "resource_id": instance_id,
            "account_id": "123456789012",
            "region": region
        }

    elif choice == "2":
        username = input("Enter target IAM Username (default: sec-analyst-temp): ").strip() or "sec-analyst-temp"
        dry_run_input = input("Enable Dry-Run mode? (y/n, default: n): ").strip().lower()
        dry_run = dry_run_input != "n"

        alert = {
            "id": "MANUAL-TEST-ALERT-002",
            "severity": "CRITICAL",
            "type": "UNAUTHORIZED_CREDENTIAL_EXFILTRATION",
            "resource_type": "iam",
            "resource_id": username,
            "account_id": "123456789012",
            "region": "global"
        }

    elif choice == "3":
        print("\nPaste your JSON alert payload below:")
        raw_json = input("> ").strip()
        try:
            alert = json.loads(raw_json)
            dry_run = False
        except Exception as e:
            print(f"Error parsing JSON: {e}")
            sys.exit(1)

    else:
        print("Exiting test bench.")
        sys.exit(0)

    print("\n--------------------------------------------------------------------------")
    print("▶ EXECUTING AUTOMATED INCIDENT RESPONSE ENGINE...")
    print("--------------------------------------------------------------------------\n")

    responder = IncidentResponder(dry_run=dry_run)
    result = responder.process_alert(alert)

    print("\n--------------------------------------------------------------------------")
    print("✅ CONTAINMENT EXECUTION RESULT:")
    print("--------------------------------------------------------------------------")
    print(json.dumps(result, indent=2))
    print("==========================================================================\n")


if __name__ == "__main__":
    main()
