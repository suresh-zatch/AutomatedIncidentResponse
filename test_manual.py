#!/usr/bin/env python3
"""
Automated Incident Response Pipeline - Multi-Cloud Interactive Manual Test Bench
-------------------------------------------------------------------------------
Supports manual simulation for AWS, Google Cloud Platform (GCP), and Microsoft Azure.
"""

import json
import sys
from incident_responder import MultiCloudIncidentResponder


def main():
    print("==========================================================================")
    print(" 🛡️ MULTI-CLOUD AUTOMATED INCIDENT RESPONSE - MANUAL TEST BENCH")
    print("==========================================================================")
    print("Select Cloud Provider & Incident Scenario:\n")
    print("  [1] AWS - EC2 Instance Malware Isolation (Security Group Swap & EBS Snapshot)")
    print("  [2] AWS - IAM User Credential Revocation (DenyAll Policy & Key Deactivation)")
    print("  [3] GCP - GCE Compute Instance Firewall Quarantine (Network Tag Swap & Disk Snapshot)")
    print("  [4] GCP - Service Account Access Token Revocation & Role Stripping")
    print("  [5] Azure - Virtual Machine NSG Isolation & Managed Disk Snapshot")
    print("  [6] Azure - Entra ID (Azure AD) Account Lockout & Session Revocation")
    print("  [7] Custom JSON Webhook Alert Payload")
    print("  [8] Exit")
    print("--------------------------------------------------------------------------")

    choice = input("\nSelect option [1-8]: ").strip()

    if choice == "1":
        instance_id = input("Enter AWS Instance ID (default: i-0a8b9c1d2e3f45678): ").strip() or "i-0a8b9c1d2e3f45678"
        alert = {
            "id": "MANUAL-AWS-COMPUTE-001",
            "cloud_provider": "aws",
            "severity": "CRITICAL",
            "type": "GUARDDUTY_MALWARE_EXECUTION",
            "resource_type": "compute",
            "resource_id": instance_id,
            "account_id": "123456789012",
            "region": "us-west-2"
        }

    elif choice == "2":
        username = input("Enter AWS IAM Username (default: sec-analyst-temp): ").strip() or "sec-analyst-temp"
        alert = {
            "id": "MANUAL-AWS-IAM-002",
            "cloud_provider": "aws",
            "severity": "CRITICAL",
            "type": "UNAUTHORIZED_CREDENTIAL_EXFILTRATION",
            "resource_type": "iam",
            "resource_id": username,
            "account_id": "123456789012",
            "region": "global"
        }

    elif choice == "3":
        vm_name = input("Enter GCP GCE Instance Name (default: gce-prod-app-01): ").strip() or "gce-prod-app-01"
        alert = {
            "id": "MANUAL-GCP-COMPUTE-003",
            "cloud_provider": "gcp",
            "severity": "CRITICAL",
            "type": "SCC_SUSPICIOUS_EXECUTION",
            "resource_type": "compute",
            "resource_id": vm_name,
            "project_id": "gcp-prod-sec-project",
            "region": "us-central1-a"
        }

    elif choice == "4":
        sa_email = input("Enter GCP Service Account Email (default: svc-deploy@gcp-prod.iam.gserviceaccount.com): ").strip() or "svc-deploy@gcp-prod.iam.gserviceaccount.com"
        alert = {
            "id": "MANUAL-GCP-IAM-004",
            "cloud_provider": "gcp",
            "severity": "CRITICAL",
            "type": "SCC_EXPOSED_SERVICE_ACCOUNT_KEY",
            "resource_type": "iam",
            "resource_id": sa_email,
            "project_id": "gcp-prod-sec-project"
        }

    elif choice == "5":
        azure_vm = input("Enter Azure VM Name (default: vm-az-prod-web-01): ").strip() or "vm-az-prod-web-01"
        alert = {
            "id": "MANUAL-AZURE-COMPUTE-005",
            "cloud_provider": "azure",
            "severity": "CRITICAL",
            "type": "SENTINEL_MALICIOUS_C2_TRAFFIC",
            "resource_type": "compute",
            "resource_id": azure_vm,
            "subscription_id": "00000000-0000-0000-0000-000000000000",
            "location": "eastus"
        }

    elif choice == "6":
        upn = input("Enter Azure Entra ID UPN (default: alex.analyst@company.com): ").strip() or "alex.analyst@company.com"
        alert = {
            "id": "MANUAL-AZURE-IAM-006",
            "cloud_provider": "azure",
            "severity": "CRITICAL",
            "type": "SENTINEL_IMPOSSIBLE_TRAVEL",
            "resource_type": "iam",
            "resource_id": upn,
            "subscription_id": "00000000-0000-0000-0000-000000000000"
        }

    elif choice == "7":
        print("\nPaste custom JSON alert payload below:")
        raw_json = input("> ").strip()
        try:
            alert = json.loads(raw_json)
        except Exception as e:
            print(f"Error parsing JSON: {e}")
            sys.exit(1)

    else:
        print("Exiting test bench.")
        sys.exit(0)

    print("\n--------------------------------------------------------------------------")
    print(f"▶ EXECUTING MULTI-CLOUD CONTAINMENT ENGINE FOR [{alert.get('cloud_provider', 'AWS').upper()}]...")
    print("--------------------------------------------------------------------------\n")

    responder = MultiCloudIncidentResponder(dry_run=False)
    result = responder.process_alert(alert)

    print("\n--------------------------------------------------------------------------")
    print("✅ CONTAINMENT EXECUTION RESULT:")
    print("--------------------------------------------------------------------------")
    print(json.dumps(result, indent=2))
    print("==========================================================================\n")


if __name__ == "__main__":
    main()
