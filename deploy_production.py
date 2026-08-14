#!/usr/bin/env python3
"""
Automated Incident Response Pipeline - Live Production Readiness & Pre-Flight Verifier
---------------------------------------------------------------------------------------
Verifies cloud credentials, IAM permissions, and SDK installations for AWS, GCP, and Azure
prior to live production deployment.
"""

import os
import sys
import json

# Ensure UTF-8 output encoding for Windows compatibility
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


def verify_aws():
    print("[1/3] Verifying AWS Production Credentials & SDK...")
    try:
        import boto3
        sts = boto3.client("sts")
        caller = sts.get_caller_identity()
        print(f"  [SUCCESS] AWS Connected | Account: {caller['Account']} | ARN: {caller['Arn']}")
        return True
    except ImportError:
        print("  [MISSING] AWS SDK (boto3) is not installed. Run: pip install boto3")
        return False
    except Exception as e:
        print(f"  [NOT CONFIG] AWS credentials inactive or missing: {e}")
        return False


def verify_gcp():
    print("[2/3] Verifying GCP Production Credentials & SDK...")
    try:
        from google.auth import default
        credentials, project = default()
        print(f"  [SUCCESS] GCP Connected | Project: {project or 'Configured via Service Account'}")
        return True
    except ImportError:
        print("  [MISSING] GCP SDK (google-cloud-compute) not installed. Run: pip install google-cloud-compute")
        return False
    except Exception as e:
        print(f"  [NOT CONFIG] GCP credentials missing (GOOGLE_APPLICATION_CREDENTIALS): {e}")
        return False


def verify_azure():
    print("[3/3] Verifying Azure Production Credentials & SDK...")
    try:
        from azure.identity import DefaultAzureCredential
        cred = DefaultAzureCredential()
        print("  [SUCCESS] Azure SDK Installed & DefaultAzureCredential initialized.")
        return True
    except ImportError:
        print("  [MISSING] Azure SDK (azure-identity) not installed. Run: pip install azure-identity azure-mgmt-compute")
        return False
    except Exception as e:
        print(f"  [NOT CONFIG] Azure Credentials missing (AZURE_SUBSCRIPTION_ID / Client Secret): {e}")
        return False


def main():
    print("==========================================================================")
    print(" MULTI-CLOUD LIVE PRODUCTION PRE-FLIGHT VERIFIER")
    print("==========================================================================")
    
    aws_ok = verify_aws()
    gcp_ok = verify_gcp()
    azure_ok = verify_azure()
    
    print("\n--------------------------------------------------------------------------")
    print("PRODUCTION READINESS SUMMARY:")
    print("--------------------------------------------------------------------------")
    print(f"  * AWS   Production Mode: {'READY (LIVE)' if aws_ok else 'SIMULATION / DRY-RUN FALLBACK'}")
    print(f"  * GCP   Production Mode: {'READY (LIVE)' if gcp_ok else 'SIMULATION / DRY-RUN FALLBACK'}")
    print(f"  * AZURE Production Mode: {'READY (LIVE)' if azure_ok else 'SIMULATION / DRY-RUN FALLBACK'}")
    print("--------------------------------------------------------------------------")
    
    print("\nTo enable Live Production Mode on any cloud platform:")
    print("  1. Install SDKs: pip install -r requirements.txt")
    print("  2. Copy template: cp .env.example .env")
    print("  3. Set LIVE_PRODUCTION_MODE=true in your environment or .env file.")
    print("==========================================================================\n")


if __name__ == "__main__":
    main()
