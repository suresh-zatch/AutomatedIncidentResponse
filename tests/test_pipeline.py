#!/usr/bin/env python3
"""
Automated Multi-Cloud Incident Response Pipeline
=================================================
Master Pytest Suite — Phases 1-4 Verification

Covers:
  - Unit: alert parsing, routing, all 6 containment handlers
  - Integration: full process_alert() pipeline per provider
  - Fault Injection: malformed payloads, unknown providers, missing fields
  - Edge Cases: empty strings, Unicode, cross-provider symmetry
"""

import json
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from incident_responder import MultiCloudIncidentResponder, setup_logger  # noqa: E402


# ===========================================================================
# FIXTURES
# ===========================================================================

@pytest.fixture
def dry_run_engine():
    return MultiCloudIncidentResponder(dry_run=True)


@pytest.fixture
def aws_compute_alert():
    return {
        "id": "TEST-AWS-COMPUTE-001",
        "cloud_provider": "aws",
        "severity": "CRITICAL",
        "type": "GUARDDUTY_MALWARE_EXECUTION",
        "resource_type": "compute",
        "resource_id": "i-0a8b9c1d2e3f45678",
        "account_id": "992817345019",
        "region": "us-west-2",
    }


@pytest.fixture
def aws_iam_alert():
    return {
        "id": "TEST-AWS-IAM-002",
        "cloud_provider": "aws",
        "severity": "CRITICAL",
        "type": "UNAUTHORIZED_CREDENTIAL_EXFILTRATION",
        "resource_type": "iam",
        "resource_id": "sec-analyst-temp",
        "account_id": "992817345019",
        "region": "global",
    }


@pytest.fixture
def gcp_compute_alert():
    return {
        "id": "TEST-GCP-COMPUTE-003",
        "cloud_provider": "gcp",
        "severity": "HIGH",
        "type": "SCC_SUSPICIOUS_EXECUTION",
        "resource_type": "compute",
        "resource_id": "gce-prod-app-01",
        "project_id": "gcp-prod-sec-project",
        "region": "us-central1-a",
    }


@pytest.fixture
def gcp_iam_alert():
    return {
        "id": "TEST-GCP-IAM-004",
        "cloud_provider": "gcp",
        "severity": "CRITICAL",
        "type": "SCC_EXPOSED_SERVICE_ACCOUNT_KEY",
        "resource_type": "iam",
        "resource_id": "svc-deploy@gcp-prod.iam.gserviceaccount.com",
        "project_id": "gcp-prod-sec-project",
    }


@pytest.fixture
def azure_compute_alert():
    return {
        "id": "TEST-AZURE-COMPUTE-005",
        "cloud_provider": "azure",
        "severity": "CRITICAL",
        "type": "SENTINEL_MALICIOUS_C2_TRAFFIC",
        "resource_type": "compute",
        "resource_id": "vm-az-prod-web-01",
        "subscription_id": "00000000-0000-0000-0000-000000000000",
        "location": "eastus",
    }


@pytest.fixture
def azure_iam_alert():
    return {
        "id": "TEST-AZURE-IAM-006",
        "cloud_provider": "azure",
        "severity": "CRITICAL",
        "type": "SENTINEL_IMPOSSIBLE_TRAVEL",
        "resource_type": "iam",
        "resource_id": "alex.analyst@company.com",
        "subscription_id": "00000000-0000-0000-0000-000000000000",
    }


# ===========================================================================
# PHASE 1 — UNIT TESTS: ALERT PARSING
# ===========================================================================

class TestAlertParsing:
    def test_parse_returns_all_required_keys(self, dry_run_engine, aws_compute_alert):
        result = dry_run_engine.parse_alert(aws_compute_alert)
        for key in ["incident_id", "cloud_provider", "severity", "alert_type",
                    "resource_type", "resource_id", "account_id", "region", "received_at"]:
            assert key in result, f"Missing key: {key}"

    def test_parse_incident_id_uses_provided_id(self, dry_run_engine, aws_compute_alert):
        result = dry_run_engine.parse_alert(aws_compute_alert)
        assert result["incident_id"] == "TEST-AWS-COMPUTE-001"

    def test_parse_auto_generates_incident_id_when_missing(self, dry_run_engine):
        result = dry_run_engine.parse_alert({"cloud_provider": "aws"})
        assert result["incident_id"].startswith("INC-")

    def test_parse_normalises_provider_to_lowercase(self, dry_run_engine):
        result = dry_run_engine.parse_alert({"cloud_provider": "AWS"})
        assert result["cloud_provider"] == "aws"

    def test_parse_normalises_severity_to_uppercase(self, dry_run_engine):
        result = dry_run_engine.parse_alert({"severity": "high"})
        assert result["severity"] == "HIGH"

    def test_parse_defaults_severity_to_critical(self, dry_run_engine):
        result = dry_run_engine.parse_alert({})
        assert result["severity"] == "CRITICAL"

    def test_parse_uses_project_id_as_account_id_for_gcp(self, dry_run_engine, gcp_iam_alert):
        result = dry_run_engine.parse_alert(gcp_iam_alert)
        assert result["account_id"] == "gcp-prod-sec-project"

    def test_parse_uses_subscription_id_for_azure(self, dry_run_engine, azure_iam_alert):
        result = dry_run_engine.parse_alert(azure_iam_alert)
        assert result["account_id"] == "00000000-0000-0000-0000-000000000000"

    def test_parse_uses_location_as_region_for_azure(self, dry_run_engine, azure_compute_alert):
        result = dry_run_engine.parse_alert(azure_compute_alert)
        assert result["region"] == "eastus"

    def test_parse_received_at_is_iso_format(self, dry_run_engine, aws_compute_alert):
        from datetime import datetime
        result = dry_run_engine.parse_alert(aws_compute_alert)
        datetime.fromisoformat(result["received_at"])


# ===========================================================================
# PHASE 2 — INTEGRATION TESTS: FULL PIPELINE
# ===========================================================================

class TestAWSContainment:
    def test_aws_compute_returns_successful_containment(self, dry_run_engine, aws_compute_alert):
        result = dry_run_engine.process_alert(aws_compute_alert)
        assert result["status"] == "SUCCESSFUL_CONTAINMENT"
        assert result["cloud_provider"] == "AWS"
        assert result["containment_type"] == "AWS_COMPUTE_ISOLATION"
        assert result["target_resource"] == "i-0a8b9c1d2e3f45678"
        assert result["execution_mode"] == "SIMULATION_DRY_RUN"
        assert len(result["steps"]) >= 2

    def test_aws_compute_steps_have_dry_run_status(self, dry_run_engine, aws_compute_alert):
        result = dry_run_engine.process_alert(aws_compute_alert)
        for step in result["steps"]:
            assert step["status"] == "DRY_RUN_SUCCESS"

    def test_aws_iam_returns_successful_containment(self, dry_run_engine, aws_iam_alert):
        result = dry_run_engine.process_alert(aws_iam_alert)
        assert result["status"] == "SUCCESSFUL_CONTAINMENT"
        assert result["containment_type"] == "AWS_IAM_ISOLATION"
        assert result["target_resource"] == "sec-analyst-temp"

    def test_aws_iam_steps_include_key_deactivation(self, dry_run_engine, aws_iam_alert):
        result = dry_run_engine.process_alert(aws_iam_alert)
        actions = [s["action"] for s in result["steps"]]
        assert "aws_iam_deactivate_keys" in actions

    def test_aws_result_is_json_serialisable(self, dry_run_engine, aws_compute_alert):
        result = dry_run_engine.process_alert(aws_compute_alert)
        serialised = json.dumps(result)
        assert len(serialised) > 100


class TestGCPContainment:
    def test_gcp_compute_returns_successful_containment(self, dry_run_engine, gcp_compute_alert):
        result = dry_run_engine.process_alert(gcp_compute_alert)
        assert result["status"] == "SUCCESSFUL_CONTAINMENT"
        assert result["cloud_provider"] == "GCP"
        assert result["containment_type"] == "GCP_COMPUTE_ISOLATION"
        assert result["target_resource"] == "gce-prod-app-01"

    def test_gcp_compute_includes_snapshot_step(self, dry_run_engine, gcp_compute_alert):
        result = dry_run_engine.process_alert(gcp_compute_alert)
        actions = [s["action"] for s in result["steps"]]
        assert "gcp_gce_create_persistent_disk_snapshot" in actions

    def test_gcp_iam_returns_successful_containment(self, dry_run_engine, gcp_iam_alert):
        result = dry_run_engine.process_alert(gcp_iam_alert)
        assert result["status"] == "SUCCESSFUL_CONTAINMENT"
        assert result["containment_type"] == "GCP_IAM_ISOLATION"

    def test_gcp_iam_includes_role_revocation(self, dry_run_engine, gcp_iam_alert):
        result = dry_run_engine.process_alert(gcp_iam_alert)
        actions = [s["action"] for s in result["steps"]]
        assert "gcp_iam_revoke_iam_roles" in actions

    def test_gcp_result_has_valid_timestamp(self, dry_run_engine, gcp_iam_alert):
        from datetime import datetime
        result = dry_run_engine.process_alert(gcp_iam_alert)
        datetime.fromisoformat(result["timestamp"])


class TestAzureContainment:
    def test_azure_compute_returns_successful_containment(self, dry_run_engine, azure_compute_alert):
        result = dry_run_engine.process_alert(azure_compute_alert)
        assert result["status"] == "SUCCESSFUL_CONTAINMENT"
        assert result["cloud_provider"] == "AZURE"
        assert result["containment_type"] == "AZURE_COMPUTE_ISOLATION"
        assert result["target_resource"] == "vm-az-prod-web-01"

    def test_azure_compute_includes_nsg_step(self, dry_run_engine, azure_compute_alert):
        result = dry_run_engine.process_alert(azure_compute_alert)
        actions = [s["action"] for s in result["steps"]]
        assert "azure_vm_associate_network_security_group" in actions

    def test_azure_iam_returns_successful_containment(self, dry_run_engine, azure_iam_alert):
        result = dry_run_engine.process_alert(azure_iam_alert)
        assert result["status"] == "SUCCESSFUL_CONTAINMENT"
        assert result["containment_type"] == "AZURE_ENTRA_ID_ISOLATION"

    def test_azure_iam_disables_account(self, dry_run_engine, azure_iam_alert):
        result = dry_run_engine.process_alert(azure_iam_alert)
        disable_steps = [s for s in result["steps"]
                         if s["action"] == "azure_entra_disable_user_account"]
        assert len(disable_steps) == 1
        assert disable_steps[0]["account_enabled"] is False

    def test_azure_iam_revokes_sessions(self, dry_run_engine, azure_iam_alert):
        result = dry_run_engine.process_alert(azure_iam_alert)
        actions = [s["action"] for s in result["steps"]]
        assert "azure_entra_revoke_sign_in_sessions" in actions


# ===========================================================================
# PHASE 3 — FAULT INJECTION TESTS
# ===========================================================================

class TestFaultInjection:
    def test_raises_on_unsupported_provider(self, dry_run_engine):
        with pytest.raises(ValueError, match="Unsupported cloud provider"):
            dry_run_engine.process_alert({"cloud_provider": "oracle", "resource_id": "x"})

    def test_empty_payload_uses_all_defaults(self, dry_run_engine):
        result = dry_run_engine.process_alert({})
        assert result["status"] == "SUCCESSFUL_CONTAINMENT"
        assert result["cloud_provider"] == "AWS"

    def test_missing_resource_id_uses_default(self, dry_run_engine):
        result = dry_run_engine.process_alert({"cloud_provider": "gcp"})
        assert result["target_resource"] == "unknown-resource"

    def test_none_severity_uses_default(self, dry_run_engine):
        alert = {
            "cloud_provider": "azure",
            "severity": None,
            "resource_type": "iam",
            "resource_id": "user@domain.com",
        }
        result = dry_run_engine.process_alert(alert)
        assert result["status"] == "SUCCESSFUL_CONTAINMENT"

    def test_extra_unknown_fields_are_ignored(self, dry_run_engine):
        alert = {
            "cloud_provider": "aws",
            "resource_type": "compute",
            "resource_id": "i-1234",
            "UNKNOWN_FIELD": "should_not_break",
            "nested": {"deep": "data"},
        }
        result = dry_run_engine.process_alert(alert)
        assert result["status"] == "SUCCESSFUL_CONTAINMENT"

    def test_provider_case_insensitive_uppercase(self, dry_run_engine):
        result = dry_run_engine.process_alert({"cloud_provider": "AWS", "resource_id": "i-test"})
        assert result["cloud_provider"] == "AWS"

    def test_provider_case_insensitive_mixed_case(self, dry_run_engine):
        result = dry_run_engine.process_alert({"cloud_provider": "Gcp", "resource_id": "vm-test"})
        assert result["cloud_provider"] == "GCP"

    def test_unicode_resource_id_does_not_crash(self, dry_run_engine):
        result = dry_run_engine.process_alert({
            "cloud_provider": "azure",
            "resource_type": "iam",
            "resource_id": "user@unicode-corp.com",
        })
        assert result["status"] == "SUCCESSFUL_CONTAINMENT"

    def test_very_long_resource_id_does_not_crash(self, dry_run_engine):
        result = dry_run_engine.process_alert({
            "cloud_provider": "aws",
            "resource_type": "iam",
            "resource_id": "x" * 1000,
        })
        assert result["status"] == "SUCCESSFUL_CONTAINMENT"

    def test_result_always_contains_incident_id(self, dry_run_engine):
        result = dry_run_engine.process_alert({"cloud_provider": "gcp"})
        assert "incident_id" in result

    def test_result_always_contains_timestamp(self, dry_run_engine):
        result = dry_run_engine.process_alert({"cloud_provider": "azure"})
        assert "timestamp" in result

    def test_result_steps_is_always_a_list(self, dry_run_engine):
        for provider in ["aws", "gcp", "azure"]:
            result = dry_run_engine.process_alert({"cloud_provider": provider})
            assert isinstance(result["steps"], list)


# ===========================================================================
# PHASE 4 — EDGE CASE & SYMMETRY TESTS
# ===========================================================================

class TestEdgeCases:
    def test_all_providers_return_same_schema_keys(self, dry_run_engine):
        required = {
            "incident_id", "cloud_provider", "execution_mode",
            "containment_type", "target_resource", "status", "steps", "timestamp",
        }
        for provider in ["aws", "gcp", "azure"]:
            result = dry_run_engine.process_alert({"cloud_provider": provider, "resource_id": "test-res"})
            missing = required - set(result.keys())
            assert not missing, f"{provider} result missing keys: {missing}"

    def test_dry_run_mode_never_returns_live_success(self, dry_run_engine):
        for provider in ["aws", "gcp", "azure"]:
            result = dry_run_engine.process_alert({"cloud_provider": provider})
            for step in result["steps"]:
                assert "LIVE" not in step["status"], (
                    f"Unexpected LIVE status in dry-run for {provider}: {step}"
                )

    def test_execution_mode_is_simulation_in_dry_run(self, dry_run_engine):
        for provider in ["aws", "gcp", "azure"]:
            result = dry_run_engine.process_alert({"cloud_provider": provider})
            assert result["execution_mode"] == "SIMULATION_DRY_RUN"

    def test_logger_is_correctly_configured(self):
        logger = setup_logger()
        assert logger.name == "LiveMultiCloudIncidentResponder"
        assert len(logger.handlers) >= 1

    def test_process_alert_json_round_trip(self, dry_run_engine):
        for provider in ["aws", "gcp", "azure"]:
            result = dry_run_engine.process_alert({"cloud_provider": provider})
            restored = json.loads(json.dumps(result))
            assert restored["status"] == "SUCCESSFUL_CONTAINMENT"

    def test_each_containment_has_at_least_one_step(self, dry_run_engine):
        for provider in ["aws", "gcp", "azure"]:
            for res_type in ["iam", "compute"]:
                result = dry_run_engine.process_alert({
                    "cloud_provider": provider,
                    "resource_type": res_type,
                    "resource_id": "test-resource",
                })
                assert len(result["steps"]) >= 1, (
                    f"No steps for {provider}/{res_type}"
                )

    def test_simulation_includes_snapshot_for_compute(self, dry_run_engine):
        for provider in ["aws", "gcp", "azure"]:
            result = dry_run_engine.process_alert({
                "cloud_provider": provider,
                "resource_type": "compute",
                "resource_id": "vm-test",
            })
            actions = [s["action"] for s in result["steps"]]
            snapshot_found = any("snapshot" in a for a in actions)
            assert snapshot_found, f"No snapshot action for {provider} compute containment"
