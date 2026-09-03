"""
Unit tests for the GxP Compliance Drift Detection Lambda handler.

Focus areas:
  - The AWS Security Hub integration (_publish_to_security_hub) that routes
    drift events to Security Hub as ASFF custom findings.
  - Non-blocking failure behavior: a Security Hub error must be logged and
    swallowed, never raised, so the primary SNS path and the Step Functions
    return value are unaffected.
  - Severity mapping for standard (HIGH) and high-process-risk (CRITICAL) drift.

The handler defines its boto3 clients at module import time, so these tests
load the module with boto3.client patched, giving each client a MagicMock the
tests can assert against.
"""

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

HANDLER_PATH = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "drift-detection"
    / "handler.py"
)


def _load_handler_with_mocked_clients():
    """
    Load the drift-detection handler module with all boto3 clients mocked.

    Returns:
        (module, clients) where clients maps service name -> MagicMock.
    """
    clients = {
        "sns": MagicMock(),
        "config": MagicMock(),
        "securityhub": MagicMock(),
    }
    with patch("boto3.client", side_effect=lambda name, *a, **k: clients[name]):
        spec = importlib.util.spec_from_file_location("drift_handler", HANDLER_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module, clients


@pytest.fixture
def compliance_details() -> dict:
    return {
        "resource_type": "AWS::S3::Bucket",
        "resource_id": "gxp-artifact-bucket",
        "config_rule_name": "s3-bucket-server-side-encryption-enabled",
        "compliance_type": "NON_COMPLIANT",
    }


@pytest.fixture
def alert_payload() -> dict:
    return {
        "account_id": "123456789012",
        "region": "us-east-1",
        "timestamp": "2026-09-03T00:00:00+00:00",
        "severity": "HIGH",
    }


def test_publish_to_security_hub_imports_valid_asff_finding(
    compliance_details, alert_payload
):
    """A well-formed ASFF finding is submitted via batch_import_findings."""
    module, clients = _load_handler_with_mocked_clients()

    module._publish_to_security_hub(
        compliance_details=compliance_details,
        alert_payload=alert_payload,
        event={},
        severity_label="HIGH",
    )

    clients["securityhub"].batch_import_findings.assert_called_once()
    findings = clients["securityhub"].batch_import_findings.call_args.kwargs["Findings"]
    assert len(findings) == 1

    finding = findings[0]
    assert finding["SchemaVersion"] == "2018-10-08"
    assert finding["AwsAccountId"] == "123456789012"
    assert finding["Severity"]["Label"] == "HIGH"
    assert finding["Severity"]["Normalized"] == 89
    assert finding["Compliance"]["Status"] == "FAILED"
    # The finding ID and resource must reference the drifted resource.
    assert "gxp-artifact-bucket" in finding["Id"]
    assert finding["Resources"][0]["Id"] == "gxp-artifact-bucket"
    assert finding["Resources"][0]["Type"] == "AWS::S3::Bucket"


def test_publish_to_security_hub_critical_severity_normalized(
    compliance_details, alert_payload
):
    """CRITICAL severity maps to the normalized value 100."""
    module, clients = _load_handler_with_mocked_clients()

    module._publish_to_security_hub(
        compliance_details=compliance_details,
        alert_payload=alert_payload,
        event={},
        severity_label="CRITICAL",
    )

    finding = clients["securityhub"].batch_import_findings.call_args.kwargs["Findings"][0]
    assert finding["Severity"]["Label"] == "CRITICAL"
    assert finding["Severity"]["Normalized"] == 100


def test_publish_to_security_hub_is_non_blocking_on_client_error(
    compliance_details, alert_payload
):
    """
    A ClientError from Security Hub (e.g. AccessDeniedException when the role
    lacks securityhub:BatchImportFindings, or InvalidAccessException when
    Security Hub is not enabled) must be caught and swallowed, not raised.
    """
    module, clients = _load_handler_with_mocked_clients()
    clients["securityhub"].batch_import_findings.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
        "BatchImportFindings",
    )

    # Must not raise.
    module._publish_to_security_hub(
        compliance_details=compliance_details,
        alert_payload=alert_payload,
        event={},
        severity_label="HIGH",
    )


def test_compliant_resource_skips_all_publishing():
    """COMPLIANT evaluations short-circuit before any SNS or Security Hub call."""
    module, clients = _load_handler_with_mocked_clients()

    event = {
        "account": "123456789012",
        "region": "us-east-1",
        "detail": {
            "resourceType": "AWS::S3::Bucket",
            "resourceId": "gxp-artifact-bucket",
            "configRuleName": "s3-bucket-server-side-encryption-enabled",
            "newEvaluationResult": {"complianceType": "COMPLIANT"},
        },
    }

    result = module.handler(event, None)

    assert result["status"] == "skipped"
    clients["sns"].publish.assert_not_called()
    clients["securityhub"].batch_import_findings.assert_not_called()
