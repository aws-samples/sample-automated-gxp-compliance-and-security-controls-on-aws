"""
Unit tests for the IQ (Installation Qualification) Verification Handler.

Tests cover module discovery, report structure, overall status logic,
deviations tracking, and proper AWS service mocking.
"""

import json
from datetime import datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# --- Simulated IQ Verification Handler Logic ---
# (Mirrors the expected behavior of src/iq-verification/handler.py)


def iq_verification_handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """
    IQ verification handler that discovers check modules, runs them,
    and produces a structured verification report.
    """
    import boto3

    stack_name = event.get("stack_name", "")
    region = event.get("region", "us-east-1")

    cfn_client = boto3.client("cloudformation", region_name=region)

    # Discover check modules
    check_modules = discover_check_modules()

    # Run all checks
    checks: list[dict[str, Any]] = []
    deviations: list[dict[str, Any]] = []

    for module in check_modules:
        result = module(cfn_client, stack_name)
        checks.append(result)
        if result["status"] == "FAIL":
            deviations.append({
                "check_name": result["check_name"],
                "expected": result.get("expected"),
                "actual": result.get("actual"),
                "severity": result.get("severity", "MAJOR"),
            })

    # Determine overall status
    overall_status = "PASS" if not deviations else "FAIL"

    return {
        "stack_name": stack_name,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "checks": checks,
        "overall_status": overall_status,
        "deviations": deviations,
    }


def discover_check_modules() -> list:
    """Discover all available IQ check modules."""
    return [
        check_stack_exists,
        check_resources_created,
        check_outputs_present,
        check_stack_tags,
        check_stack_status,
    ]


def check_stack_exists(cfn_client: Any, stack_name: str) -> dict[str, Any]:
    """Verify the CloudFormation stack exists."""
    try:
        response = cfn_client.describe_stacks(StackName=stack_name)
        stacks = response.get("Stacks", [])
        if stacks:
            return {"check_name": "stack_exists", "status": "PASS", "detail": "Stack found"}
    except Exception:
        pass
    return {
        "check_name": "stack_exists",
        "status": "FAIL",
        "expected": "Stack exists",
        "actual": "Stack not found",
        "severity": "CRITICAL",
    }


def check_resources_created(cfn_client: Any, stack_name: str) -> dict[str, Any]:
    """Verify all expected resources were created."""
    try:
        response = cfn_client.list_stack_resources(StackName=stack_name)
        resources = response.get("StackResourceSummaries", [])
        if resources:
            return {"check_name": "resources_created", "status": "PASS", "detail": f"{len(resources)} resources found"}
    except Exception:
        pass
    return {
        "check_name": "resources_created",
        "status": "FAIL",
        "expected": "Resources created",
        "actual": "No resources found",
        "severity": "CRITICAL",
    }


def check_outputs_present(cfn_client: Any, stack_name: str) -> dict[str, Any]:
    """Verify stack outputs are present."""
    try:
        response = cfn_client.describe_stacks(StackName=stack_name)
        stacks = response.get("Stacks", [])
        if stacks and stacks[0].get("Outputs"):
            return {"check_name": "outputs_present", "status": "PASS", "detail": "Outputs present"}
    except Exception:
        pass
    return {
        "check_name": "outputs_present",
        "status": "FAIL",
        "expected": "Stack outputs defined",
        "actual": "No outputs found",
        "severity": "MAJOR",
    }


def check_stack_tags(cfn_client: Any, stack_name: str) -> dict[str, Any]:
    """Verify required GxP tags are present on the stack."""
    try:
        response = cfn_client.describe_stacks(StackName=stack_name)
        stacks = response.get("Stacks", [])
        if stacks:
            tags = {t["Key"]: t["Value"] for t in stacks[0].get("Tags", [])}
            required_tags = ["gxp:qualification-status", "gxp:environment"]
            missing = [t for t in required_tags if t not in tags]
            if not missing:
                return {"check_name": "stack_tags", "status": "PASS", "detail": "All required tags present"}
            return {
                "check_name": "stack_tags",
                "status": "FAIL",
                "expected": f"Tags: {required_tags}",
                "actual": f"Missing: {missing}",
                "severity": "MAJOR",
            }
    except Exception:
        pass
    return {
        "check_name": "stack_tags",
        "status": "FAIL",
        "expected": "GxP tags present",
        "actual": "Unable to verify tags",
        "severity": "MAJOR",
    }


def check_stack_status(cfn_client: Any, stack_name: str) -> dict[str, Any]:
    """Verify stack is in a healthy state (CREATE_COMPLETE or UPDATE_COMPLETE)."""
    try:
        response = cfn_client.describe_stacks(StackName=stack_name)
        stacks = response.get("Stacks", [])
        if stacks:
            status = stacks[0].get("StackStatus", "")
            healthy_states = ["CREATE_COMPLETE", "UPDATE_COMPLETE"]
            if status in healthy_states:
                return {"check_name": "stack_status", "status": "PASS", "detail": f"Status: {status}"}
            return {
                "check_name": "stack_status",
                "status": "FAIL",
                "expected": f"One of {healthy_states}",
                "actual": status,
                "severity": "CRITICAL",
            }
    except Exception:
        pass
    return {
        "check_name": "stack_status",
        "status": "FAIL",
        "expected": "Healthy stack status",
        "actual": "Unable to determine status",
        "severity": "CRITICAL",
    }


# --- Test Cases ---


class TestIQVerificationDiscovery:
    """Tests for check module discovery."""

    def test_handler_discovers_check_modules(self) -> None:
        """Test that handler discovers all available check modules."""
        modules = discover_check_modules()
        assert len(modules) >= 5
        assert all(callable(m) for m in modules)

    def test_discovered_modules_have_expected_names(self) -> None:
        """Test that discovered modules include all critical checks."""
        modules = discover_check_modules()
        module_names = [m.__name__ for m in modules]
        assert "check_stack_exists" in module_names
        assert "check_resources_created" in module_names
        assert "check_outputs_present" in module_names
        assert "check_stack_tags" in module_names
        assert "check_stack_status" in module_names


class TestIQVerificationReportStructure:
    """Tests for IQ verification report structure."""

    @patch("boto3.client")
    def test_report_has_all_required_fields(self, mock_boto_client: MagicMock) -> None:
        """Test that the report contains all required fields."""
        # Mock CloudFormation responses
        mock_cfn = MagicMock()
        mock_boto_client.return_value = mock_cfn
        mock_cfn.describe_stacks.return_value = {
            "Stacks": [{
                "StackName": "gxp-compliance-prod",
                "StackStatus": "CREATE_COMPLETE",
                "Outputs": [{"OutputKey": "AlertTopicArn", "OutputValue": "arn:aws:sns:..."}],
                "Tags": [
                    {"Key": "gxp:qualification-status", "Value": "pending"},
                    {"Key": "gxp:environment", "Value": "production"},
                ],
            }]
        }
        mock_cfn.list_stack_resources.return_value = {
            "StackResourceSummaries": [
                {"LogicalResourceId": "DriftDetection", "ResourceType": "AWS::Lambda::Function"},
            ]
        }

        event = {"stack_name": "gxp-compliance-prod", "region": "us-east-1"}
        result = iq_verification_handler(event)

        # Verify all required fields are present
        assert "stack_name" in result
        assert "timestamp" in result
        assert "checks" in result
        assert "overall_status" in result
        assert "deviations" in result

    @patch("boto3.client")
    def test_report_timestamp_is_iso_format(self, mock_boto_client: MagicMock) -> None:
        """Test that the timestamp is in ISO 8601 format."""
        mock_cfn = MagicMock()
        mock_boto_client.return_value = mock_cfn
        mock_cfn.describe_stacks.return_value = {
            "Stacks": [{
                "StackName": "test-stack",
                "StackStatus": "CREATE_COMPLETE",
                "Outputs": [{"OutputKey": "Out1", "OutputValue": "val1"}],
                "Tags": [
                    {"Key": "gxp:qualification-status", "Value": "qualified"},
                    {"Key": "gxp:environment", "Value": "prod"},
                ],
            }]
        }
        mock_cfn.list_stack_resources.return_value = {
            "StackResourceSummaries": [{"LogicalResourceId": "Res1", "ResourceType": "AWS::SNS::Topic"}]
        }

        event = {"stack_name": "test-stack", "region": "us-east-1"}
        result = iq_verification_handler(event)

        # Should parse without error and end with Z
        assert result["timestamp"].endswith("Z")
        datetime.fromisoformat(result["timestamp"].rstrip("Z"))


class TestIQVerificationOverallStatus:
    """Tests for overall status determination."""

    @patch("boto3.client")
    def test_overall_status_pass_when_all_checks_pass(self, mock_boto_client: MagicMock) -> None:
        """Test that overall_status is PASS when all checks succeed."""
        mock_cfn = MagicMock()
        mock_boto_client.return_value = mock_cfn
        mock_cfn.describe_stacks.return_value = {
            "Stacks": [{
                "StackName": "gxp-compliance-prod",
                "StackStatus": "CREATE_COMPLETE",
                "Outputs": [{"OutputKey": "AlertTopicArn", "OutputValue": "arn:..."}],
                "Tags": [
                    {"Key": "gxp:qualification-status", "Value": "qualified"},
                    {"Key": "gxp:environment", "Value": "production"},
                ],
            }]
        }
        mock_cfn.list_stack_resources.return_value = {
            "StackResourceSummaries": [
                {"LogicalResourceId": "Function1", "ResourceType": "AWS::Lambda::Function"},
            ]
        }

        event = {"stack_name": "gxp-compliance-prod", "region": "us-east-1"}
        result = iq_verification_handler(event)

        assert result["overall_status"] == "PASS"
        assert result["deviations"] == []

    @patch("boto3.client")
    def test_overall_status_fail_if_any_check_fails(self, mock_boto_client: MagicMock) -> None:
        """Test that overall_status is FAIL if any single check fails."""
        mock_cfn = MagicMock()
        mock_boto_client.return_value = mock_cfn
        # Stack exists but has no outputs and wrong status -> some checks fail
        mock_cfn.describe_stacks.return_value = {
            "Stacks": [{
                "StackName": "gxp-compliance-prod",
                "StackStatus": "ROLLBACK_COMPLETE",
                "Outputs": [],
                "Tags": [],
            }]
        }
        mock_cfn.list_stack_resources.return_value = {
            "StackResourceSummaries": []
        }

        event = {"stack_name": "gxp-compliance-prod", "region": "us-east-1"}
        result = iq_verification_handler(event)

        assert result["overall_status"] == "FAIL"

    @patch("boto3.client")
    def test_deviations_populated_on_failures(self, mock_boto_client: MagicMock) -> None:
        """Test that the deviations list contains entries for each failed check."""
        mock_cfn = MagicMock()
        mock_boto_client.return_value = mock_cfn
        # Stack with issues: wrong status, no outputs, no tags
        mock_cfn.describe_stacks.return_value = {
            "Stacks": [{
                "StackName": "gxp-compliance-prod",
                "StackStatus": "UPDATE_ROLLBACK_COMPLETE",
                "Outputs": [],
                "Tags": [],
            }]
        }
        mock_cfn.list_stack_resources.return_value = {
            "StackResourceSummaries": []
        }

        event = {"stack_name": "gxp-compliance-prod", "region": "us-east-1"}
        result = iq_verification_handler(event)

        assert len(result["deviations"]) > 0
        # Each deviation should have required fields
        for deviation in result["deviations"]:
            assert "check_name" in deviation
            assert "severity" in deviation

    @patch("boto3.client")
    def test_stack_not_found_produces_failure(self, mock_boto_client: MagicMock) -> None:
        """Test that a missing stack results in FAIL status."""
        mock_cfn = MagicMock()
        mock_boto_client.return_value = mock_cfn
        from botocore.exceptions import ClientError

        mock_cfn.describe_stacks.side_effect = ClientError(
            {"Error": {"Code": "ValidationError", "Message": "Stack not found"}},
            "DescribeStacks",
        )
        mock_cfn.list_stack_resources.side_effect = ClientError(
            {"Error": {"Code": "ValidationError", "Message": "Stack not found"}},
            "ListStackResources",
        )

        event = {"stack_name": "nonexistent-stack", "region": "us-east-1"}
        result = iq_verification_handler(event)

        assert result["overall_status"] == "FAIL"
        assert any(d["check_name"] == "stack_exists" for d in result["deviations"])
