"""
Pytest fixtures for GxP Compliance Automation test suite.

Provides common test data and AWS credential mocking for unit tests.
"""

import os
from typing import Any

import pytest


@pytest.fixture(autouse=True)
def aws_credentials() -> None:
    """
    Set dummy AWS credentials for moto/mocking.

    This fixture is autouse=True so all tests automatically get
    mocked credentials, preventing any accidental real AWS calls.
    """
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    os.environ["ALERT_TOPIC_ARN"] = "arn:aws:sns:us-east-1:123456789012:gxp-alerts"
    os.environ["CRITICAL_TOPIC_ARN"] = "arn:aws:sns:us-east-1:123456789012:gxp-critical"


@pytest.fixture
def sample_stack_config() -> dict[str, Any]:
    """
    Return a typical CloudFormation stack configuration dict for IQ checks.

    Simulates the structure expected by the IQ verification handler
    when performing installation qualification checks.
    """
    return {
        "stack_name": "gxp-compliance-prod",
        "region": "us-east-1",
        "account_id": "123456789012",
        "expected_resources": {
            "AWS::Lambda::Function": [
                "drift-detection-handler",
                "iq-verification-handler",
                "e-signature-handler",
            ],
            "AWS::SNS::Topic": [
                "gxp-alerts",
                "gxp-critical",
            ],
            "AWS::DynamoDB::Table": [
                "gxp-audit-trail",
                "gxp-signatures",
            ],
            "AWS::S3::Bucket": [
                "gxp-compliance-artifacts-123456789012",
            ],
        },
        "expected_outputs": {
            "AlertTopicArn": "arn:aws:sns:us-east-1:123456789012:gxp-alerts",
            "CriticalTopicArn": "arn:aws:sns:us-east-1:123456789012:gxp-critical",
            "AuditTableName": "gxp-audit-trail",
        },
        "tags": {
            "gxp:qualification-status": "pending",
            "gxp:environment": "production",
            "gxp:system-owner": "quality-team",
        },
    }


@pytest.fixture
def sample_signature_event() -> dict[str, Any]:
    """
    Return a typical electronic signature request event.

    Simulates an API Gateway event for the 21 CFR Part 11
    electronic signature workflow.
    """
    return {
        "httpMethod": "POST",
        "path": "/signatures/sign",
        "headers": {
            "Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test",
            "Content-Type": "application/json",
        },
        "body": '{"record_id": "BATCH-2024-001", "signer_id": "user@example.com", '
        '"meaning": "approved", "reason": "Production batch release - all IPC tests passed", '
        '"document_hash": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}',
        "requestContext": {
            "accountId": "123456789012",
            "stage": "prod",
            "requestId": "req-abc-123",
            "identity": {
                "sourceIp": "10.0.1.50",
                "userAgent": "GxP-Client/1.0",
            },
        },
    }
