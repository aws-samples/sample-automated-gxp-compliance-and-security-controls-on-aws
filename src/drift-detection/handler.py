"""
GxP Compliance Drift Detection Lambda Handler.

Triggered by EventBridge rule on AWS Config compliance change events.
Detects NON_COMPLIANT evaluations, publishes findings to AWS Security Hub
(primary, for auditable record) and SNS (secondary, for alerting), and checks
if the affected resource is tagged as high-process-risk for critical alerting.

Python 3.12 | AWS Lambda Runtime
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

# Configure structured logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment variables
ALERT_TOPIC_ARN: str = os.environ.get("ALERT_TOPIC_ARN", "")
CRITICAL_TOPIC_ARN: str = os.environ.get("CRITICAL_TOPIC_ARN", "")
SECURITY_HUB_ENABLED: str = os.environ.get("SECURITY_HUB_ENABLED", "true")

# AWS clients (initialized outside handler for connection reuse)
sns_client = boto3.client("sns")
config_client = boto3.client("config")
securityhub_client = boto3.client("securityhub")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Lambda entry point for Config compliance change events.

    Args:
        event: EventBridge event payload containing Config compliance change detail.
        context: Lambda context object.

    Returns:
        dict: Event details for Step Functions integration including resource info,
              compliance status, and alert metadata.

    Raises:
        ValueError: If event payload is missing required fields.
    """
    logger.info("Received compliance change event", extra={"event": json.dumps(event)})

    try:
        # Extract compliance change details from EventBridge event
        detail = event.get("detail", {})
        compliance_details = _extract_compliance_details(detail)

        # Only process NON_COMPLIANT evaluations
        if compliance_details["compliance_type"] != "NON_COMPLIANT":
            logger.info(
                "Skipping compliant resource",
                extra={
                    "resource_id": compliance_details["resource_id"],
                    "compliance_type": compliance_details["compliance_type"],
                },
            )
            return {
                "status": "skipped",
                "reason": "Resource is compliant",
                "compliance_type": compliance_details["compliance_type"],
            }

        # Build structured alert message
        alert_payload = _build_alert_payload(compliance_details, event)

        # Log the drift event with structured JSON
        logger.warning(
            "GxP compliance drift detected",
            extra={"drift_event": json.dumps(alert_payload)},
        )

        # Publish to standard alert topic
        _publish_to_sns(
            topic_arn=ALERT_TOPIC_ARN,
            subject=f"GxP Compliance Drift Detected: {compliance_details['config_rule_name']}",
            message=alert_payload,
        )

        # Publish to Security Hub as a custom finding (auditable, queryable record)
        if SECURITY_HUB_ENABLED.lower() == "true":
            _publish_to_security_hub(
                compliance_details=compliance_details,
                alert_payload=alert_payload,
                event=event,
                severity_label="HIGH",
            )

        # Check if resource is high-process-risk
        is_critical = _check_high_process_risk(
            resource_type=compliance_details["resource_type"],
            resource_id=compliance_details["resource_id"],
        )

        if is_critical:
            logger.critical(
                "High-process-risk resource drift detected",
                extra={"drift_event": json.dumps(alert_payload)},
            )
            alert_payload["severity"] = "CRITICAL"
            alert_payload["high_process_risk"] = True
            _publish_to_sns(
                topic_arn=CRITICAL_TOPIC_ARN,
                subject=f"CRITICAL GxP Drift: {compliance_details['config_rule_name']}",
                message=alert_payload,
            )
            if SECURITY_HUB_ENABLED.lower() == "true":
                _publish_to_security_hub(
                    compliance_details=compliance_details,
                    alert_payload=alert_payload,
                    event=event,
                    severity_label="CRITICAL",
                )

        # Return details for Step Functions integration
        return {
            "status": "drift_detected",
            "resource_type": compliance_details["resource_type"],
            "resource_id": compliance_details["resource_id"],
            "config_rule_name": compliance_details["config_rule_name"],
            "compliance_type": compliance_details["compliance_type"],
            "high_process_risk": is_critical,
            "timestamp": alert_payload["timestamp"],
            "account_id": alert_payload["account_id"],
            "region": alert_payload["region"],
        }

    except (ValueError, KeyError) as e:
        logger.error("Failed to process compliance event", extra={"error": str(e)})
        raise
    except ClientError as e:
        logger.error(
            "AWS API error during drift detection",
            extra={"error": str(e), "error_code": e.response["Error"]["Code"]},
        )
        raise


def _extract_compliance_details(detail: dict[str, Any]) -> dict[str, str]:
    """
    Extract resource and compliance information from Config event detail.

    Args:
        detail: The 'detail' field from the EventBridge event.

    Returns:
        dict with resource_type, resource_id, config_rule_name, compliance_type.

    Raises:
        ValueError: If required fields are missing from the event detail.
    """
    # AWS Config compliance change events structure
    resource_type = detail.get("resourceType")
    resource_id = detail.get("resourceId")
    config_rule_name = detail.get("configRuleName")
    compliance_type = detail.get("newEvaluationResult", {}).get(
        "complianceType", detail.get("complianceType", "")
    )

    if not all([resource_type, resource_id, config_rule_name]):
        raise ValueError(
            f"Missing required fields in event detail. "
            f"resource_type={resource_type}, resource_id={resource_id}, "
            f"config_rule_name={config_rule_name}"
        )

    return {
        "resource_type": resource_type,
        "resource_id": resource_id,
        "config_rule_name": config_rule_name,
        "compliance_type": compliance_type,
    }


def _build_alert_payload(
    compliance_details: dict[str, str], event: dict[str, Any]
) -> dict[str, Any]:
    """
    Build a structured alert payload for SNS notification.

    Args:
        compliance_details: Extracted compliance information.
        event: Original EventBridge event for account/region metadata.

    Returns:
        Structured dict with all alert details.
    """
    return {
        "resource_type": compliance_details["resource_type"],
        "resource_id": compliance_details["resource_id"],
        "config_rule_name": compliance_details["config_rule_name"],
        "compliance_type": compliance_details["compliance_type"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "account_id": event.get("account", "unknown"),
        "region": event.get("region", "unknown"),
        "severity": "HIGH",
        "high_process_risk": False,
        "source": "gxp-compliance-drift-detection",
    }


def _publish_to_sns(
    topic_arn: str, subject: str, message: dict[str, Any]
) -> None:
    """
    Publish an alert message to an SNS topic.

    Args:
        topic_arn: The ARN of the SNS topic.
        subject: Email subject line for the notification.
        message: Structured message payload (will be JSON-serialized).

    Raises:
        ClientError: If SNS publish fails.
        ValueError: If topic_arn is not configured.
    """
    if not topic_arn:
        logger.error("SNS topic ARN not configured", extra={"subject": subject})
        raise ValueError(f"SNS topic ARN not configured for alert: {subject}")

    # Truncate subject to SNS limit (100 chars)
    subject = subject[:100]

    sns_client.publish(
        TopicArn=topic_arn,
        Subject=subject,
        Message=json.dumps(message, indent=2),
        MessageAttributes={
            "severity": {
                "DataType": "String",
                "StringValue": message.get("severity", "HIGH"),
            },
            "resource_type": {
                "DataType": "String",
                "StringValue": message.get("resource_type", "unknown"),
            },
        },
    )

    logger.info(
        "Alert published to SNS",
        extra={"topic_arn": topic_arn, "subject": subject},
    )


def _publish_to_security_hub(
    compliance_details: dict[str, str],
    alert_payload: dict[str, Any],
    event: dict[str, Any],
    severity_label: str = "HIGH",
) -> None:
    """
    Publish a GxP compliance drift event to AWS Security Hub as a custom finding.

    Security Hub provides a structured, queryable audit trail that satisfies
    GxP change control requirements better than email or SNS alone. Findings
    are retained in Security Hub and can be queried for periodic review evidence.

    Args:
        compliance_details: Extracted compliance information.
        alert_payload: The structured alert payload from _build_alert_payload.
        event: Original EventBridge event for account/region metadata.
        severity_label: ASFF severity label ("INFORMATIONAL", "LOW", "MEDIUM",
                        "HIGH", or "CRITICAL").

    Raises:
        ClientError: If Security Hub batch_import_findings fails.
    """
    account_id = alert_payload.get("account_id", "unknown")
    region = alert_payload.get("region", "unknown")
    resource_type = compliance_details["resource_type"]
    resource_id = compliance_details["resource_id"]
    config_rule_name = compliance_details["config_rule_name"]
    timestamp = alert_payload.get("timestamp", datetime.now(timezone.utc).isoformat())

    # Unique finding ID: account/region/rule/resource
    finding_id = (
        f"gxp-drift/{account_id}/{region}/{config_rule_name}/{resource_id}"
    )
    product_arn = f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default"

    severity_map = {
        "INFORMATIONAL": 0, "LOW": 39, "MEDIUM": 69, "HIGH": 89, "CRITICAL": 100
    }

    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": product_arn,
        "GeneratorId": "gxp-compliance-drift-detection",
        "AwsAccountId": account_id,
        "Types": ["Software and Configuration Checks/GxP Compliance/Drift Detection"],
        "CreatedAt": timestamp,
        "UpdatedAt": timestamp,
        "Severity": {
            "Label": severity_label,
            "Normalized": severity_map.get(severity_label, 89),
        },
        "Title": f"GxP compliance drift: {config_rule_name}",
        "Description": (
            f"Resource {resource_id} ({resource_type}) is NON_COMPLIANT with "
            f"Config rule {config_rule_name}. This drift may affect the validated "
            f"state of the GxP system. Assess whether this change was intentional "
            f"(requiring retroactive change control documentation) or unintentional "
            f"(requiring remediation)."
        ),
        "Resources": [
            {
                "Type": resource_type,
                "Id": resource_id,
                "Region": region,
            }
        ],
        "Compliance": {"Status": "FAILED"},
        "Note": {
            "Text": f"Config rule: {config_rule_name}. Source: gxp-drift-detection.",
            "UpdatedBy": "gxp-compliance-drift-detection",
            "UpdatedAt": timestamp,
        },
    }

    try:
        securityhub_client.batch_import_findings(Findings=[finding])
        logger.info(
            "Drift finding published to Security Hub",
            extra={"finding_id": finding_id, "severity": severity_label},
        )
    except ClientError as e:
        # Log but do not raise: SNS already fired; Security Hub failure
        # should not block the Step Functions return value.
        logger.error(
            "Failed to publish finding to Security Hub",
            extra={"error": str(e), "finding_id": finding_id},
        )


def _check_high_process_risk(resource_type: str, resource_id: str) -> bool:
    """
    Check if a resource is tagged as high-process-risk via AWS Config API.

    Queries the resource's tags to determine if it carries the
    'gxp:process-risk' tag with value 'high'.

    Args:
        resource_type: AWS resource type (e.g., 'AWS::EC2::Instance').
        resource_id: The resource identifier.

    Returns:
        True if the resource is tagged as high-process-risk, False otherwise.
    """
    try:
        response = config_client.get_resource_config_history(
            resourceType=resource_type,
            resourceId=resource_id,
            limit=1,
        )

        config_items = response.get("configurationItems", [])
        if not config_items:
            logger.warning(
                "No configuration items found for resource",
                extra={
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                },
            )
            return False

        # Check tags for high-process-risk designation
        tags = config_items[0].get("tags", {})
        process_risk = tags.get("gxp:process-risk", "").lower()

        return process_risk == "high"

    except ClientError as e:
        logger.warning(
            "Unable to check resource tags, treating as non-critical",
            extra={
                "resource_type": resource_type,
                "resource_id": resource_id,
                "error": str(e),
            },
        )
        return False
