"""
GxP Compliance Drift Detection Lambda Handler.

Triggered by EventBridge rule on AWS Config compliance change events.
Detects NON_COMPLIANT evaluations, publishes alerts to SNS, and checks
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

# AWS clients (initialized outside handler for connection reuse)
sns_client = boto3.client("sns")
config_client = boto3.client("config")


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
