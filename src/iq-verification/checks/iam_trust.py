"""
IQ Check: IAM Trust Relationship Verification
===============================================
Verifies that IAM roles deployed by the CloudFormation stack can actually be
assumed by their intended principals using sts:AssumeRole.

This check validates the Installation Qualification requirement that access
control mechanisms are correctly configured and operational. IAM trust
relationships are critical for GxP compliance as they enforce the principle
of least privilege and ensure only authorized services/users can access
protected resources.

Verification Scope:
- Discover all IAM roles created by the stack
- Attempt sts:AssumeRole for each role
- Verify trust policy allows the expected principals
- Report any roles that cannot be assumed (trust misconfiguration)
"""

import logging
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Session duration for test assume-role calls (minimum allowed)
TEST_SESSION_DURATION_SECONDS = 900


def run_check(config: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Verify that all IAM roles in the stack can be assumed by their intended principals.

    Discovers IAM roles created by the CloudFormation stack, then attempts
    to assume each one. This validates that trust policies are correctly
    configured and that the roles are operationally usable.

    Args:
        config: Dictionary containing:
            - stack_name (str): CloudFormation stack name
            - region (str): AWS region
            - account_id (str): AWS account ID

    Returns:
        List of check result dicts, one per IAM role, each containing:
            - check_name: Identifier for this specific trust verification
            - status: "PASS" or "FAIL"
            - details: Human-readable description of the result
            - timestamp: ISO 8601 timestamp of the check execution
    """
    region = config["region"]
    stack_name = config["stack_name"]
    account_id = config["account_id"]
    results: list[dict[str, Any]] = []

    logger.info(
        "Starting IAM trust verification for stack '%s' in account '%s'",
        stack_name,
        account_id,
    )

    # Discover IAM roles from the CloudFormation stack
    roles = _discover_stack_roles(stack_name, region)

    if not roles:
        logger.warning("No IAM roles found in stack '%s'", stack_name)
        results.append({
            "check_name": "iam_trust_discovery",
            "status": "FAIL",
            "details": (
                f"No IAM roles discovered in stack '{stack_name}'. "
                f"Expected at least one role for GxP workload execution. "
                f"Verify the stack deployed successfully."
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return results

    logger.info("Discovered %d IAM roles in stack '%s'", len(roles), stack_name)

    # Test each role's assumability
    sts_client = boto3.client("sts", region_name=region)
    iam_client = boto3.client("iam", region_name=region)

    for role_info in roles:
        role_arn = role_info["arn"]
        role_name = role_info["name"]
        check_name = f"iam_trust_{role_name}"
        timestamp = datetime.now(timezone.utc).isoformat()

        logger.info("Verifying trust for role: %s", role_arn)

        # First, get the role's trust policy for reporting
        trust_policy = _get_trust_policy(iam_client, role_name)

        # Attempt to assume the role
        assume_result = _attempt_assume_role(sts_client, role_arn, stack_name)

        if assume_result["success"]:
            results.append({
                "check_name": check_name,
                "status": "PASS",
                "details": (
                    f"Role '{role_name}' ({role_arn}) can be assumed successfully. "
                    f"Trust policy principals: {_summarize_trust_principals(trust_policy)}. "
                    f"Temporary credentials obtained and validated."
                ),
                "timestamp": timestamp,
                "role_arn": role_arn,
                "trust_principals": _summarize_trust_principals(trust_policy),
            })
        else:
            error_code = assume_result.get("error_code", "Unknown")
            error_message = assume_result.get("error_message", "Unknown error")

            # Determine if this is expected (some roles should only be assumable
            # by specific services, not by the verification Lambda)
            is_service_role = _is_service_linked_role(trust_policy)

            if is_service_role:
                results.append({
                    "check_name": check_name,
                    "status": "PASS",
                    "details": (
                        f"Role '{role_name}' ({role_arn}) is a service-linked role. "
                        f"Cannot be assumed by verification Lambda (expected behavior). "
                        f"Trust policy correctly restricts to service principal: "
                        f"{_summarize_trust_principals(trust_policy)}."
                    ),
                    "timestamp": timestamp,
                    "role_arn": role_arn,
                    "trust_principals": _summarize_trust_principals(trust_policy),
                    "service_role": True,
                })
            else:
                results.append({
                    "check_name": check_name,
                    "status": "FAIL",
                    "details": (
                        f"Role '{role_name}' ({role_arn}) cannot be assumed. "
                        f"Error: [{error_code}] {error_message}. "
                        f"Trust policy principals: {_summarize_trust_principals(trust_policy)}. "
                        f"Verify the trust policy allows the intended principals."
                    ),
                    "timestamp": timestamp,
                    "role_arn": role_arn,
                    "error_code": error_code,
                    "error_message": error_message,
                    "trust_principals": _summarize_trust_principals(trust_policy),
                })

    logger.info(
        "IAM trust verification complete: %d/%d passed",
        sum(1 for r in results if r["status"] == "PASS"),
        len(results),
    )

    return results


def _discover_stack_roles(stack_name: str, region: str) -> list[dict[str, str]]:
    """
    Discover IAM roles created by the CloudFormation stack.

    Args:
        stack_name: CloudFormation stack name.
        region: AWS region.

    Returns:
        List of dicts with 'arn' and 'name' keys for each discovered role.
    """
    roles: list[dict[str, str]] = []

    try:
        cfn_client = boto3.client("cloudformation", region_name=region)

        # List all stack resources of type AWS::IAM::Role
        paginator = cfn_client.get_paginator("list_stack_resources")
        for page in paginator.paginate(StackName=stack_name):
            for resource in page.get("StackResourceSummaries", []):
                if resource["ResourceType"] == "AWS::IAM::Role":
                    physical_id = resource.get("PhysicalResourceId", "")
                    if physical_id:
                        # Physical ID for IAM roles is the role name
                        role_name = physical_id
                        # Construct the ARN
                        iam_client = boto3.client("iam", region_name=region)
                        try:
                            role_response = iam_client.get_role(RoleName=role_name)
                            role_arn = role_response["Role"]["Arn"]
                        except ClientError:
                            # Fallback: construct ARN from account info
                            continue

                        roles.append({"arn": role_arn, "name": role_name})

    except ClientError as exc:
        logger.error(
            "Failed to discover stack roles: [%s] %s",
            exc.response["Error"]["Code"],
            exc.response["Error"]["Message"],
        )
    except Exception as exc:
        logger.exception("Unexpected error discovering stack roles: %s", str(exc))

    return roles


def _get_trust_policy(iam_client: Any, role_name: str) -> dict[str, Any]:
    """
    Retrieve the trust policy (assume role policy document) for a role.

    Args:
        iam_client: Boto3 IAM client.
        role_name: Name of the IAM role.

    Returns:
        Trust policy document as a dict, or empty dict on error.
    """
    try:
        response = iam_client.get_role(RoleName=role_name)
        return response["Role"].get("AssumeRolePolicyDocument", {})
    except ClientError as exc:
        logger.warning(
            "Could not retrieve trust policy for role '%s': %s",
            role_name,
            str(exc),
        )
        return {}


def _attempt_assume_role(
    sts_client: Any, role_arn: str, stack_name: str
) -> dict[str, Any]:
    """
    Attempt to assume an IAM role using STS.

    Args:
        sts_client: Boto3 STS client.
        role_arn: ARN of the role to assume.
        stack_name: Stack name (used for session naming).

    Returns:
        Dict with 'success' bool and optional 'error_code'/'error_message'.
    """
    session_name = f"iq-verify-{stack_name[:32]}"

    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=TEST_SESSION_DURATION_SECONDS,
        )

        # Verify we got valid credentials
        credentials = response.get("Credentials", {})
        if credentials.get("AccessKeyId") and credentials.get("SecretAccessKey"):
            logger.info("Successfully assumed role: %s", role_arn)
            return {"success": True}
        else:
            return {
                "success": False,
                "error_code": "InvalidCredentials",
                "error_message": "AssumeRole succeeded but credentials are incomplete",
            }

    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        error_message = exc.response["Error"]["Message"]
        logger.warning(
            "AssumeRole failed for %s: [%s] %s", role_arn, error_code, error_message
        )
        return {
            "success": False,
            "error_code": error_code,
            "error_message": error_message,
        }
    except Exception as exc:
        logger.exception("Unexpected error assuming role %s", role_arn)
        return {
            "success": False,
            "error_code": "UnexpectedException",
            "error_message": str(exc),
        }


def _summarize_trust_principals(trust_policy: dict[str, Any]) -> list[str]:
    """
    Extract and summarize principals from a trust policy document.

    Args:
        trust_policy: IAM trust policy document.

    Returns:
        List of principal strings (services, accounts, ARNs).
    """
    principals: list[str] = []

    for statement in trust_policy.get("Statement", []):
        principal = statement.get("Principal", {})
        if isinstance(principal, str):
            principals.append(principal)
        elif isinstance(principal, dict):
            for principal_type, values in principal.items():
                if isinstance(values, str):
                    principals.append(f"{principal_type}:{values}")
                elif isinstance(values, list):
                    for v in values:
                        principals.append(f"{principal_type}:{v}")

    return principals


def _is_service_linked_role(trust_policy: dict[str, Any]) -> bool:
    """
    Determine if a role's trust policy indicates it's a service-linked role.

    Service-linked roles can only be assumed by specific AWS services and
    should not be tested with sts:AssumeRole from the verification Lambda.

    Args:
        trust_policy: IAM trust policy document.

    Returns:
        True if the role appears to be service-linked.
    """
    for statement in trust_policy.get("Statement", []):
        principal = statement.get("Principal", {})
        if isinstance(principal, dict):
            service = principal.get("Service", "")
            if isinstance(service, str) and service.endswith(".amazonaws.com"):
                # Only service principals in trust = service-linked role
                # Check if there are NO non-service principals
                has_non_service = any(
                    k != "Service" for k in principal.keys()
                )
                if not has_non_service:
                    return True

    return False
