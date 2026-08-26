"""
IQ Check: Encryption Access Verification
==========================================
Verifies that KMS encryption keys deployed by the stack are accessible and
operational by performing actual encrypt/decrypt operations with test data,
and confirming that automatic key rotation is enabled.

This check validates the Installation Qualification requirement that data
protection mechanisms are correctly installed and functional. For GxP
compliance (21 CFR Part 11, EU Annex 11), encryption at rest is mandatory
for electronic records, and key rotation ensures cryptographic hygiene.

Verification Scope:
- KMS key discoverability from the stack
- kms:Encrypt operation with test plaintext
- kms:Decrypt operation to verify round-trip integrity
- Data integrity validation (plaintext matches after round-trip)
- Automatic key rotation status verification
"""

import base64
import logging
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Test plaintext for encrypt/decrypt verification
# Using a known string that can validate round-trip integrity
TEST_PLAINTEXT = b"GxP-IQ-Verification-Test-Data-2024"

# Encryption context for audit trail (GxP requirement)
ENCRYPTION_CONTEXT = {
    "purpose": "iq-verification",
    "framework": "gxp-compliance-automation",
}


def run_check(config: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Verify KMS key accessibility, encrypt/decrypt functionality, and rotation status.

    Discovers KMS keys from the CloudFormation stack, then performs actual
    cryptographic operations to confirm the keys are fully operational.

    Args:
        config: Dictionary containing:
            - stack_name (str): CloudFormation stack name
            - region (str): AWS region
            - account_id (str): AWS account ID

    Returns:
        List of check result dicts for each KMS key verification, containing:
            - check_name: Identifier for this specific encryption test
            - status: "PASS" or "FAIL"
            - details: Human-readable description of the result
            - timestamp: ISO 8601 timestamp of the check execution
    """
    region = config["region"]
    stack_name = config["stack_name"]
    results: list[dict[str, Any]] = []

    logger.info(
        "Starting encryption access verification for stack '%s'", stack_name
    )

    # Discover KMS keys from the stack
    kms_keys = _discover_stack_kms_keys(stack_name, region)

    if not kms_keys:
        logger.warning("No KMS keys found in stack '%s'", stack_name)
        results.append({
            "check_name": "encryption_access_discovery",
            "status": "FAIL",
            "details": (
                f"No KMS keys discovered in stack '{stack_name}'. "
                f"GxP workloads require encryption at rest. "
                f"Verify the stack includes KMS key resources."
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return results

    kms_client = boto3.client("kms", region_name=region)

    for key_info in kms_keys:
        key_id = key_info["key_id"]
        key_arn = key_info.get("arn", key_id)
        logical_id = key_info.get("logical_id", "Unknown")

        # Check 1: Encrypt/Decrypt round-trip
        encrypt_result = _verify_encrypt_decrypt(kms_client, key_id, logical_id)
        results.append(encrypt_result)

        # Check 2: Key rotation status
        rotation_result = _verify_key_rotation(kms_client, key_id, logical_id)
        results.append(rotation_result)

    logger.info(
        "Encryption access verification complete: %d/%d passed",
        sum(1 for r in results if r["status"] == "PASS"),
        len(results),
    )

    return results


def _discover_stack_kms_keys(
    stack_name: str, region: str
) -> list[dict[str, str]]:
    """
    Discover KMS keys created by the CloudFormation stack.

    Args:
        stack_name: CloudFormation stack name.
        region: AWS region.

    Returns:
        List of dicts with 'key_id', 'arn', and 'logical_id' for each key.
    """
    keys: list[dict[str, str]] = []

    try:
        cfn_client = boto3.client("cloudformation", region_name=region)
        paginator = cfn_client.get_paginator("list_stack_resources")

        for page in paginator.paginate(StackName=stack_name):
            for resource in page.get("StackResourceSummaries", []):
                if resource["ResourceType"] in (
                    "AWS::KMS::Key",
                    "AWS::KMS::ReplicaKey",
                ):
                    physical_id = resource.get("PhysicalResourceId", "")
                    logical_id = resource.get("LogicalResourceId", "")
                    if physical_id:
                        keys.append({
                            "key_id": physical_id,
                            "arn": physical_id,  # Physical ID for KMS is the key ID/ARN
                            "logical_id": logical_id,
                        })

    except ClientError as exc:
        logger.error(
            "Failed to discover KMS keys from stack: [%s] %s",
            exc.response["Error"]["Code"],
            exc.response["Error"]["Message"],
        )
    except Exception as exc:
        logger.exception("Unexpected error discovering KMS keys: %s", str(exc))

    return keys


def _verify_encrypt_decrypt(
    kms_client: Any, key_id: str, logical_id: str
) -> dict[str, Any]:
    """
    Perform an encrypt/decrypt round-trip to verify key operational status.

    Args:
        kms_client: Boto3 KMS client.
        key_id: KMS key ID or ARN.
        logical_id: CloudFormation logical resource ID.

    Returns:
        Check result dict with status and details.
    """
    check_name = f"encryption_access_roundtrip_{logical_id}"
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        # Step 1: Encrypt test data
        logger.info("Encrypting test data with key: %s", key_id)
        encrypt_response = kms_client.encrypt(
            KeyId=key_id,
            Plaintext=TEST_PLAINTEXT,
            EncryptionContext=ENCRYPTION_CONTEXT,
        )
        ciphertext_blob = encrypt_response["CiphertextBlob"]
        encrypting_key_id = encrypt_response["KeyId"]

        if not ciphertext_blob:
            return {
                "check_name": check_name,
                "status": "FAIL",
                "details": (
                    f"KMS Encrypt returned empty ciphertext for key '{logical_id}' "
                    f"({key_id}). Key may be in an unusable state."
                ),
                "timestamp": timestamp,
                "key_id": key_id,
            }

        # Step 2: Decrypt the ciphertext
        logger.info("Decrypting test data with key: %s", key_id)
        decrypt_response = kms_client.decrypt(
            CiphertextBlob=ciphertext_blob,
            EncryptionContext=ENCRYPTION_CONTEXT,
        )
        decrypted_plaintext = decrypt_response["Plaintext"]

        # Step 3: Verify data integrity (round-trip)
        if decrypted_plaintext == TEST_PLAINTEXT:
            ciphertext_b64 = base64.b64encode(ciphertext_blob).decode("utf-8")[:32]
            return {
                "check_name": check_name,
                "status": "PASS",
                "details": (
                    f"KMS key '{logical_id}' ({key_id}) encrypt/decrypt round-trip "
                    f"successful. Data integrity verified. "
                    f"Encrypting key: {encrypting_key_id}. "
                    f"Ciphertext sample: {ciphertext_b64}..."
                ),
                "timestamp": timestamp,
                "key_id": key_id,
                "encrypting_key_arn": encrypting_key_id,
            }
        else:
            return {
                "check_name": check_name,
                "status": "FAIL",
                "details": (
                    f"KMS key '{logical_id}' ({key_id}) data integrity check FAILED. "
                    f"Decrypted plaintext does not match original. "
                    f"This indicates a critical encryption system error."
                ),
                "timestamp": timestamp,
                "key_id": key_id,
            }

    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        error_message = exc.response["Error"]["Message"]
        logger.error(
            "KMS encrypt/decrypt failed for key %s: [%s] %s",
            key_id,
            error_code,
            error_message,
        )
        return {
            "check_name": check_name,
            "status": "FAIL",
            "details": (
                f"KMS encrypt/decrypt operation failed for key '{logical_id}' "
                f"({key_id}). Error: [{error_code}] {error_message}. "
                f"Verify the Lambda execution role has kms:Encrypt and "
                f"kms:Decrypt permissions on this key."
            ),
            "timestamp": timestamp,
            "key_id": key_id,
            "error_code": error_code,
        }
    except Exception as exc:
        logger.exception("Unexpected error in encrypt/decrypt for key %s", key_id)
        return {
            "check_name": check_name,
            "status": "FAIL",
            "details": (
                f"Unexpected error during encrypt/decrypt verification for key "
                f"'{logical_id}' ({key_id}): {str(exc)}"
            ),
            "timestamp": timestamp,
            "key_id": key_id,
        }


def _verify_key_rotation(
    kms_client: Any, key_id: str, logical_id: str
) -> dict[str, Any]:
    """
    Verify that automatic key rotation is enabled for the KMS key.

    Key rotation is a GxP compliance requirement to ensure cryptographic
    hygiene and limit the exposure window of any single key version.

    Args:
        kms_client: Boto3 KMS client.
        key_id: KMS key ID or ARN.
        logical_id: CloudFormation logical resource ID.

    Returns:
        Check result dict with status and details.
    """
    check_name = f"encryption_key_rotation_{logical_id}"
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        response = kms_client.get_key_rotation_status(KeyId=key_id)
        rotation_enabled = response.get("KeyRotationEnabled", False)

        if rotation_enabled:
            # Get rotation period if available (newer API)
            rotation_period = response.get("RotationPeriodInDays", "default (365)")
            return {
                "check_name": check_name,
                "status": "PASS",
                "details": (
                    f"Automatic key rotation is ENABLED for key '{logical_id}' "
                    f"({key_id}). Rotation period: {rotation_period} days. "
                    f"Meets GxP cryptographic hygiene requirements."
                ),
                "timestamp": timestamp,
                "key_id": key_id,
                "rotation_enabled": True,
                "rotation_period_days": rotation_period,
            }
        else:
            return {
                "check_name": check_name,
                "status": "FAIL",
                "details": (
                    f"Automatic key rotation is DISABLED for key '{logical_id}' "
                    f"({key_id}). GxP compliance requires automatic key rotation "
                    f"to be enabled for all customer-managed KMS keys. "
                    f"Enable rotation via aws kms enable-key-rotation."
                ),
                "timestamp": timestamp,
                "key_id": key_id,
                "rotation_enabled": False,
            }

    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        error_message = exc.response["Error"]["Message"]

        # Some key types (asymmetric, HMAC) don't support rotation
        if error_code == "UnsupportedOperationException":
            return {
                "check_name": check_name,
                "status": "PASS",
                "details": (
                    f"Key '{logical_id}' ({key_id}) does not support automatic "
                    f"rotation (likely asymmetric or HMAC key type). "
                    f"Manual rotation procedures should be documented."
                ),
                "timestamp": timestamp,
                "key_id": key_id,
                "rotation_enabled": None,
                "note": "Key type does not support automatic rotation",
            }

        logger.error(
            "Failed to check rotation status for key %s: [%s] %s",
            key_id,
            error_code,
            error_message,
        )
        return {
            "check_name": check_name,
            "status": "FAIL",
            "details": (
                f"Cannot verify key rotation status for '{logical_id}' ({key_id}). "
                f"Error: [{error_code}] {error_message}. "
                f"Verify Lambda has kms:GetKeyRotationStatus permission."
            ),
            "timestamp": timestamp,
            "key_id": key_id,
            "error_code": error_code,
        }
    except Exception as exc:
        logger.exception(
            "Unexpected error checking rotation for key %s", key_id
        )
        return {
            "check_name": check_name,
            "status": "FAIL",
            "details": (
                f"Unexpected error verifying key rotation for '{logical_id}' "
                f"({key_id}): {str(exc)}"
            ),
            "timestamp": timestamp,
            "key_id": key_id,
        }
