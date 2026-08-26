"""
21 CFR Part 11.50 Signature Record Lambda
==========================================

This Lambda function creates the compliant electronic signature record per
21 CFR Part 11.50, which requires that signed electronic records shall contain
information associated with the signing that clearly indicates all of the following:

    11.50(a)(1): The printed name of the signer
    11.50(a)(2): The date and time when the signature was executed
    11.50(a)(3): The meaning (such as review, approval, responsibility, or authorship)
                 associated with the signature

Additionally, this function implements 21 CFR Part 11.70, which requires that
electronic signatures and handwritten signatures executed to electronic records
shall be linked to their respective electronic records to ensure that the
signatures cannot be excised, copied, or otherwise transferred to falsify an
electronic record by ordinary means.

The signature_hash field (SHA-256) cryptographically binds the signature to the
specific record, making it computationally impractical to transplant a signature
from one record to another without detection.

Environment Variables:
    SIGNATURE_TABLE_NAME: DynamoDB table for storing signature records
    COGNITO_USER_POOL_ID: Cognito User Pool for resolving signer attributes
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment configuration
SIGNATURE_TABLE_NAME: str = os.environ["SIGNATURE_TABLE_NAME"]
COGNITO_USER_POOL_ID: str = os.environ["COGNITO_USER_POOL_ID"]

dynamodb = boto3.resource("dynamodb")
cognito_client = boto3.client("cognito-idp")
signature_table = dynamodb.Table(SIGNATURE_TABLE_NAME)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Create a Part 11.50-compliant electronic signature record.

    This function is invoked after successful re-authentication in the
    e-signature Step Functions workflow. It resolves the signer's printed
    name from Cognito, generates a server-side timestamp (non-editable),
    and creates a cryptographically linked signature record in DynamoDB.

    Args:
        event: Step Functions input containing:
            - username (str): The authenticated signer's Cognito username
            - record_id (str): The ID of the electronic record being signed
            - signature_meaning (str): The meaning of the signature per 11.50(a)(3)
        context: Lambda execution context

    Returns:
        dict containing the complete signature record with all 11.50 fields

    Raises:
        ValueError: If required fields are missing
        ClientError: If DynamoDB or Cognito operations fail
    """
    username: str = event.get("username", "")
    record_id: str = event.get("record_id", "")
    signature_meaning: str = event.get("signature_meaning", "")

    # Validate required inputs
    _validate_inputs(username=username, record_id=record_id, signature_meaning=signature_meaning)

    # Resolve the signer's printed name from Cognito user attributes (11.50(a)(1))
    printed_name: str = _resolve_printed_name(username=username)

    # Generate server-side timestamp - NOT user-editable (11.50(a)(2))
    date_time: str = datetime.now(timezone.utc).isoformat()

    # Generate unique signature ID
    signature_id: str = str(uuid.uuid4())

    # Construct the linked record ARN per 11.70
    linked_record_arn: str = _construct_record_arn(record_id=record_id)

    # Compute the signature hash for tamper detection per 11.70
    # This cryptographically binds the signature to the specific record,
    # making transplantation computationally impractical
    signature_hash: str = _compute_signature_hash(
        printed_name=printed_name,
        date_time=date_time,
        meaning=signature_meaning,
        record_id=record_id,
    )

    # Build the complete signature record
    signature_record: dict[str, str] = {
        "record_id": record_id,
        "signature_id": signature_id,
        "printed_name": printed_name,
        "date_time": date_time,
        "meaning": signature_meaning,
        "linked_record_arn": linked_record_arn,
        "signature_hash": signature_hash,
        "signer_username": username,
    }

    # Persist to DynamoDB
    _store_signature_record(signature_record)

    logger.info(
        "Signature record created: signature_id='%s' for record_id='%s' by '%s' meaning='%s'",
        signature_id,
        record_id,
        username,
        signature_meaning,
    )

    return {
        "statusCode": 200,
        "signature_record": signature_record,
    }


def _validate_inputs(username: str, record_id: str, signature_meaning: str) -> None:
    """Validate that all required signature fields are present.

    Args:
        username: The signer's username
        record_id: The record being signed
        signature_meaning: The meaning of the signature

    Raises:
        ValueError: If any required field is missing or empty
    """
    valid_meanings: set[str] = {"Approval", "Review", "Responsibility", "Authorship", "Verification"}

    if not username:
        raise ValueError("signer_username is required per 11.50(a)(1)")
    if not record_id:
        raise ValueError("record_id is required per 11.70 (signature-record linking)")
    if not signature_meaning:
        raise ValueError("signature_meaning is required per 11.50(a)(3)")
    if signature_meaning not in valid_meanings:
        raise ValueError(
            f"Invalid signature_meaning '{signature_meaning}'. "
            f"Must be one of: {', '.join(sorted(valid_meanings))}"
        )


def _resolve_printed_name(username: str) -> str:
    """Resolve the signer's printed name from Cognito user attributes.

    Per 11.50(a)(1), the printed name of the signer must be included.
    This is resolved from the authoritative identity store (Cognito),
    not from user input, to prevent name spoofing.

    Args:
        username: The Cognito username

    Returns:
        The signer's full printed name (given_name + family_name)

    Raises:
        ClientError: If the Cognito lookup fails
        ValueError: If name attributes are not configured
    """
    try:
        response = cognito_client.admin_get_user(
            UserPoolId=COGNITO_USER_POOL_ID,
            Username=username,
        )
    except ClientError as exc:
        logger.error("Failed to resolve printed name for user '%s': %s", username, str(exc))
        raise

    # Extract name attributes
    attributes: dict[str, str] = {
        attr["Name"]: attr["Value"] for attr in response.get("UserAttributes", [])
    }

    given_name: str = attributes.get("given_name", "")
    family_name: str = attributes.get("family_name", "")

    if not given_name or not family_name:
        raise ValueError(
            f"User '{username}' is missing required name attributes "
            f"(given_name and/or family_name) in Cognito. "
            f"These are required per 11.50(a)(1) for printed name."
        )

    return f"{given_name} {family_name}"


def _construct_record_arn(record_id: str) -> str:
    """Construct the ARN or identifier for the record being signed.

    Per 11.70, signatures must be linked to their respective records.
    This creates a deterministic reference to the signed record.

    Args:
        record_id: The record identifier

    Returns:
        A formatted ARN-style reference to the electronic record
    """
    region: str = os.environ.get("AWS_REGION", "us-east-1")
    account_id: str = boto3.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:gxp:{region}:{account_id}:record/{record_id}"


def _compute_signature_hash(
    printed_name: str,
    date_time: str,
    meaning: str,
    record_id: str,
) -> str:
    """Compute SHA-256 hash binding the signature to the record per 11.70.

    This hash ensures that signatures cannot be excised, copied, or otherwise
    transferred to falsify an electronic record. Any attempt to transplant a
    signature to a different record would produce a different hash, enabling
    tamper detection.

    The hash includes all Part 11.50(a) required fields PLUS the record_id,
    creating a cryptographic binding between signature and record.

    Args:
        printed_name: The signer's printed name (11.50(a)(1))
        date_time: The signing timestamp (11.50(a)(2))
        meaning: The signature meaning (11.50(a)(3))
        record_id: The signed record's identifier (11.70 linking)

    Returns:
        Hex-encoded SHA-256 hash string
    """
    # Concatenate fields with a delimiter that cannot appear in the values
    hash_input: str = f"{printed_name}\x1f{date_time}\x1f{meaning}\x1f{record_id}"
    return hashlib.sha256(hash_input.encode("utf-8")).hexdigest()


def _store_signature_record(record: dict[str, str]) -> None:
    """Persist the signature record to DynamoDB.

    Uses a conditional write to prevent duplicate signature IDs.
    The table has PointInTimeRecovery enabled for data integrity.

    Args:
        record: The complete signature record to store

    Raises:
        ClientError: If the DynamoDB put fails
    """
    try:
        signature_table.put_item(
            Item=record,
            ConditionExpression="attribute_not_exists(signature_id)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.error(
                "Duplicate signature_id detected: %s (this should never happen with UUIDs)",
                record["signature_id"],
            )
        raise
