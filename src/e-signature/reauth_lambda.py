"""
21 CFR Part 11.50 Re-Authentication Lambda
==========================================

This Lambda function implements the re-authentication requirement of 21 CFR Part 11.50,
which mandates that electronic signatures shall be executed by the signer at the time
of signing. Re-authentication ensures that the individual executing the signature is
indeed the authorized signer and has not left their session unattended.

Per 11.100(a), each electronic signature must be unique to one individual and shall
not be reused or reassigned. This function verifies the signer's identity immediately
prior to signature creation by requiring fresh credential validation through
Amazon Cognito's ADMIN_USER_PASSWORD_AUTH flow.

Environment Variables:
    COGNITO_USER_POOL_ID: The Cognito User Pool ID for credential verification
    COGNITO_CLIENT_ID: The Cognito App Client ID (must allow ADMIN_USER_PASSWORD_AUTH)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment configuration
COGNITO_USER_POOL_ID: str = os.environ["COGNITO_USER_POOL_ID"]
COGNITO_CLIENT_ID: str = os.environ["COGNITO_CLIENT_ID"]

cognito_client = boto3.client("cognito-idp")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Re-authenticate the signer at the time of signing per 21 CFR Part 11.50.

    This function is invoked as part of the e-signature Step Functions workflow.
    It validates the signer's credentials against Cognito to confirm identity
    immediately before the signature record is created.

    Args:
        event: Step Functions input containing:
            - username (str): The signer's Cognito username
            - credential (str): The signer's current credential for re-authentication
            - record_id (str): The ID of the record being signed (passed through)
            - signature_meaning (str): The meaning of the signature (passed through)
        context: Lambda execution context

    Returns:
        dict containing:
            - statusCode (int): HTTP status code (200 on success, 401 on failure)
            - authenticated (bool): Whether re-authentication succeeded
            - username (str): The authenticated username
            - record_id (str): Pass-through of the record being signed
            - signature_meaning (str): Pass-through of the signature meaning
            - error (str): Error message (on failure only)

        Note:
            Cognito tokens are intentionally NOT returned. Downstream steps
            re-derive authorization from username + record_id, and returning
            live tokens would expose them via Step Functions execution history
            and CloudWatch Logs (see the success-path comment below).
    """
    username: str = event.get("username", "")
    # nosec B105 - credential from signer input, not hardcoded
    credential: str = event.get("password", "")
    record_id: str = event.get("record_id", "")
    signature_meaning: str = event.get("signature_meaning", "")

    if not username or not credential:
        logger.warning("Re-authentication attempt with missing credentials")
        return _build_failure_response(
            username=username,
            record_id=record_id,
            signature_meaning=signature_meaning,
            error="Username and password are required for re-authentication",
        )

    try:
        auth_result = _authenticate_user(username=username, credential=credential)
        logger.info(
            "Re-authentication successful for user '%s' signing record '%s'",
            username,
            record_id,
        )
        # Do NOT return the Cognito tokens. This Lambda's output is written to
        # Step Functions execution history (retained up to 90 days, not
        # customer-managed-key encrypted by default) and may reach CloudWatch
        # Logs. Returning live AccessToken/IdToken would allow any principal
        # with states:GetExecutionHistory or Logs read access to replay them
        # and impersonate the signer (21 CFR Part 11.100(a) uniqueness control).
        # Downstream steps re-derive authorization from username + record_id,
        # so the tokens are not needed here.
        _ = auth_result  # authentication verified; tokens intentionally discarded
        return {
            "statusCode": 200,
            "authenticated": True,
            "username": username,
            "record_id": record_id,
            "signature_meaning": signature_meaning,
        }

    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        logger.warning(
            "Re-authentication failed for user '%s': %s - %s",
            username,
            error_code,
            exc.response["Error"]["Message"],
        )
        return _build_failure_response(
            username=username,
            record_id=record_id,
            signature_meaning=signature_meaning,
            error="Re-authentication failed",
        )

    except Exception as exc:
        logger.error(
            "Unexpected error during re-authentication for user '%s': %s",
            username,
            str(exc),
        )
        return _build_failure_response(
            username=username,
            record_id=record_id,
            signature_meaning=signature_meaning,
            error="Re-authentication failed",
        )


def _authenticate_user(username: str, credential: str) -> dict[str, str]:
    """Invoke Cognito AdminInitiateAuth with ADMIN_USER_PASSWORD_AUTH flow.

    Per 21 CFR Part 11.300, electronic signatures based on use of identification
    codes in combination with passwords shall employ controls to ensure their
    security and integrity. Cognito provides the secure credential store.

    Args:
        username: The Cognito username
        credential: The user's password for re-authentication

    Returns:
        dict containing AccessToken, IdToken, and RefreshToken from Cognito

    Raises:
        ClientError: If authentication fails (invalid credentials, user disabled, etc.)
    """
    response = cognito_client.admin_initiate_auth(
        UserPoolId=COGNITO_USER_POOL_ID,
        ClientId=COGNITO_CLIENT_ID,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={
            "USERNAME": username,
            "PASSWORD": credential,
        },
    )
    return response["AuthenticationResult"]


def _build_failure_response(
    username: str,
    record_id: str,
    signature_meaning: str,
    error: str,
) -> dict[str, Any]:
    """Build a standardized failure response for re-authentication.

    Args:
        username: The username that failed authentication
        record_id: The record that was being signed
        signature_meaning: The intended signature meaning
        error: Human-readable error message

    Returns:
        Standardized failure response dictionary
    """
    return {
        "statusCode": 401,
        "authenticated": False,
        "username": username,
        "record_id": record_id,
        "signature_meaning": signature_meaning,
        "error": error,
    }
