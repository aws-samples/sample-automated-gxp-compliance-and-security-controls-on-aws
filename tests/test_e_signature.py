"""
Unit tests for the 21 CFR Part 11 Electronic Signature Workflow.

Tests cover signature record creation, hash determinism, hash uniqueness
(11.70 linking), re-authentication, and meaning validation.
"""

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# --- Simulated E-Signature Handler Logic ---
# (Mirrors the expected behavior of src/e-signature/handler.py)

VALID_MEANINGS = ["approved", "rejected", "reviewed", "authored", "verified"]


def signature_record_lambda(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """
    Creates an electronic signature record compliant with 21 CFR Part 11.

    The record includes a cryptographic hash binding the signer to the
    record, ensuring non-repudiation and integrity.
    """
    import boto3

    body = json.loads(event.get("body", "{}"))

    record_id = body["record_id"]
    signer_id = body["signer_id"]
    meaning = body["meaning"]
    reason = body.get("reason", "")
    document_hash = body.get("document_hash", "")

    # Validate meaning
    if meaning not in VALID_MEANINGS:
        return {
            "statusCode": 400,
            "body": json.dumps({
                "error": "Invalid signature meaning",
                "valid_meanings": VALID_MEANINGS,
            }),
        }

    # Create timestamp
    timestamp = datetime.now(timezone.utc).isoformat()

    # Generate deterministic signature hash (11.70 linking)
    signature_hash = _compute_signature_hash(
        record_id=record_id,
        signer_id=signer_id,
        meaning=meaning,
        timestamp=timestamp,
        document_hash=document_hash,
    )

    # Build the signature record
    signature_record = {
        "signature_id": f"SIG-{record_id}-{int(time.time())}",
        "record_id": record_id,
        "signer_id": signer_id,
        "meaning": meaning,
        "reason": reason,
        "timestamp": timestamp,
        "signature_hash": signature_hash,
        "document_hash": document_hash,
        "ip_address": event.get("requestContext", {}).get("identity", {}).get("sourceIp", "unknown"),
        "user_agent": event.get("requestContext", {}).get("identity", {}).get("userAgent", "unknown"),
        "cfr_part_11_compliant": True,
    }

    # Store in DynamoDB
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table("gxp-signatures")
    table.put_item(Item=signature_record)

    return {
        "statusCode": 201,
        "body": json.dumps({
            "message": "Signature recorded successfully",
            "signature_id": signature_record["signature_id"],
            "signature_hash": signature_hash,
        }),
    }


def _compute_signature_hash(
    record_id: str,
    signer_id: str,
    meaning: str,
    timestamp: str,
    document_hash: str,
) -> str:
    """
    Compute a deterministic SHA-256 hash for the signature record.

    This implements 21 CFR 11.70 linking requirements: the hash binds
    the signature to the signed record, making them inseparable.
    """
    hash_input = f"{record_id}|{signer_id}|{meaning}|{timestamp}|{document_hash}"
    return hashlib.sha256(hash_input.encode("utf-8")).hexdigest()


def reauth_lambda(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """
    Re-authentication Lambda for 21 CFR Part 11 Section 11.10(a).

    Verifies user credentials before allowing signature operations.
    """
    import boto3

    body = json.loads(event.get("body", "{}"))
    username = body.get("username", "")
    cred_secret = body.get("password", "")

    if not username or not cred_secret:
        return {
            "statusCode": 401,
            "body": json.dumps({"error": "Missing credentials"}),
        }

    cognito_client = boto3.client("cognito-idp")

    try:
        response = cognito_client.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": cred_secret,
            },
            ClientId="gxp-app-client-id",
        )
        return {
            "statusCode": 200,
            "body": json.dumps({
                "authenticated": True,
                "token": response["AuthenticationResult"]["AccessToken"],
            }),
        }
    except cognito_client.exceptions.NotAuthorizedException:
        return {
            "statusCode": 401,
            "body": json.dumps({"error": "Invalid credentials", "authenticated": False}),
        }
    except Exception as e:
        return {
            "statusCode": 401,
            "body": json.dumps({"error": str(e), "authenticated": False}),
        }


def validate_meaning(meaning: str) -> bool:
    """Validate that the signature meaning is one of the allowed values."""
    return meaning in VALID_MEANINGS


# --- Test Cases ---


class TestSignatureRecordCreation:
    """Tests for signature record creation."""

    @patch("boto3.resource")
    def test_signature_record_creates_proper_structure(
        self, mock_boto_resource: MagicMock, sample_signature_event: dict[str, Any]
    ) -> None:
        """Test that the handler creates a signature record with all required fields."""
        mock_table = MagicMock()
        mock_dynamodb = MagicMock()
        mock_dynamodb.Table.return_value = mock_table
        mock_boto_resource.return_value = mock_dynamodb

        result = signature_record_lambda(sample_signature_event)

        assert result["statusCode"] == 201
        body = json.loads(result["body"])
        assert "signature_id" in body
        assert "signature_hash" in body
        assert body["message"] == "Signature recorded successfully"

        # Verify DynamoDB put_item was called with proper structure
        mock_table.put_item.assert_called_once()
        item = mock_table.put_item.call_args[1]["Item"]
        assert "record_id" in item
        assert "signer_id" in item
        assert "meaning" in item
        assert "timestamp" in item
        assert "signature_hash" in item
        assert "document_hash" in item
        assert item["cfr_part_11_compliant"] is True

    @patch("boto3.resource")
    def test_signature_record_captures_ip_and_user_agent(
        self, mock_boto_resource: MagicMock, sample_signature_event: dict[str, Any]
    ) -> None:
        """Test that the signature record captures source IP and user agent."""
        mock_table = MagicMock()
        mock_dynamodb = MagicMock()
        mock_dynamodb.Table.return_value = mock_table
        mock_boto_resource.return_value = mock_dynamodb

        result = signature_record_lambda(sample_signature_event)

        assert result["statusCode"] == 201
        item = mock_table.put_item.call_args[1]["Item"]
        assert item["ip_address"] == "10.0.1.50"
        assert item["user_agent"] == "GxP-Client/1.0"


class TestSignatureHashDeterminism:
    """Tests for signature hash determinism (21 CFR 11.70 linking)."""

    def test_signature_hash_is_deterministic(self) -> None:
        """Test that the same inputs always produce the same hash."""
        inputs = {
            "record_id": "BATCH-2024-001",
            "signer_id": "user@example.com",
            "meaning": "approved",
            "timestamp": "2024-01-15T10:30:00+00:00",
            "document_hash": "sha256:abcdef1234567890",
        }

        hash1 = _compute_signature_hash(**inputs)
        hash2 = _compute_signature_hash(**inputs)
        hash3 = _compute_signature_hash(**inputs)

        assert hash1 == hash2 == hash3

    def test_different_record_ids_produce_different_hashes(self) -> None:
        """Test that different record_ids produce different hashes (11.70 linking)."""
        common_params = {
            "signer_id": "user@example.com",
            "meaning": "approved",
            "timestamp": "2024-01-15T10:30:00+00:00",
            "document_hash": "sha256:abcdef1234567890",
        }

        hash1 = _compute_signature_hash(record_id="BATCH-2024-001", **common_params)
        hash2 = _compute_signature_hash(record_id="BATCH-2024-002", **common_params)
        hash3 = _compute_signature_hash(record_id="BATCH-2024-003", **common_params)

        assert hash1 != hash2
        assert hash2 != hash3
        assert hash1 != hash3

    def test_signature_hash_is_sha256_hex(self) -> None:
        """Test that the hash output is a valid SHA-256 hex string."""
        result = _compute_signature_hash(
            record_id="TEST-001",
            signer_id="signer@test.com",
            meaning="reviewed",
            timestamp="2024-06-01T00:00:00+00:00",
            document_hash="sha256:test",
        )

        # SHA-256 hex digest is 64 characters
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)


class TestReauthLambda:
    """Tests for re-authentication Lambda."""

    @patch("boto3.client")
    def test_reauth_returns_401_on_bad_credentials(self, mock_boto_client: MagicMock) -> None:
        """Test that reauth returns 401 when credentials are invalid."""
        mock_cognito = MagicMock()
        mock_boto_client.return_value = mock_cognito

        # Simulate NotAuthorizedException
        mock_cognito.exceptions = MagicMock()
        mock_cognito.exceptions.NotAuthorizedException = type(
            "NotAuthorizedException", (Exception,), {}
        )
        mock_cognito.initiate_auth.side_effect = (
            mock_cognito.exceptions.NotAuthorizedException("Bad creds")
        )

        event = {
            "body": json.dumps({"username": "user@test.com", "password": "wrong-value"}),
        }

        result = reauth_lambda(event)

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["authenticated"] is False

    @patch("boto3.client")
    def test_reauth_returns_401_on_missing_credentials(self, mock_boto_client: MagicMock) -> None:
        """Test that reauth returns 401 when credentials are missing."""
        event = {"body": json.dumps({"username": "", "password": ""})}

        result = reauth_lambda(event)

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert "Missing credentials" in body["error"]

    @patch("boto3.client")
    def test_reauth_returns_200_on_valid_credentials(self, mock_boto_client: MagicMock) -> None:
        """Test that reauth returns 200 with token on valid credentials."""
        mock_cognito = MagicMock()
        mock_boto_client.return_value = mock_cognito
        mock_cognito.exceptions = MagicMock()
        mock_cognito.exceptions.NotAuthorizedException = type(
            "NotAuthorizedException", (Exception,), {}
        )
        mock_cognito.initiate_auth.return_value = {
            "AuthenticationResult": {"AccessToken": "valid-jwt-token-here"}
        }

        event = {
            "body": json.dumps({"username": "user@test.com", "password": "correct-value"}),
        }

        result = reauth_lambda(event)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["authenticated"] is True
        assert body["token"] == "valid-jwt-token-here"


class TestMeaningValidation:
    """Tests for signature meaning validation."""

    def test_valid_meanings_are_accepted(self) -> None:
        """Test that all valid meanings pass validation."""
        for meaning in VALID_MEANINGS:
            assert validate_meaning(meaning) is True

    def test_invalid_meaning_is_rejected(self) -> None:
        """Test that invalid meanings are rejected."""
        invalid_meanings = ["acknowledged", "signed", "APPROVED", "Accept", "", "null"]
        for meaning in invalid_meanings:
            assert validate_meaning(meaning) is False

    @patch("boto3.resource")
    def test_signature_lambda_rejects_invalid_meaning(
        self, mock_boto_resource: MagicMock
    ) -> None:
        """Test that the signature Lambda returns 400 for invalid meanings."""
        event = {
            "body": json.dumps({
                "record_id": "BATCH-2024-001",
                "signer_id": "user@test.com",
                "meaning": "acknowledged",  # Not a valid meaning
                "document_hash": "sha256:test",
            }),
            "requestContext": {"identity": {}},
        }

        result = signature_record_lambda(event)

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert "Invalid signature meaning" in body["error"]
        assert "valid_meanings" in body
