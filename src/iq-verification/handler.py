"""
IQ Verification Lambda Handler
================================
Installation Qualification (IQ) verification for GxP-compliant AWS infrastructure.

This Lambda function executes all IQ verification checks against a deployed CloudFormation
stack and produces a structured JSON report suitable for inclusion in a Validation Summary
Report (VSR) as the IQ deliverable in the V-model qualification lifecycle.

The IQ report verifies that:
- Infrastructure is installed correctly per design specifications
- Network connectivity meets requirements
- IAM trust relationships are properly configured
- Encryption mechanisms are operational
- Integration endpoints are reachable and functional

Environment Variables:
    IQ_REPORT_BUCKET: S3 bucket name for storing IQ verification reports
"""

import importlib
import json
import logging
import os
import pkgutil
from datetime import datetime, timezone
from typing import Any

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Module-level constants
CHECKS_PACKAGE = "checks"
REPORT_PREFIX = "iq-reports"


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Main Lambda handler for IQ Verification.

    Accepts a CloudFormation stack reference, runs all qualification checks,
    generates a structured IQ report, stores it in S3, and returns the result.

    Args:
        event: Lambda event containing:
            - stack_name (str): CloudFormation stack name to verify
            - region (str): AWS region where the stack is deployed
            - account_id (str): AWS account ID owning the stack
        context: Lambda context object (runtime metadata)

    Returns:
        dict with keys:
            - status: "PASS" or "FAIL"
            - report_s3_key: S3 object key where the full report is stored
            - summary: Brief summary of results
            - report: Full IQ report object
    """
    logger.info("IQ Verification Lambda invoked with event: %s", json.dumps(event))

    # Validate required input parameters
    stack_name = event.get("stack_name")
    region = event.get("region")
    account_id = event.get("account_id")

    if not all([stack_name, region, account_id]):
        error_msg = (
            "Missing required parameters. Expected: stack_name, region, account_id"
        )
        logger.error(error_msg)
        return {
            "status": "FAIL",
            "report_s3_key": None,
            "summary": error_msg,
            "report": None,
        }

    # Build configuration passed to each check module
    config: dict[str, Any] = {
        "stack_name": stack_name,
        "region": region,
        "account_id": account_id,
        "execution_id": getattr(context, "aws_request_id", "local-execution"),
        "function_name": getattr(context, "function_name", "iq-verification-local"),
    }

    # Discover and run all check modules
    check_results = _run_all_checks(config)

    # Build the IQ report
    report = _build_iq_report(config, check_results)

    # Persist report to S3
    report_s3_key = _save_report_to_s3(report, stack_name)

    # Determine overall status
    overall_status = report["overall_status"]
    passed_count = sum(1 for c in check_results if c["status"] == "PASS")
    total_count = len(check_results)

    summary = (
        f"IQ Verification {overall_status}: "
        f"{passed_count}/{total_count} checks passed for stack '{stack_name}'"
    )
    logger.info(summary)

    return {
        "status": overall_status,
        "report_s3_key": report_s3_key,
        "summary": summary,
        "report": report,
    }


def _run_all_checks(config: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Discover and execute all check modules in the checks/ package.

    Each module must expose a `run_check(config: dict) -> dict` function.

    Args:
        config: Configuration dictionary passed to each check.

    Returns:
        List of check result dictionaries.
    """
    results: list[dict[str, Any]] = []
    checks_path = os.path.join(os.path.dirname(__file__), CHECKS_PACKAGE)

    logger.info("Discovering check modules in: %s", checks_path)

    for importer, module_name, is_pkg in pkgutil.iter_modules([checks_path]):
        if module_name.startswith("_"):
            continue

        full_module_name = f"{CHECKS_PACKAGE}.{module_name}"
        logger.info("Loading check module: %s", full_module_name)

        try:
            module = importlib.import_module(full_module_name)

            if not hasattr(module, "run_check"):
                logger.warning(
                    "Module %s does not have run_check function, skipping",
                    full_module_name,
                )
                continue

            logger.info("Executing check: %s", module_name)
            result = module.run_check(config)

            # Validate result structure
            if isinstance(result, list):
                # Some checks return multiple sub-results
                for sub_result in result:
                    _validate_check_result(sub_result, module_name)
                    results.append(sub_result)
            elif isinstance(result, dict):
                _validate_check_result(result, module_name)
                results.append(result)
            else:
                logger.error(
                    "Check %s returned invalid type: %s", module_name, type(result)
                )
                results.append({
                    "check_name": module_name,
                    "status": "FAIL",
                    "details": f"Check returned invalid result type: {type(result)}",
                    "timestamp": _now_iso(),
                })

        except Exception as exc:
            logger.exception("Check module %s raised an exception", full_module_name)
            results.append({
                "check_name": module_name,
                "status": "FAIL",
                "details": f"Unhandled exception during check execution: {str(exc)}",
                "timestamp": _now_iso(),
            })

    return results


def _validate_check_result(result: dict[str, Any], module_name: str) -> None:
    """
    Validate that a check result has the required fields.

    Args:
        result: The check result dictionary.
        module_name: Name of the module that produced the result.
    """
    required_keys = {"check_name", "status", "details", "timestamp"}
    missing = required_keys - set(result.keys())
    if missing:
        logger.warning(
            "Check result from %s missing keys: %s. Adding defaults.",
            module_name,
            missing,
        )
        result.setdefault("check_name", module_name)
        result.setdefault("status", "FAIL")
        result.setdefault("details", "Result missing required fields")
        result.setdefault("timestamp", _now_iso())

    # Normalize status
    if result["status"] not in ("PASS", "FAIL"):
        logger.warning(
            "Check %s returned non-standard status '%s', normalizing to FAIL",
            result["check_name"],
            result["status"],
        )
        result["status"] = "FAIL"


def _build_iq_report(
    config: dict[str, Any], check_results: list[dict[str, Any]]
) -> dict[str, Any]:
    """
    Build the complete IQ Verification Report.

    This report structure maps to the Installation Qualification deliverable
    in the V-model validation lifecycle. It contains sufficient detail for
    inclusion in a Validation Summary Report (VSR).

    Args:
        config: Execution configuration.
        check_results: List of all individual check results.

    Returns:
        Complete IQ report dictionary.
    """
    failed_checks = [c for c in check_results if c["status"] == "FAIL"]
    overall_status = "PASS" if not failed_checks else "FAIL"

    # Build deviations list from failed checks (GxP deviation tracking)
    deviations: list[dict[str, str]] = []
    for idx, failed in enumerate(failed_checks, start=1):
        deviations.append({
            "deviation_id": f"IQ-DEV-{idx:04d}",
            "check_name": failed["check_name"],
            "description": failed["details"],
            "severity": "CRITICAL" if "error" in failed["details"].lower() else "MAJOR",
            "timestamp": failed["timestamp"],
            "remediation_status": "OPEN",
        })

    report: dict[str, Any] = {
        "report_type": "Installation Qualification (IQ)",
        "report_version": "1.0.0",
        "stack_name": config["stack_name"],
        "region": config["region"],
        "account_id": config["account_id"],
        "execution_id": config["execution_id"],
        "function_name": config["function_name"],
        "timestamp": _now_iso(),
        "overall_status": overall_status,
        "summary": {
            "total_checks": len(check_results),
            "passed": sum(1 for c in check_results if c["status"] == "PASS"),
            "failed": len(failed_checks),
            "pass_rate_percent": round(
                (sum(1 for c in check_results if c["status"] == "PASS")
                 / max(len(check_results), 1)) * 100, 2
            ),
        },
        "checks": check_results,
        "deviations": deviations,
        "validation_metadata": {
            "qualification_type": "IQ",
            "v_model_phase": "Installation Qualification",
            "regulatory_framework": "GxP (21 CFR Part 11, EU Annex 11)",
            "document_reference": "Validation Summary Report (VSR)",
            "gamp5_category": "Category 5 - Custom Application",
            "approval_status": "PENDING_REVIEW",
        },
    }

    return report


def _save_report_to_s3(report: dict[str, Any], stack_name: str) -> str | None:
    """
    Persist the IQ report to the designated S3 bucket.

    Args:
        report: The complete IQ report dictionary.
        stack_name: Stack name used for the S3 key prefix.

    Returns:
        The S3 object key if successful, None otherwise.
    """
    bucket_name = os.environ.get("IQ_REPORT_BUCKET")
    if not bucket_name:
        logger.error("IQ_REPORT_BUCKET environment variable is not set")
        return None

    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    s3_key = f"{REPORT_PREFIX}/{stack_name}/{timestamp_slug}/iq-report.json"

    try:
        s3_client = boto3.client("s3", region_name=report["region"])
        s3_client.put_object(
            Bucket=bucket_name,
            Key=s3_key,
            Body=json.dumps(report, indent=2, default=str),
            ContentType="application/json",
            ServerSideEncryption="aws:kms",
            Metadata={
                "report-type": "iq-verification",
                "stack-name": stack_name,
                "overall-status": report["overall_status"],
            },
        )
        logger.info("IQ report saved to s3://%s/%s", bucket_name, s3_key)
        return s3_key

    except Exception as exc:
        logger.exception("Failed to save IQ report to S3: %s", str(exc))
        return None


def _now_iso() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()
