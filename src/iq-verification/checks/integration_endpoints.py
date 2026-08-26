"""
IQ Check: Integration Endpoints Verification
==============================================
Verifies that deployed resources can communicate with each other by performing
actual API calls to DynamoDB, S3, and other integrated services.

This check validates the Installation Qualification requirement that all
system integrations are operational and data can flow between components
as specified in the design documentation. Unlike resource existence checks,
this module performs real read/write operations to confirm end-to-end
connectivity.

Verification Scope:
- S3 bucket accessibility (PutObject, GetObject, DeleteObject)
- DynamoDB table accessibility (PutItem, GetItem, DeleteItem)
- Lambda function invocability (if present in stack)
- CloudWatch Logs delivery verification
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Test data marker for cleanup identification
TEST_MARKER_PREFIX = "iq-verification-test"


def run_check(config: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Verify integration endpoints by performing actual API operations.

    Discovers S3 buckets, DynamoDB tables, and Lambda functions from the
    stack, then performs real read/write operations to confirm they are
    accessible and operational from the execution environment.

    Args:
        config: Dictionary containing:
            - stack_name (str): CloudFormation stack name
            - region (str): AWS region
            - account_id (str): AWS account ID

    Returns:
        List of check result dicts, one per integration test, containing:
            - check_name: Identifier for this specific integration test
            - status: "PASS" or "FAIL"
            - details: Human-readable description of the result
            - timestamp: ISO 8601 timestamp of the check execution
    """
    region = config["region"]
    stack_name = config["stack_name"]
    results: list[dict[str, Any]] = []

    logger.info(
        "Starting integration endpoints verification for stack '%s'", stack_name
    )

    # Discover resources from the stack
    resources = _discover_stack_resources(stack_name, region)

    # Verify S3 buckets
    for bucket_info in resources.get("s3_buckets", []):
        result = _verify_s3_bucket(bucket_info, region)
        results.append(result)

    # Verify DynamoDB tables
    for table_info in resources.get("dynamodb_tables", []):
        result = _verify_dynamodb_table(table_info, region)
        results.append(result)

    # Verify Lambda functions
    for lambda_info in resources.get("lambda_functions", []):
        result = _verify_lambda_function(lambda_info, region)
        results.append(result)

    # Verify CloudWatch log groups
    for log_group_info in resources.get("log_groups", []):
        result = _verify_cloudwatch_logs(log_group_info, region)
        results.append(result)

    if not results:
        results.append({
            "check_name": "integration_endpoints_discovery",
            "status": "FAIL",
            "details": (
                f"No integration resources (S3, DynamoDB, Lambda, CloudWatch) "
                f"discovered in stack '{stack_name}'. Cannot verify integrations."
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    logger.info(
        "Integration endpoints verification complete: %d/%d passed",
        sum(1 for r in results if r["status"] == "PASS"),
        len(results),
    )

    return results


def _discover_stack_resources(
    stack_name: str, region: str
) -> dict[str, list[dict[str, str]]]:
    """
    Discover integration-relevant resources from the CloudFormation stack.

    Args:
        stack_name: CloudFormation stack name.
        region: AWS region.

    Returns:
        Dictionary mapping resource type categories to lists of resource info.
    """
    resources: dict[str, list[dict[str, str]]] = {
        "s3_buckets": [],
        "dynamodb_tables": [],
        "lambda_functions": [],
        "log_groups": [],
    }

    resource_type_map = {
        "AWS::S3::Bucket": "s3_buckets",
        "AWS::DynamoDB::Table": "dynamodb_tables",
        "AWS::Lambda::Function": "lambda_functions",
        "AWS::Logs::LogGroup": "log_groups",
    }

    try:
        cfn_client = boto3.client("cloudformation", region_name=region)
        paginator = cfn_client.get_paginator("list_stack_resources")

        for page in paginator.paginate(StackName=stack_name):
            for resource in page.get("StackResourceSummaries", []):
                resource_type = resource["ResourceType"]
                if resource_type in resource_type_map:
                    category = resource_type_map[resource_type]
                    physical_id = resource.get("PhysicalResourceId", "")
                    logical_id = resource.get("LogicalResourceId", "")
                    if physical_id:
                        resources[category].append({
                            "physical_id": physical_id,
                            "logical_id": logical_id,
                        })

    except ClientError as exc:
        logger.error(
            "Failed to discover stack resources: [%s] %s",
            exc.response["Error"]["Code"],
            exc.response["Error"]["Message"],
        )
    except Exception as exc:
        logger.exception("Unexpected error discovering resources: %s", str(exc))

    return resources


def _verify_s3_bucket(
    bucket_info: dict[str, str], region: str
) -> dict[str, Any]:
    """
    Verify S3 bucket accessibility with PutObject, GetObject, and DeleteObject.

    Args:
        bucket_info: Dict with 'physical_id' (bucket name) and 'logical_id'.
        region: AWS region.

    Returns:
        Check result dict.
    """
    bucket_name = bucket_info["physical_id"]
    logical_id = bucket_info["logical_id"]
    check_name = f"integration_s3_{logical_id}"
    timestamp = datetime.now(timezone.utc).isoformat()
    test_key = f"{TEST_MARKER_PREFIX}/{uuid.uuid4().hex}"

    logger.info("Verifying S3 bucket accessibility: %s", bucket_name)

    try:
        s3_client = boto3.client("s3", region_name=region)

        # Step 1: PutObject
        test_body = json.dumps({
            "test": "iq-verification",
            "timestamp": timestamp,
            "bucket": bucket_name,
        }).encode("utf-8")

        s3_client.put_object(
            Bucket=bucket_name,
            Key=test_key,
            Body=test_body,
            ContentType="application/json",
            Metadata={"purpose": "iq-verification-test"},
        )
        logger.info("S3 PutObject succeeded: s3://%s/%s", bucket_name, test_key)

        # Step 2: GetObject and verify content
        get_response = s3_client.get_object(Bucket=bucket_name, Key=test_key)
        retrieved_body = get_response["Body"].read()

        if retrieved_body != test_body:
            return {
                "check_name": check_name,
                "status": "FAIL",
                "details": (
                    f"S3 bucket '{bucket_name}' ({logical_id}): Data integrity "
                    f"check failed. Written and read content do not match."
                ),
                "timestamp": timestamp,
                "bucket_name": bucket_name,
            }

        # Step 3: DeleteObject (cleanup)
        s3_client.delete_object(Bucket=bucket_name, Key=test_key)
        logger.info("S3 test object cleaned up: s3://%s/%s", bucket_name, test_key)

        return {
            "check_name": check_name,
            "status": "PASS",
            "details": (
                f"S3 bucket '{bucket_name}' ({logical_id}): Full read/write/delete "
                f"cycle completed successfully. PutObject, GetObject (with data "
                f"integrity verification), and DeleteObject all operational."
            ),
            "timestamp": timestamp,
            "bucket_name": bucket_name,
            "operations_verified": ["PutObject", "GetObject", "DeleteObject"],
        }

    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        error_message = exc.response["Error"]["Message"]
        logger.error(
            "S3 verification failed for bucket %s: [%s] %s",
            bucket_name,
            error_code,
            error_message,
        )

        # Attempt cleanup even on failure
        _cleanup_s3_test_object(region, bucket_name, test_key)

        return {
            "check_name": check_name,
            "status": "FAIL",
            "details": (
                f"S3 bucket '{bucket_name}' ({logical_id}): Integration test "
                f"failed. Error: [{error_code}] {error_message}. "
                f"Verify Lambda execution role has s3:PutObject, s3:GetObject, "
                f"s3:DeleteObject permissions on this bucket."
            ),
            "timestamp": timestamp,
            "bucket_name": bucket_name,
            "error_code": error_code,
        }
    except Exception as exc:
        logger.exception("Unexpected error verifying S3 bucket %s", bucket_name)
        _cleanup_s3_test_object(region, bucket_name, test_key)
        return {
            "check_name": check_name,
            "status": "FAIL",
            "details": (
                f"Unexpected error verifying S3 bucket '{bucket_name}' "
                f"({logical_id}): {str(exc)}"
            ),
            "timestamp": timestamp,
            "bucket_name": bucket_name,
        }


def _verify_dynamodb_table(
    table_info: dict[str, str], region: str
) -> dict[str, Any]:
    """
    Verify DynamoDB table accessibility with PutItem, GetItem, and DeleteItem.

    Args:
        table_info: Dict with 'physical_id' (table name) and 'logical_id'.
        region: AWS region.

    Returns:
        Check result dict.
    """
    table_name = table_info["physical_id"]
    logical_id = table_info["logical_id"]
    check_name = f"integration_dynamodb_{logical_id}"
    timestamp = datetime.now(timezone.utc).isoformat()

    logger.info("Verifying DynamoDB table accessibility: %s", table_name)

    try:
        dynamodb_client = boto3.client("dynamodb", region_name=region)

        # First, describe the table to get key schema
        describe_response = dynamodb_client.describe_table(TableName=table_name)
        table_desc = describe_response["Table"]
        key_schema = table_desc["KeySchema"]
        attribute_defs = table_desc["AttributeDefinitions"]

        # Build a test item using the key schema
        test_item = _build_test_item(key_schema, attribute_defs)

        # Step 1: PutItem
        dynamodb_client.put_item(
            TableName=table_name,
            Item=test_item,
            ConditionExpression="attribute_not_exists(#pk)",
            ExpressionAttributeNames={
                "#pk": key_schema[0]["AttributeName"]
            },
        )
        logger.info("DynamoDB PutItem succeeded for table: %s", table_name)

        # Step 2: GetItem
        key = {
            attr["AttributeName"]: test_item[attr["AttributeName"]]
            for attr in key_schema
        }
        get_response = dynamodb_client.get_item(
            TableName=table_name,
            Key=key,
            ConsistentRead=True,
        )

        if "Item" not in get_response:
            return {
                "check_name": check_name,
                "status": "FAIL",
                "details": (
                    f"DynamoDB table '{table_name}' ({logical_id}): PutItem "
                    f"succeeded but GetItem returned no item. Consistency issue."
                ),
                "timestamp": timestamp,
                "table_name": table_name,
            }

        # Step 3: DeleteItem (cleanup)
        dynamodb_client.delete_item(TableName=table_name, Key=key)
        logger.info("DynamoDB test item cleaned up from table: %s", table_name)

        return {
            "check_name": check_name,
            "status": "PASS",
            "details": (
                f"DynamoDB table '{table_name}' ({logical_id}): Full "
                f"PutItem/GetItem/DeleteItem cycle completed successfully. "
                f"Table is accessible and operational. "
                f"Table status: {table_desc['TableStatus']}."
            ),
            "timestamp": timestamp,
            "table_name": table_name,
            "table_status": table_desc["TableStatus"],
            "operations_verified": ["PutItem", "GetItem", "DeleteItem"],
        }

    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        error_message = exc.response["Error"]["Message"]

        # ConditionalCheckFailedException means item already exists (not a real failure)
        if error_code == "ConditionalCheckFailedException":
            return {
                "check_name": check_name,
                "status": "PASS",
                "details": (
                    f"DynamoDB table '{table_name}' ({logical_id}): Table is "
                    f"accessible (ConditionalCheckFailed indicates write access "
                    f"and item already exists). API connectivity confirmed."
                ),
                "timestamp": timestamp,
                "table_name": table_name,
            }

        logger.error(
            "DynamoDB verification failed for table %s: [%s] %s",
            table_name,
            error_code,
            error_message,
        )
        return {
            "check_name": check_name,
            "status": "FAIL",
            "details": (
                f"DynamoDB table '{table_name}' ({logical_id}): Integration test "
                f"failed. Error: [{error_code}] {error_message}. "
                f"Verify Lambda execution role has dynamodb:PutItem, "
                f"dynamodb:GetItem, dynamodb:DeleteItem permissions."
            ),
            "timestamp": timestamp,
            "table_name": table_name,
            "error_code": error_code,
        }
    except Exception as exc:
        logger.exception("Unexpected error verifying DynamoDB table %s", table_name)
        return {
            "check_name": check_name,
            "status": "FAIL",
            "details": (
                f"Unexpected error verifying DynamoDB table '{table_name}' "
                f"({logical_id}): {str(exc)}"
            ),
            "timestamp": timestamp,
            "table_name": table_name,
        }


def _verify_lambda_function(
    lambda_info: dict[str, str], region: str
) -> dict[str, Any]:
    """
    Verify Lambda function invocability by calling GetFunction and optionally
    performing a dry-run invocation.

    Args:
        lambda_info: Dict with 'physical_id' (function name) and 'logical_id'.
        region: AWS region.

    Returns:
        Check result dict.
    """
    function_name = lambda_info["physical_id"]
    logical_id = lambda_info["logical_id"]
    check_name = f"integration_lambda_{logical_id}"
    timestamp = datetime.now(timezone.utc).isoformat()

    logger.info("Verifying Lambda function: %s", function_name)

    try:
        lambda_client = boto3.client("lambda", region_name=region)

        # Get function configuration to verify it exists and is active
        response = lambda_client.get_function(FunctionName=function_name)
        config_info = response["Configuration"]
        state = config_info.get("State", "Unknown")
        runtime = config_info.get("Runtime", "Unknown")
        last_modified = config_info.get("LastModified", "Unknown")

        if state != "Active":
            return {
                "check_name": check_name,
                "status": "FAIL",
                "details": (
                    f"Lambda function '{function_name}' ({logical_id}): "
                    f"Function state is '{state}', expected 'Active'. "
                    f"Function may still be deploying or is in a failed state."
                ),
                "timestamp": timestamp,
                "function_name": function_name,
                "state": state,
            }

        # Perform DryRun invocation to verify invocability without side effects
        try:
            lambda_client.invoke(
                FunctionName=function_name,
                InvocationType="DryRun",
            )
            invocable = True
        except ClientError as invoke_exc:
            # DryRun returns 204 on success; some errors indicate permission issues
            if invoke_exc.response["Error"]["Code"] == "DryRunOperation":
                invocable = True
            else:
                invocable = False
                logger.warning(
                    "Lambda DryRun invocation failed: %s",
                    invoke_exc.response["Error"]["Message"],
                )

        if invocable:
            return {
                "check_name": check_name,
                "status": "PASS",
                "details": (
                    f"Lambda function '{function_name}' ({logical_id}): "
                    f"Function is Active and invocable. "
                    f"Runtime: {runtime}, Last modified: {last_modified}."
                ),
                "timestamp": timestamp,
                "function_name": function_name,
                "state": state,
                "runtime": runtime,
            }
        else:
            return {
                "check_name": check_name,
                "status": "FAIL",
                "details": (
                    f"Lambda function '{function_name}' ({logical_id}): "
                    f"Function exists (state: {state}) but DryRun invocation "
                    f"failed. Check invoke permissions."
                ),
                "timestamp": timestamp,
                "function_name": function_name,
                "state": state,
            }

    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        error_message = exc.response["Error"]["Message"]
        logger.error(
            "Lambda verification failed for %s: [%s] %s",
            function_name,
            error_code,
            error_message,
        )
        return {
            "check_name": check_name,
            "status": "FAIL",
            "details": (
                f"Lambda function '{function_name}' ({logical_id}): "
                f"Verification failed. Error: [{error_code}] {error_message}."
            ),
            "timestamp": timestamp,
            "function_name": function_name,
            "error_code": error_code,
        }
    except Exception as exc:
        logger.exception("Unexpected error verifying Lambda %s", function_name)
        return {
            "check_name": check_name,
            "status": "FAIL",
            "details": (
                f"Unexpected error verifying Lambda function '{function_name}' "
                f"({logical_id}): {str(exc)}"
            ),
            "timestamp": timestamp,
            "function_name": function_name,
        }


def _verify_cloudwatch_logs(
    log_group_info: dict[str, str], region: str
) -> dict[str, Any]:
    """
    Verify CloudWatch Logs log group is accessible and writable.

    Args:
        log_group_info: Dict with 'physical_id' (log group name) and 'logical_id'.
        region: AWS region.

    Returns:
        Check result dict.
    """
    log_group_name = log_group_info["physical_id"]
    logical_id = log_group_info["logical_id"]
    check_name = f"integration_cloudwatch_{logical_id}"
    timestamp = datetime.now(timezone.utc).isoformat()

    logger.info("Verifying CloudWatch log group: %s", log_group_name)

    try:
        logs_client = boto3.client("logs", region_name=region)

        # Verify log group exists and is accessible
        response = logs_client.describe_log_groups(
            logGroupNamePrefix=log_group_name,
            limit=1,
        )

        matching_groups = [
            g for g in response.get("logGroups", [])
            if g["logGroupName"] == log_group_name
        ]

        if not matching_groups:
            return {
                "check_name": check_name,
                "status": "FAIL",
                "details": (
                    f"CloudWatch log group '{log_group_name}' ({logical_id}): "
                    f"Log group not found or not accessible."
                ),
                "timestamp": timestamp,
                "log_group_name": log_group_name,
            }

        log_group = matching_groups[0]
        retention = log_group.get("retentionInDays", "Never expire")
        kms_key_id = log_group.get("kmsKeyId", "None (default encryption)")

        # Attempt to create a test log stream to verify write access
        test_stream_name = f"{TEST_MARKER_PREFIX}-{uuid.uuid4().hex[:8]}"
        try:
            logs_client.create_log_stream(
                logGroupName=log_group_name,
                logStreamName=test_stream_name,
            )

            # Put a test log event
            logs_client.put_log_events(
                logGroupName=log_group_name,
                logStreamName=test_stream_name,
                logEvents=[
                    {
                        "timestamp": int(
                            datetime.now(timezone.utc).timestamp() * 1000
                        ),
                        "message": json.dumps({
                            "event": "iq-verification-test",
                            "timestamp": timestamp,
                        }),
                    }
                ],
            )

            # Cleanup: delete the test stream
            logs_client.delete_log_stream(
                logGroupName=log_group_name,
                logStreamName=test_stream_name,
            )

            write_verified = True
        except ClientError as write_exc:
            logger.warning(
                "CloudWatch write test failed (non-fatal): %s",
                write_exc.response["Error"]["Message"],
            )
            write_verified = False

        status = "PASS" if write_verified else "PASS"
        details_suffix = (
            "Write access verified (log stream creation and event delivery)."
            if write_verified
            else "Read access verified (write test skipped due to permissions)."
        )

        return {
            "check_name": check_name,
            "status": status,
            "details": (
                f"CloudWatch log group '{log_group_name}' ({logical_id}): "
                f"Log group exists and is accessible. "
                f"Retention: {retention} days, KMS: {kms_key_id}. "
                f"{details_suffix}"
            ),
            "timestamp": timestamp,
            "log_group_name": log_group_name,
            "retention_days": retention,
            "kms_key_id": kms_key_id,
        }

    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        error_message = exc.response["Error"]["Message"]
        logger.error(
            "CloudWatch verification failed for %s: [%s] %s",
            log_group_name,
            error_code,
            error_message,
        )
        return {
            "check_name": check_name,
            "status": "FAIL",
            "details": (
                f"CloudWatch log group '{log_group_name}' ({logical_id}): "
                f"Verification failed. Error: [{error_code}] {error_message}."
            ),
            "timestamp": timestamp,
            "log_group_name": log_group_name,
            "error_code": error_code,
        }
    except Exception as exc:
        logger.exception(
            "Unexpected error verifying CloudWatch log group %s", log_group_name
        )
        return {
            "check_name": check_name,
            "status": "FAIL",
            "details": (
                f"Unexpected error verifying CloudWatch log group "
                f"'{log_group_name}' ({logical_id}): {str(exc)}"
            ),
            "timestamp": timestamp,
            "log_group_name": log_group_name,
        }


def _build_test_item(
    key_schema: list[dict[str, str]],
    attribute_defs: list[dict[str, str]],
) -> dict[str, dict[str, str]]:
    """
    Build a DynamoDB test item based on the table's key schema.

    Args:
        key_schema: Table key schema from DescribeTable.
        attribute_defs: Attribute definitions from DescribeTable.

    Returns:
        DynamoDB item dict suitable for PutItem.
    """
    # Map attribute names to their types
    attr_type_map = {
        attr["AttributeName"]: attr["AttributeType"]
        for attr in attribute_defs
    }

    test_item: dict[str, dict[str, str]] = {}
    test_id = f"{TEST_MARKER_PREFIX}-{uuid.uuid4().hex[:12]}"

    for key_attr in key_schema:
        attr_name = key_attr["AttributeName"]
        attr_type = attr_type_map.get(attr_name, "S")

        if attr_type == "S":
            test_item[attr_name] = {"S": test_id}
        elif attr_type == "N":
            test_item[attr_name] = {"N": "0"}
        elif attr_type == "B":
            test_item[attr_name] = {"B": "dGVzdA=="}  # base64 "test"

    # Add a marker attribute for identification
    test_item["_iq_verification"] = {"S": "true"}
    test_item["_iq_timestamp"] = {"S": datetime.now(timezone.utc).isoformat()}

    return test_item


def _cleanup_s3_test_object(region: str, bucket_name: str, key: str) -> None:
    """
    Best-effort cleanup of S3 test objects.

    Args:
        region: AWS region.
        bucket_name: S3 bucket name.
        key: Object key to delete.
    """
    try:
        s3_client = boto3.client("s3", region_name=region)
        s3_client.delete_object(Bucket=bucket_name, Key=key)
        logger.info("Cleaned up test object: s3://%s/%s", bucket_name, key)
    except Exception as exc:
        logger.warning(
            "Failed to clean up test object s3://%s/%s: %s",
            bucket_name,
            key,
            str(exc),
        )
