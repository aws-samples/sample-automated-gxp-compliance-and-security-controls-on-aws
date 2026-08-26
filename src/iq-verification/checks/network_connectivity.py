"""
IQ Check: Network Connectivity Verification
=============================================
Verifies that VPC endpoints for critical AWS services (S3, KMS, CloudTrail)
are reachable from the Lambda execution environment via TCP connectivity tests.

This check validates the Installation Qualification requirement that the deployed
infrastructure has proper network paths established for all required service
integrations, ensuring data can flow as designed in the architecture specification.

Verification Scope:
- S3 VPC endpoint reachability (port 443)
- KMS VPC endpoint reachability (port 443)
- CloudTrail VPC endpoint reachability (port 443)
- DNS resolution of regional endpoint hostnames
"""

import logging
import socket
from datetime import datetime, timezone
from typing import Any

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# TCP connection timeout in seconds
CONNECT_TIMEOUT_SECONDS = 5

# Port used by AWS service endpoints (HTTPS)
ENDPOINT_PORT = 443

# Service endpoints to verify (mapped to their regional DNS names)
SERVICE_ENDPOINTS = {
    "s3": "s3.{region}.amazonaws.com",
    "kms": "kms.{region}.amazonaws.com",
    "cloudtrail": "cloudtrail.{region}.amazonaws.com",
}


def run_check(config: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Verify VPC endpoint connectivity for critical AWS services.

    Tests actual TCP connectivity (not just DNS resolution) to ensure
    that the network path from the execution environment to each service
    endpoint is fully operational.

    Args:
        config: Dictionary containing:
            - region (str): AWS region for endpoint resolution
            - stack_name (str): Stack being verified

    Returns:
        List of check result dicts, one per endpoint, each containing:
            - check_name: Identifier for this specific connectivity test
            - status: "PASS" or "FAIL"
            - details: Human-readable description of the result
            - timestamp: ISO 8601 timestamp of the check execution
    """
    region = config["region"]
    stack_name = config["stack_name"]
    results: list[dict[str, Any]] = []

    logger.info(
        "Starting network connectivity checks for stack '%s' in region '%s'",
        stack_name,
        region,
    )

    # First, attempt to discover VPC endpoints from the stack
    vpc_endpoint_dns = _discover_vpc_endpoints(config)

    for service_name, endpoint_template in SERVICE_ENDPOINTS.items():
        check_name = f"network_connectivity_{service_name}"
        timestamp = datetime.now(timezone.utc).isoformat()

        # Use VPC endpoint DNS if discovered, otherwise use public endpoint
        if service_name in vpc_endpoint_dns:
            hostname = vpc_endpoint_dns[service_name]
            endpoint_type = "VPC Endpoint"
        else:
            hostname = endpoint_template.format(region=region)
            endpoint_type = "Regional Public Endpoint"

        logger.info(
            "Testing connectivity to %s (%s): %s:%d",
            service_name,
            endpoint_type,
            hostname,
            ENDPOINT_PORT,
        )

        try:
            # Test DNS resolution
            resolved_ip = _resolve_hostname(hostname)
            if not resolved_ip:
                results.append({
                    "check_name": check_name,
                    "status": "FAIL",
                    "details": (
                        f"DNS resolution failed for {service_name} endpoint "
                        f"'{hostname}'. The endpoint is not resolvable from this "
                        f"execution environment."
                    ),
                    "timestamp": timestamp,
                    "endpoint_type": endpoint_type,
                    "hostname": hostname,
                })
                continue

            # Test TCP connectivity
            connected, latency_ms = _test_tcp_connectivity(hostname, ENDPOINT_PORT)

            if connected:
                results.append({
                    "check_name": check_name,
                    "status": "PASS",
                    "details": (
                        f"{service_name.upper()} endpoint reachable via {endpoint_type}. "
                        f"Host: {hostname}, Resolved IP: {resolved_ip}, "
                        f"Latency: {latency_ms:.1f}ms"
                    ),
                    "timestamp": timestamp,
                    "endpoint_type": endpoint_type,
                    "hostname": hostname,
                    "resolved_ip": resolved_ip,
                    "latency_ms": latency_ms,
                })
            else:
                results.append({
                    "check_name": check_name,
                    "status": "FAIL",
                    "details": (
                        f"TCP connection to {service_name.upper()} endpoint failed. "
                        f"Host: {hostname}:{ENDPOINT_PORT}, Resolved IP: {resolved_ip}. "
                        f"Timeout after {CONNECT_TIMEOUT_SECONDS}s. Check security groups "
                        f"and NACLs for the VPC."
                    ),
                    "timestamp": timestamp,
                    "endpoint_type": endpoint_type,
                    "hostname": hostname,
                    "resolved_ip": resolved_ip,
                })

        except Exception as exc:
            logger.exception(
                "Unexpected error testing connectivity to %s", service_name
            )
            results.append({
                "check_name": check_name,
                "status": "FAIL",
                "details": (
                    f"Unexpected error testing {service_name.upper()} endpoint "
                    f"connectivity: {str(exc)}"
                ),
                "timestamp": timestamp,
                "endpoint_type": endpoint_type,
                "hostname": hostname,
            })

    logger.info(
        "Network connectivity checks complete: %d/%d passed",
        sum(1 for r in results if r["status"] == "PASS"),
        len(results),
    )

    return results


def _discover_vpc_endpoints(config: dict[str, Any]) -> dict[str, str]:
    """
    Discover VPC endpoints associated with the stack by querying EC2.

    Looks for VPC endpoints tagged with the stack name or belonging to
    VPCs that are part of the stack.

    Args:
        config: Configuration with region and stack_name.

    Returns:
        Dictionary mapping service name to VPC endpoint DNS name.
    """
    vpc_endpoint_dns: dict[str, str] = {}
    region = config["region"]
    stack_name = config["stack_name"]

    try:
        ec2_client = boto3.client("ec2", region_name=region)

        # Look for VPC endpoints tagged with our stack
        response = ec2_client.describe_vpc_endpoints(
            Filters=[
                {
                    "Name": "tag:aws:cloudformation:stack-name",
                    "Values": [stack_name],
                }
            ]
        )

        for endpoint in response.get("VpcEndpoints", []):
            service_name_full = endpoint.get("ServiceName", "")
            dns_entries = endpoint.get("DnsEntries", [])

            # Extract short service name (e.g., "com.amazonaws.us-east-1.s3" -> "s3")
            service_short = service_name_full.split(".")[-1] if service_name_full else ""

            if dns_entries and service_short in SERVICE_ENDPOINTS:
                # Use the first DNS entry (regional)
                vpc_endpoint_dns[service_short] = dns_entries[0].get("DnsName", "")
                logger.info(
                    "Discovered VPC endpoint for %s: %s",
                    service_short,
                    vpc_endpoint_dns[service_short],
                )

    except Exception as exc:
        logger.warning(
            "Could not discover VPC endpoints (non-fatal, will use public endpoints): %s",
            str(exc),
        )

    return vpc_endpoint_dns


def _resolve_hostname(hostname: str) -> str | None:
    """
    Resolve a hostname to its IP address.

    Args:
        hostname: The hostname to resolve.

    Returns:
        Resolved IP address string, or None if resolution fails.
    """
    try:
        result = socket.getaddrinfo(hostname, ENDPOINT_PORT, socket.AF_INET)
        if result:
            return result[0][4][0]
        return None
    except (socket.gaierror, socket.herror, OSError) as exc:
        logger.warning("DNS resolution failed for %s: %s", hostname, str(exc))
        return None


def _test_tcp_connectivity(hostname: str, port: int) -> tuple[bool, float]:
    """
    Test TCP connectivity to a host:port with timeout.

    Args:
        hostname: Target hostname.
        port: Target port number.

    Returns:
        Tuple of (connected: bool, latency_ms: float).
        If connection fails, latency_ms is 0.0.
    """
    import time

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT_SECONDS)

    try:
        start_time = time.monotonic()
        sock.connect((hostname, port))
        end_time = time.monotonic()
        latency_ms = (end_time - start_time) * 1000
        return True, latency_ms
    except (socket.timeout, socket.error, OSError) as exc:
        logger.warning(
            "TCP connection to %s:%d failed: %s", hostname, port, str(exc)
        )
        return False, 0.0
    finally:
        sock.close()
