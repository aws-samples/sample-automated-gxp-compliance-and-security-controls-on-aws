# Security Policy

## Disclaimer

This project is sample/educational code and is **NOT** intended for production use in
GxP-regulated environments without additional security hardening and formal validation
by your quality assurance, computerized system validation, and regulatory affairs teams.
Your organization's specific regulatory requirements, risk assessments, and quality
management system must govern the final implementation.

## Reporting Vulnerabilities

If you discover a potential security issue in this project, please do **not** create a
public GitHub issue. Instead, notify AWS/Amazon Security via the
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/).

## AWS Services Used

- **AWS KMS** — customer-managed keys for encryption at rest
- **Amazon S3** — GxP data storage with Object Lock (COMPLIANCE mode), versioning, and access logging
- **Amazon DynamoDB** — electronic signature records with point-in-time recovery
- **AWS Lambda** — re-authentication, signature record creation, drift detection, IQ verification
- **AWS Step Functions** — e-signature workflow orchestration
- **Amazon Cognito** — signer identity and re-authentication
- **Amazon API Gateway** — REST endpoint (IAM-authorized)
- **AWS Config** — conformance packs and drift detection
- **AWS CloudTrail** — organizational audit trail
- **AWS CodePipeline / CodeBuild** — IQ/OQ/PQ validation pipeline
- **Amazon SNS** — signature and drift notifications

## Prerequisites and Permissions

To deploy this solution you need an AWS account (with AWS Organizations enabled for the
landing-zone guardrails) and permissions to create KMS keys, S3 buckets, DynamoDB tables,
Lambda functions, Step Functions state machines, Cognito user pools, API Gateway APIs,
CodePipeline/CodeBuild resources, IAM roles, and SNS topics.

## Known Security Considerations (accepted debt in this sample)

| Item | Category | Rationale |
|------|----------|-----------|
| KMS key policies grant `kms:*` to the account root principal | Security Debt | Standard AWS baseline key policy. Scope the admin statement to a specific deployment role ARN in production. |
| DynamoDB signature table uses AWS-managed KMS (no CMK) | Security Debt | Encryption is enabled by default; use a customer-managed key for GxP signature records in production. |
| Lambda functions are not deployed inside a VPC | Security Debt | Sample simplicity. Place functions in private subnets with VPC endpoints for production. |
| Lambda functions have no dead-letter queue (DLQ) | Security Debt | Add a `DeadLetterConfig` (SQS/SNS) so failed invocations are captured for GxP traceability in production. |
| Lambda functions have no reserved concurrency limit | Security Debt | Set `ReservedConcurrentExecutions` on the e-signature functions to bound blast radius and protect downstream services in production. |
| API Gateway has no AWS WAF association | Security Debt | Add AWS WAF (rate limiting, managed rule groups) in production. |
| CloudWatch Log groups and Lambda environment variables are not CMK-encrypted | Security Debt | Add a customer-managed KMS key for log and environment-variable encryption in production. |
| Pipeline artifact bucket lacks access logging and a TLS-deny policy | Security Debt | The GxP data bucket demonstrates both; apply the same controls to the pipeline artifact bucket in production. |

## Production Hardening Recommendations

Before using this code in production, implement the following changes specific to this
project's architecture:

- **IAM**: Scope each KMS key's administrative statement to a specific deployment role ARN
  instead of the account root principal.
- **Encryption**: Use a customer-managed KMS key for the DynamoDB signature table, the
  CloudWatch Log groups, and Lambda environment variables.
- **Networking**: Deploy the e-signature Lambda functions into a VPC (private subnets with
  interface/gateway endpoints) and attach AWS WAF to the API Gateway stage.
- **Logging**: Enable S3 access logging and add a `DenyInsecureTransport` bucket policy on
  the pipeline artifact bucket (mirroring the GxP data bucket).
- **Availability**: Set `ReservedConcurrentExecutions` on the e-signature Lambda functions.
- **Secrets**: Keep all runtime configuration in environment variables or AWS Systems
  Manager Parameter Store / Secrets Manager — never hardcode credentials.

## Resource Cleanup

Delete the CloudFormation stacks in reverse dependency order (see the README `Cleanup`
section). Note:

- S3 buckets with Object Lock in **COMPLIANCE** mode cannot be emptied or deleted until the
  retention period expires — plan test deployments with short retention.
- KMS keys enter a mandatory 7–30 day pending-deletion window before actual deletion.

## Dependencies

| Dependency | Notes |
|------------|-------|
| boto3 / botocore | AWS SDK for Python — keep updated to the latest release |
| pytest, moto | Test-only dependencies (not deployed to Lambda runtime) |
