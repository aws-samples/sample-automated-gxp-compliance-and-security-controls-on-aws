# System Boundary Definition Template

> **Purpose:** This template supports the definition of system boundaries for computerized systems subject to GxP validation, per ISPE GAMP 5 Second Edition guidelines. It establishes what is in and out of validation scope, maps components to the AWS Shared Responsibility Model, and assigns GAMP 5 software categories.

---

## 1. System Identification

| Field | Value |
|---|---|
| **System Name** | _[Enter system name]_ |
| **System Version** | _[Enter version or release identifier]_ |
| **System Owner** | _[Name, Title, Department]_ |
| **Quality Owner** | _[Name, Title, Department]_ |
| **IT Owner** | _[Name, Title, Department]_ |
| **Unique System Identifier** | _[Internal tracking ID]_ |
| **GxP Classification** | _[GMP / GLP / GCP / GDP]_ |
| **Risk Level (per CSA)** | _[High / Medium / Low]_ |
| **Date Prepared** | _[YYYY-MM-DD]_ |
| **Document Version** | _[e.g., 1.0]_ |

---

## 2. Intended Use Statement

> _Describe the intended use of the system in the context of its GxP-regulated function. This statement drives the scope of validation activities._

**Intended Use:**

_[Example: This system is intended to manage batch production records for pharmaceutical manufacturing, ensuring data integrity, traceability, and compliance with 21 CFR Part 211. The system captures critical process parameters, provides electronic batch record review and approval workflows, and maintains a complete audit trail of all record modifications.]_

**Regulated Functions:**

- _[Function 1: e.g., Electronic batch record creation and management]_
- _[Function 2: e.g., Electronic review and approval with 21 CFR Part 11 signatures]_
- _[Function 3: e.g., Audit trail for all data modifications]_

**Out-of-Scope Functions:**

- _[Function 1: e.g., General email notifications (non-GxP)]_
- _[Function 2: e.g., User preference settings]_

---

## 3. Layered Boundary Definition

The following table defines the system boundary using the AWS infrastructure stack layers. Each component is assessed for validation scope inclusion.

| Layer | Component | In/Out of Validation Scope | Justification | Evidence Source |
|---|---|---|---|---|
| **Layer 0 — Physical Infrastructure** | AWS Global Infrastructure (data centers, hardware, networking) | ❌ Out of Scope | AWS responsibility under Shared Responsibility Model. Covered by AWS SOC 2 Type II, ISO 27001, and GxP qualification pack. | AWS Artifact — SOC 2 Report, AWS GxP Compliance page |
| **Layer 1 — Hypervisor / Virtualization** | EC2 Nitro Hypervisor, EBS storage subsystem | ❌ Out of Scope | AWS responsibility. Nitro is purpose-built with no operator access. Covered by AWS third-party audits. | AWS Artifact — SOC 2 Report, Nitro Security Design whitepaper |
| **Layer 2 — Managed Services (AWS-Managed Layer)** | Amazon RDS (database engine), Amazon S3 (object storage), AWS KMS (key management) | ⚠️ Shared — Configuration in Scope | AWS manages service availability and patching. Customer responsible for configuration (encryption, access policies, retention). Configuration validation required. | IQ verification of configuration, AWS Config rules, CloudFormation templates |
| **Layer 3 — Application Runtime** | AWS Lambda (runtime), Amazon ECS/EKS (container orchestration), API Gateway | ⚠️ Shared — Configuration & Integration in Scope | AWS manages runtime patching. Customer responsible for function code, container images, API definitions, and integration logic. | OQ test results, deployment pipeline artifacts, container scan reports |
| **Layer 4 — Application Code** | Custom Lambda functions, application business logic, data processing code | ✅ Full Validation Scope | Entirely customer-developed. Directly implements GxP-regulated processes. | Unit tests, OQ/PQ test results, code review records, RTM |
| **Layer 5 — Data & Configuration** | Application data, user configurations, workflow definitions, validation rules | ✅ Full Validation Scope | Customer-owned data that drives regulated decisions. Data integrity is paramount. | Data integrity checks, backup verification, audit trail validation |

---

## 4. Detailed Component Inventory

### 4.1 Infrastructure Components (AWS Managed — Out of Scope)

| Component | AWS Service | Justification for Exclusion |
|---|---|---|
| Physical servers | EC2 bare metal | AWS SOC 2 Type II covers physical security |
| Network backbone | AWS Global Network | AWS manages; VPC configuration IS in scope |
| Storage media | EBS/S3 physical disks | AWS manages encryption at rest at hardware level |

### 4.2 Managed Service Components (Shared Responsibility — Configuration in Scope)

| Component | AWS Service | Customer Validation Responsibility |
|---|---|---|
| Database | Amazon RDS PostgreSQL | Encryption at rest (KMS), backup retention, access controls, parameter groups |
| Object storage | Amazon S3 | Bucket policies, Object Lock, versioning, lifecycle rules, encryption |
| Secrets | AWS Secrets Manager | Rotation policy, access policy, encryption |
| Identity | Amazon Cognito | User pool configuration, MFA enforcement, password policies |
| Encryption | AWS KMS | Key policies, rotation, alias management |

### 4.3 Application Components (Full Validation Scope)

| Component | AWS Service | GAMP 5 Category | Validation Activities |
|---|---|---|---|
| IQ Verification Lambda | AWS Lambda | Category 5 (Custom) | Unit test, integration test, IQ protocol |
| E-Signature Workflow | Step Functions + Lambda | Category 5 (Custom) | Full V-model (IQ/OQ/PQ) |
| Batch Record Logic | Lambda + DynamoDB | Category 5 (Custom) | Full V-model (IQ/OQ/PQ) |
| Config Rule Evaluations | AWS Config (custom rules) | Category 5 (Custom) | Unit test, integration test |
| API Layer | API Gateway + Lambda | Category 4 (Configured) | Configuration verification, OQ |

---

## 5. Shared Responsibility Mapping

```
┌─────────────────────────────────────────────────────────┐
│              CUSTOMER RESPONSIBILITY                      │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Data, Application Code, Identity & Access,      │    │
│  │  Encryption Configuration, Network Config,       │    │
│  │  OS/Firewall (EC2), Client-side Encryption       │    │
│  └─────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────┤
│              AWS RESPONSIBILITY                           │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Global Infrastructure, Hardware, Networking,    │    │
│  │  Managed Service Software, Hypervisor,           │    │
│  │  Physical Security, Environmental Controls       │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

### Mapping to Validation Activities

| Responsibility Domain | Owner | Validation Activity | Frequency |
|---|---|---|---|
| Physical infrastructure security | AWS | Third-party audit (SOC 2) | Annual — review report |
| Service availability & patching | AWS | Shared — monitor advisories | Ongoing |
| Encryption key management config | Customer | IQ of KMS configuration | Initial + change control |
| IAM policies & access control | Customer | IQ + periodic access review | Initial + quarterly |
| Application code correctness | Customer | OQ (functional testing) | Each release |
| Data integrity controls | Customer | PQ (performance & integrity) | Each release + periodic |
| Backup & disaster recovery | Shared | DR test execution | Annual |

---

## 6. GAMP 5 Category Assignment

| GAMP 5 Category | Definition | Components in This System |
|---|---|---|
| **Category 1** — Infrastructure Software | Operating systems, database engines (as managed by AWS) | Amazon Linux 2, RDS PostgreSQL engine |
| **Category 3** — Non-Configured Products | Commercial off-the-shelf used as-is | _[List any COTS, e.g., third-party libraries]_ |
| **Category 4** — Configured Products | Products configured for specific use | API Gateway routes, Step Functions state machines, Config rules (AWS-managed) |
| **Category 5** — Custom Applications | Bespoke code developed for specific requirements | IQ Lambda, e-signature logic, custom Config rules, business logic functions |

### Validation Effort by Category

| Category | Expected Effort | Key Activities |
|---|---|---|
| 1 | Minimal | Verify version, reference AWS audit reports |
| 3 | Low | Verify version, document intended use, supplier assessment |
| 4 | Medium | Configuration specification, IQ verification, OQ of configured behavior |
| 5 | High | Full V-model — URS, FRS, IQ, OQ, PQ, traceability matrix |

---

## 7. Regulatory References

| Reference | Section | Relevance |
|---|---|---|
| 21 CFR Part 11 | § 11.10(a) | System validation requirements |
| 21 CFR Part 11 | § 11.10(e) | Audit trail requirements |
| 21 CFR Part 11 | § 11.50, 11.70 | Electronic signature requirements |
| FDA CSA Guidance (Feb 2026) | Section IV | Risk-based approaches to software assurance |
| FDA CSA Guidance (Feb 2026) | Section V | Leveraging existing evidence from development |
| ISPE GAMP 5 2nd Edition | Appendix M4 | IT Infrastructure Qualification |
| ISPE GAMP 5 2nd Edition | Appendix D7 | Category and Specification |
| ISPE GAMP 5 2nd Edition | Appendix O5 | Cloud and SaaS — Supplier Assessment |
| EU Annex 11 | Section 1 | Risk management approach |
| EU Annex 11 | Section 4.4 | Access control requirements |
| EU Annex 11 | Section 9 | Audit trail requirements |
| ICH Q9 | — | Quality Risk Management principles |

---

## 8. Approval

| Role | Name | Signature | Date |
|---|---|---|---|
| System Owner | ___________________ | ___________________ | ________ |
| Quality Assurance | ___________________ | ___________________ | ________ |
| IT/Cloud Operations | ___________________ | ___________________ | ________ |
| Validation Lead | ___________________ | ___________________ | ________ |

---

## Document Control

| Version | Date | Author | Change Description |
|---|---|---|---|
| 1.0 | _[Date]_ | _[Author]_ | Initial release |
| | | | |
