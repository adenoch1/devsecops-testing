# Terraform Bootstrap – Week 3 DevSecOps

## Purpose

This folder contains the **Terraform bootstrap** for the DevSecOps project.

Bootstrapping is the process of creating the **secure foundation that Terraform itself depends on**.
These resources must exist **before** any environment infrastructure (VPC, ALB, ECS, WAF, etc.) can be safely managed.

This bootstrap is run **once**, locally, and is intentionally kept **separate** from application infrastructure.

---

## What This Bootstrap Creates

The bootstrap provisions the following **foundational resources**:

### 1. Terraform Remote State Backend
- **S3 bucket** for Terraform state
- **Versioning enabled**
- **KMS-encrypted**
- **Public access fully blocked**
- **TLS-only bucket policy enforced**

This allows Terraform to:
- Store state safely
- Recover from mistakes
- Support team workflows

---

### 2. Terraform State Locking
- **DynamoDB table** for state locking

This prevents:
- Concurrent `terraform apply` runs
- State corruption
- Race conditions in CI/CD

---

### 3. KMS Keys (Encryption at Rest)
Two separate customer-managed KMS keys:
- **State KMS key** – encrypts Terraform state
- **Logs KMS key** – encrypts security logs (ALB, WAF, Firehose)

Key rotation is enabled and access is tightly controlled.

---

### 4. Centralized Logs Bucket
- Encrypted S3 bucket for:
  - ALB access logs
  - WAF logs
  - Firehose delivery
- Versioning enabled
- Public access blocked
- Lifecycle rules applied
- TLS-only access enforced

This supports:
- Security investigations
- Auditing
- Compliance requirements

---

## Why Bootstrap Is Separate

Bootstrap resources **cannot depend on themselves**.

Terraform cannot:
- Store state in a bucket that does not exist
- Lock state in a table that does not exist
- Encrypt state with a key that does not exist

Therefore:
- Bootstrap is executed **locally**
- Uses **local Terraform state**
- Is applied **once**
- Rarely changes

All other Terraform environments (dev, prod) use the **remote backend created here**.

---

## How Bootstrap Is Used in This Project

1. Run bootstrap locally:
   ```bash
   terraform init
   terraform apply

Capture the outputs:
State bucket name
DynamoDB lock table name
KMS key ARNs

Reference these outputs in environment backends:

backend "s3" {
  bucket         = "devsecops-testing-tfstate-enoch-2026"
  key            = "dev/envs/terraform.tfstate"
  region         = "ca-central-1"
  dynamodb_table = "devsecops-testing-tflocks"
  encrypt        = true
  kms_key_id     = "<tfstate-kms-key-arn>"
}


CI/CD pipelines now safely run Terraform using the remote backend.

Security Principles Enforced
Encryption at rest (KMS)
Encryption in transit (TLS-only S3 policies)
Least privilege enablement via consistent tagging
State locking to prevent corruption
Centralized logging for auditability

Production Notes
Bootstrap is usually owned by a platform or security team
Often stored in a separate repository
Changes are rare and heavily reviewed
Destruction is restricted or disabled in production

This design reflects real-world DevSecOps and platform engineering practices.

force_destroy=false by default (production-safe)

For lab teardown, set force_destroy=true temporarily