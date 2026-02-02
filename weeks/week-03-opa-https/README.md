DevSecOps Project – Week 3
Governance & Policy as Code with OPA, Conftest, and Secure HTTPS Architecture
Overview

In Week 3 of this DevSecOps project series, we move from security scanning to security enforcement.

Week 1 focused on application CI security:
testing, SAST, dependency scanning, and container image scanning.

Week 2 automated infrastructure using Terraform and introduced infrastructure security scanning with tools like tfsec and Checkov.

In Week 3, we take the next critical step:

Security is no longer advisory. It is mandatory and enforced by policy.

Infrastructure changes are now automatically blocked if they violate security or compliance rules.
This is achieved using Policy as Code with OPA (Open Policy Agent) and Conftest, integrated directly into the CI/CD pipeline.

Week 3 Theme: Governance and Policy as Code

The core objective of Week 3 is to implement:

Automated security governance

Policy enforcement before deployment

Compliance-as-code

Zero-trust infrastructure changes

Real-world approval workflows

From this point forward:

No insecure infrastructure can be merged

No policy-violating changes can reach production

No manual exceptions or ignored warnings

No deployment without security approval

Real Domain & HTTPS with ACM

This project uses a real public domain:

https://app.clevernews.org

The domain is registered with GoDaddy and secured using:

AWS Certificate Manager (ACM)

DNS-based validation

TLS termination on an Application Load Balancer

Strong TLS security policy

Certificate Flow

Public SSL certificate requested in ca-central-1

AWS provides a DNS CNAME validation record

CNAME added in GoDaddy DNS

Certificate status becomes Issued

Certificate attached to the Application Load Balancer

HTTPS enforced by both policy and infrastructure

Traffic encrypted end-to-end

High-Level Architecture

The architecture is governed at every layer:

Layer	Governance Mechanism
Source Code	Protected branches & PR reviews
CI/CD	GitHub Actions with policy gates
Infrastructure	Terraform
Security Policy	OPA + Conftest
Identity	IAM Least Privilege via OIDC
Network	Private subnets, VPC Flow Logs
Transport	TLS 1.2+, HTTPS enforced
Deployment	Approval gates via GitHub Environments
CI/CD Governance Flow
1. Pull Request Phase (Policy Enforcement)

Workflow:
.github/workflows/terraform-security.yml

What happens on every pull request:

Terraform formatting and validation

Static infrastructure security scanning (tfsec, Checkov)

Terraform plan generation

Plan converted to JSON

OPA evaluates the plan using Rego policies

Conftest enforces policy decisions

Merge is blocked if any rule fails

This ensures that insecure infrastructure never reaches the main branch.

2. Policy as Code

Location:
policy/conftest/terraform.rego

Enforced rules include:

No public SSH (0.0.0.0/0:22)

No wildcard IAM permissions

Encryption required for storage

VPC Flow Logs required

HTTPS enforced on the Application Load Balancer

Strong TLS versions only

No insecure load balancer listeners

Least-privilege IAM roles

These are executable compliance rules, not documentation.

IAM Governance via GitHub OIDC (Least Privilege)

This project uses GitHub OpenID Connect (OIDC) to access AWS without long-lived credentials.

Two separate IAM roles are used to enforce separation of duties:

Plan Role (Pull Requests)

Used by terraform-security.yml

Read-only permissions plus Terraform backend access

Can generate and evaluate Terraform plans

Cannot deploy or modify infrastructure

Apply Role (Release)

Used by terraform-release.yml

Has the permissions required for terraform apply

Protected by GitHub Environment approval

Only runs after policy enforcement and human approval

Both workflows reference the same secret name (AWS_ROLE_ARN), but:

Pull request jobs use repository-level secrets

Release jobs use environment-level secrets, which override repository secrets

This design ensures:
Least privilege by default
Clear separation between validation and execution
No deployment without approval
No shared high-privilege credentials

3. Release Phase (Controlled Deployment)
Workflow:
.github/workflows/terraform-release.yml
Features:
Protected main branch
GitHub OIDC → AWS IAM role
Environment approval gate
Remote Terraform state (S3 + DynamoDB lock)
Post-deployment state verification
Only after policy enforcement and approval does infrastructure get deployed.

Secure Runtime Architecture
Inside AWS

VPC with public and private subnets
Application Load Balancer in public subnets
ECS tasks running in private subnets
TLS terminated at ALB using ACM
DNS resolution via GoDaddy CNAME
Encrypted traffic end-to-end
CloudWatch Logs enabled
VPC Flow Logs enabled
IAM least privilege enforced

User Flow
Browser → GoDaddy DNS → ALB (HTTPS) → ACM Certificate → ECS → Application
All governed.
All encrypted.
All logged.

Repository Structure (Week 3 Additions)
.github/workflows/
  terraform-security.yml
  terraform-release.yml

policy/
  conftest/
    terraform.rego

terraform/
  (VPC, ALB, ECS, IAM, TLS, Logging)

What Was Achieved in Week 3

✔ Policy as Code with OPA & Rego
✔ Automated compliance enforcement
✔ Pull-request security gates
✔ Terraform plan evaluation by policy engine
✔ HTTPS enforced with real domain and certificate
✔ Strong TLS configuration
✔ Protected main branch
✔ Deployment approval workflow
✔ Least-privilege IAM via OIDC
✔ End-to-end governed DevSecOps pipeline

DevSecOps Maturity Demonstrated
This week demonstrates:
Shift-left security
Shift-left compliance
Zero-trust infrastructure changes
Automated security governance
Real production-grade controls
Enterprise CI/CD architecture
This is not “scan and hope.”
This is verify, enforce, and block.

What’s Next – Week 4 Preview
In Week 4, we will add:
CloudWatch dashboards
Security alarms
Log metric filters
SSM Parameter Store secrets
Runtime monitoring & alerting
Security observability