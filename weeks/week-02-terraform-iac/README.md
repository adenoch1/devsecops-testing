# Week 02 – Terraform IaC + ECS Fargate (Infrastructure DevSecOps)
[![terraform-ci](https://github.com/adenoch1/devsecops-bootcamp/actions/workflows/terraform-ci.yml/badge.svg)](https://github.com/adenoch1/devsecops-bootcamp/actions/workflows/terraform-ci.yml)

In Week 2 of the DevSecOps Bootcamp, we move from application CI (Week 1) into **Infrastructure as Code**.

We use **Terraform** to create a production-style AWS baseline:
- VPC across 2 Availability Zones
- Public + Private subnets
- Internet Gateway + NAT Gateway
- Route tables
- ECR repository for container images
- IAM roles for ECS
- ECS Fargate cluster + service (private compute)
- Application Load Balancer (public entry)

Then we implement Infrastructure DevSecOps checks in GitHub Actions:
- `terraform fmt`
- `terraform validate`
- `tfsec`
- `checkov`

---

## Objectives

By the end of Week 2, you will have:

✅ Reproducible AWS infrastructure created by Terraform  
✅ A container running securely in ECS Fargate (private subnets)  
✅ A public ALB as the only internet entry point  
✅ An ECR registry to store your container image  
✅ IaC security scanning in CI (shift-left for infra)

---

## Architecture (Week 2)

This week implements the **public entry + private compute** pattern.

### Inbound flow
User → **Public ALB** → **Private ECS Fargate Tasks** → CloudWatch Logs

### Outbound flow (for private tasks)
Private ECS → **NAT Gateway (public subnet)** → AWS APIs / Internet

### Image flow
CI/CD builds image → **ECR** → ECS pulls image at runtime

Key principles:
- Only the ALB is public.
- ECS tasks have **no public IPs**.
- Private subnets get outbound access only through NAT.
- Logs go to CloudWatch (no SSH).

---

## Repo Structure (Terraform)

Terraform is structured like a real production repo:

infra/
envs/
dev/
main.tf
variables.tf
terraform.tfvars
outputs.tf
providers.tf
versions.tf
modules/
network/
ecr/
iam/
ecs/


### Why this structure?
- `infra/envs/dev` is the environment entry point (dev today, stage/prod later)
- `infra/modules/*` are reusable building blocks
- This avoids “one giant Terraform file” and scales like real teams

---

## Environment Files (infra/envs/dev)

### `versions.tf`
Pins Terraform and provider versions so teams don’t break each other with version drift.

### `providers.tf`
Defines the AWS provider and region.

### `variables.tf`
Defines configurable inputs (no hardcoding):
- project name
- environment
- region
- app port
- ECS CPU/memory
- desired task count

### `terraform.tfvars`
Provides actual values for this environment.
Terraform loads it automatically.

### `main.tf` (the orchestrator)
Calls modules in order and wires outputs to inputs:

- `module.network` → VPC + subnets + NAT + routes
- `module.ecr` → container registry
- `module.iam` → ECS task roles
- `module.ecs` → ALB + target group + ECS cluster + service

### `outputs.tf`
Outputs operational information like:
- ALB DNS name (to test in browser)
- ECR repo URL (for pushes)

---

## Modules (infra/modules/*)

### 1) `network` module
Creates:
- VPC (with DNS hostnames enabled)
- Internet Gateway
- 2 public subnets (one per AZ)
- 2 private subnets (one per AZ)
- NAT Gateway (for outbound from private)
- Route tables:
  - Public: `0.0.0.0/0 → IGW`
  - Private: `0.0.0.0/0 → NAT`

Outputs:
- `vpc_id`
- `public_subnet_ids`
- `private_subnet_ids`

These outputs feed the ECS module.

---

### 2) `ecr` module
Creates the container registry:
- Image scanning on push (basic)
- Immutable tags (prevents overwriting)
- Lifecycle policy (prevents registry growing forever)

This connects Week 1 → Week 2:
- Week 1 builds and scans the image
- Week 2 provides ECR and the runtime platform (ECS)

---

### 3) `iam` module
Creates ECS roles:

1) **Task Execution Role**
- Used by ECS itself
- Pulls image from ECR
- Pushes logs to CloudWatch

2) **Task Role**
- Used by the application at runtime
- Reserved for future least-privilege app permissions

Note:
- Week 2 uses managed policies for speed.
- Week 3 hardens IAM to least privilege.

---

### 4) `ecs` module
This is where the app becomes a real deployment:

Creates:
- CloudWatch Log Group
- Security groups (ALB + ECS tasks)
- Public Application Load Balancer
- Target group + health checks
- HTTP listener (Week 2 baseline)
- ECS cluster (with Container Insights)
- Task definition (Fargate)
- ECS service in private subnets (`assign_public_ip = false`)

Security rules:
- ALB SG allows inbound HTTP (80) from internet (public entry)
- ECS SG allows inbound ONLY from ALB on app port
- ECS tasks can egress outbound via NAT (normal for pulling images/logging)

Week 3 upgrades:
- HTTPS with ACM
- Strong TLS policy
- Policy enforcement with OPA/Conftest

---

## GitHub Actions (Terraform CI Checks)

Week 2 introduces infrastructure DevSecOps checks:

Pipeline runs on:
- PRs that modify infra
- pushes to main that modify infra

Checks:
1. `terraform fmt` – formatting standards
2. `terraform validate` – syntax and wiring validation
3. `tfsec` – blocks HIGH/CRITICAL (Week 2 policy)
4. `checkov` – advisory (Week 2), enforced later

This is shift-left security for infrastructure.

---

## Deploy & Test (Week 2 Demo)

> Note: In later weeks, Terraform apply is done through CI/CD approval gates.
> Week 2 shows the core Terraform workflow.

From `infra/envs/dev`:

```bash
terraform init
terraform fmt -recursive
terraform validate
terraform plan
terraform apply
Show Terraform-managed resources:

terraform state list
Get ALB DNS name:

terraform output -raw alb_dns_name
Open the ALB DNS in a browser and confirm the app responds.

Push Image to ECR (Connect Week 1 → Week 2)
Login Docker to ECR:

aws ecr get-login-password --region ca-central-1 \
  | docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.ca-central-1.amazonaws.com
Build and tag the image:

docker build -f docker/Dockerfile \
  -t <ACCOUNT_ID>.dkr.ecr.ca-central-1.amazonaws.com/<ECR_REPO_NAME>:latest .
Push to ECR:

docker push <ACCOUNT_ID>.dkr.ecr.ca-central-1.amazonaws.com/<ECR_REPO_NAME>:latest
ECS pulls this image using the task execution role.

Week 2 Wrap-Up
Week 2 delivers:

✅ VPC with secure public/private subnet design
✅ ECS Fargate service running in private subnets
✅ Public ALB as the only entry point
✅ ECR registry for container images
✅ Terraform CI checks (fmt, validate, tfsec, checkov)

What’s Next – Week 03
Week 3 introduces governance and enforcement:

Policy as Code (OPA / Conftest)

Least privilege IAM hardening

CI/CD enforcement gates (block non-compliant infra)

HTTPS with ACM + strong TLS policy

DNS routing for app.clevernews.org

See: weeks/week-03-opa-https/README.md
