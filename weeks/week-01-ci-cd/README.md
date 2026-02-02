# Week 01 – CI/CD with Security (DevSecOps Foundations)
[![Release](https://github.com/adenoch1/devsecops-bootcamp/actions/workflows/03-release.yml/badge.svg)](https://github.com/adenoch1/devsecops-bootcamp/actions/workflows/03-release.yml)

In Week 1 of the DevSecOps Bootcamp, we build a production-style CI/CD pipeline for a Flask application using GitHub Actions, with security embedded at every stage.

This week focuses on the **CI and Security gates** that run before any code is allowed into the protected `main` branch and before any container image is released.

---

## Objectives

By the end of Week 1, you will understand how to:

- Build a CI pipeline with automated unit testing
- Add SAST (Static Application Security Testing)
- Scan dependencies for known vulnerabilities
- Scan both the filesystem and final Docker image
- Publish secure container images to GitHub Container Registry (GHCR)
- Enforce pull request checks and branch protection like real production teams

---

## Application Overview

The demo application is a simple Flask portfolio site:

- `/` → Renders a portfolio HTML page (About, Skills, Contact)
- `/health` → Returns JSON: `{ "status": "ok" }` (for monitoring and load balancers)

This gives us a realistic service with:
- Templates
- Static assets (CSS)
- Health checks
- Unit tests

---

## DevSecOps Pipeline Design

The pipeline is intentionally split into three workflows:

### 1) CI Workflow – Unit Tests (`01-ci.yml`)
Runs on: `pull_request → main`

Purpose:
- Validate correctness
- Prevent broken code from being merged

Steps:
- Checkout code
- Setup Python 3.11
- Install dependencies
- Run Pytest

Command:
```bash
pytest -q app/tests
If tests fail, the pull request is blocked.

2) Security Workflow – SAST + Dependency + FS Scan (02-security.yml)
Runs on: pull_request → main

Purpose:

Prevent insecure code and vulnerable libraries from entering main

Tools:

Bandit (SAST)
Scans Python source code for insecure patterns:

Hardcoded secrets

Insecure cryptography

Unsafe subprocess usage

Weak random generators

Command:

bandit -r app -ll
pip-audit (Dependency Vulnerabilities)
Checks Python dependencies for known CVEs.

Command:

pip-audit -r app/requirements.txt
Trivy Filesystem Scan
Scans the entire repository before any image is built:

Dependency manifests

Known vulnerable packages

Potential misconfigurations

Configured to fail the build if vulnerabilities are found.

3) Release Workflow – Docker Build + Image Scan (03-release.yml)
Runs on:

push → main

Manual trigger (workflow_dispatch)

Purpose:

Build the final artifact

Scan it

Publish it

Steps:

Login to GitHub Container Registry

Build Docker image

Push image to GHCR

Scan final image with Trivy

Trivy Image Scan checks:

Base OS vulnerabilities (Alpine)

Installed Python libraries

Runtime packages

Docker Security Design
The Dockerfile follows production best practices:

Multi-stage build

No compilers in runtime image

Non-root user

Gunicorn as WSGI server

Minimal Alpine base image

This results in:

Smaller image

Fewer vulnerabilities

Reduced attack surface

GitHub Security & Governance
Branch Protection
main is protected with:

Required pull request reviews

Required status checks (CI + Security)

No direct pushes

Optional admin enforcement

Pull Request Flow
Developer creates feature branch:

git checkout -b feature/week1-ci-security-pipeline
Pushes code:

git push -u origin feature/week1-ci-security-pipeline
Opens PR to main

GitHub runs:

CI (tests)

Security scans

Second account reviews and approves

PR is merged

Release workflow runs automatically

Container Registry
Images are published to:

ghcr.io/<github-username>/<repo-name>:latest
Example:

docker pull ghcr.io/adenoch1/devsecops-project1:latest
Local Verification (Proof of Delivery)
docker login ghcr.io
docker pull ghcr.io/<username>/<repo>:latest
docker run -p 5000:5000 ghcr.io/<username>/<repo>:latest
Test:

http://localhost:5000

http://localhost:5000/health

This proves:

The same artifact built in CI runs locally

The pipeline produces portable, secure images

DevSecOps Concepts Demonstrated
This week shows:

CI as a quality gate (Pytest)

SAST as a security gate (Bandit)

Dependency risk management (pip-audit)

Artifact security (Trivy FS + Image)

Immutable releases (GHCR)

Protected main branch

PR-based governance

Automated security enforcement

This is real DevSecOps, not just DevOps with security tools added later.

What’s Next – Week 02
Week 2 introduces Infrastructure as Code and cloud security:

Terraform VPC, subnets, routing

ECS Fargate

IAM roles

tfsec and Checkov

Terraform validation and formatting

IaC security gates

See: weeks/week-02-terraform-iac/README.md
