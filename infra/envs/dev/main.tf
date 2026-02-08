# Dev environment root module.
#
# This is intentionally minimal in this repo snapshot so that:
# - terraform fmt/init/validate/plan works in CI
# - tfsec/checkov/conftest can run reliably
#
# As you add real infrastructure (VPC, ALB, ECS, etc.), add it here or
# wire in modules under infra/modules and call them from this root.

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

output "account_id" {
  value       = data.aws_caller_identity.current.account_id
  description = "AWS account ID (sanity check for CI/OIDC)"
}

output "region" {
  value       = data.aws_region.current.name
  description = "AWS region (sanity check for CI/OIDC)"
}
