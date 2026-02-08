terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Primary region
provider "aws" {
  region = var.aws_region

  # Guardrail: prevent accidentally applying into the wrong AWS account
  allowed_account_ids = [var.aws_account_id]

  default_tags {
    tags = local.tags
  }
}

# Replica region (used only when replication_enabled = true)
provider "aws" {
  alias  = "replica"
  region = var.replication_region

  allowed_account_ids = [var.aws_account_id]

  default_tags {
    tags = local.tags
  }
}
