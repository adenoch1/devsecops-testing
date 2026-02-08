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
}

# Replica region (used only when replication_enabled = true)
provider "aws" {
  alias  = "replica"
  region = var.replication_region
}
