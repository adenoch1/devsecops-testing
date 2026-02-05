terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"

      # This module can accept an aliased AWS provider from the caller
      # (e.g., providers = { aws = aws, aws.replica = aws.replica })
      configuration_aliases = [aws.replica]
    }

    time = {
      source  = "hashicorp/time"
      version = ">= 0.10"
    }
  }
}
