terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"

      # Allow the root module to pass an aliased AWS provider (aws.replica) into this module
      configuration_aliases = [aws.replica]
    }
  }
}
