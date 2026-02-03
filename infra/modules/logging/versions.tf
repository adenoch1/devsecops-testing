terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"

      # Allows the root module to pass an aliased provider config like:
      # providers = { aws = aws, aws.replica = aws.replica }
      configuration_aliases = [aws.replica]
    }
  }
}
