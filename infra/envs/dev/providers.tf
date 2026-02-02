provider "aws" {
  region = var.aws_region
}

provider "aws" {
  alias  = "replica"
  region = var.replication_region
}

module "logging" {
  source = "../../modules/logging"

  providers = {
    aws         = aws
    aws.replica = aws.replica
  }

  # ... your existing vars
}
