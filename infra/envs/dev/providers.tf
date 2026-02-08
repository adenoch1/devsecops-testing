# Primary region
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.tags
  }
}

# Replica region (required because some modules pass aws.replica)
provider "aws" {
  alias  = "replica"
  region = var.replication_region

  default_tags {
    tags = local.tags
  }
}
