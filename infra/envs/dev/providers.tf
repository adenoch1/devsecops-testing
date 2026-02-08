# Primary region
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.tags
  }
}

# Replica region (needed because some modules pass aws.replica in providers map)
# If you are not using replication yet, it is still safe to define this alias.
provider "aws" {
  alias  = "replica"
  region = var.replication_region

  default_tags {
    tags = var.tags
  }
}
