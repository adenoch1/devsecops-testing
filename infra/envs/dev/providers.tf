provider "aws" {
  region = var.aws_region
}

# Optional: only needed if you are truly implementing cross-region replication.
# If replication_enabled = false, you can remove this whole block.
provider "aws" {
  alias  = "replica"
  region = var.replication_region
}
