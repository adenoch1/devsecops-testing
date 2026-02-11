# -----------------------------
# Week 3 DevSecOps - Bootstrap
# Remote state + locking + KMS + logs bucket
# -----------------------------

aws_region  = "ca-central-1"
name_prefix = "devsecops-flask-dev"

# S3 bucket names must be globally unique.
# Keep them stable (do NOT change after first apply) so your backend remains consistent.
tfstate_bucket_name = "devsecops-testing-tfstate-enoch-2026"
logs_bucket_name    = "devsecops-flask-dev-logs-enoch-2026"

# Production default: protect logs from accidental deletion.
# For labs only, you may set this to true to allow full cleanup.
logs_bucket_force_destroy = false

# DynamoDB lock table name
lock_table_name = "devsecops-testing-tflocks"

# Standard tags (used for governance + least privilege conditions)
tags = {
  Project     = "devsecops-flask"
  Environment = "dev"
  Owner       = "enoch"
  ManagedBy   = "Terraform"
}
