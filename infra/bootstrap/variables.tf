variable "aws_region" {
  description = "AWS region for the backend resources"
  type        = string
  default     = "ca-central-1"
}

variable "state_bucket_name" {
  description = "S3 bucket name for Terraform remote state (must be globally unique)"
  type        = string
  default     = "devsecops-testing-tfstate-enoch-2026"
}

variable "lock_table_name" {
  description = "DynamoDB table name for Terraform state locking"
  type        = string
  default     = "devsecops-testing-tflocks"
}

variable "tags" {
  description = "Common tags"
  type        = map(string)
  default = {
    Project   = "devsecops-project1"
    ManagedBy = "Terraform"
  }
}
