variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ca-central-1"
}

variable "project" {
  description = "Project name"
  type        = string
  default     = "devsecops-testing"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "owner" {
  description = "Owner tag"
  type        = string
  default     = "enoch"
}

variable "tags" {
  description = "Common tags"
  type        = map(string)
  default = {
    Project   = "devsecops-project1"
    ManagedBy = "Terraform"
  }
}
