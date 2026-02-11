variable "aws_region" {
  description = "AWS region to deploy bootstrap resources into"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for naming bootstrap resources"
  type        = string
}

variable "tfstate_bucket_name" {
  description = "Name of S3 bucket for Terraform state"
  type        = string
}

variable "logs_bucket_name" {
  description = "Name of S3 bucket for security / ALB / WAF logs"
  type        = string
}

variable "logs_bucket_force_destroy" {
  description = "Whether the logs bucket should be force-destroyed (NOT recommended for prod)"
  type        = bool
  default     = false
}

variable "lock_table_name" {
  description = "Name of DynamoDB table for Terraform state locking"
  type        = string
}

variable "tags" {
  description = "Standard tags applied to all resources"
  type        = map(string)
  default     = {}
}
