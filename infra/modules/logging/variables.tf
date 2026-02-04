variable "name_prefix" {
  description = "Prefix for naming resources"
  type        = string
}

variable "tags" {
  description = "Common tags applied to resources"
  type        = map(string)
  default     = {}
}

# Passed from root module (kept for compatibility)
variable "alb_log_prefix" {
  description = "Prefix for ALB logs in the S3 bucket (kept for compatibility with root module)"
  type        = string
  default     = "alb-access"
}

# Lifecycle tuning for S3 buckets
variable "lifecycle_expire_days" {
  description = "Number of days to expire objects in log buckets"
  type        = number
  default     = 365
}

variable "lifecycle_glacier_days" {
  description = "Number of days before transitioning objects to GLACIER"
  type        = number
  default     = 30
}

# Replication controls (kept for compatibility; not implemented in this demo)
variable "replication_enabled" {
  description = "Enable cross-region replication for log buckets (not implemented in this demo)"
  type        = bool
  default     = false
}

variable "replication_region" {
  description = "Destination region for replication (not implemented in this demo)"
  type        = string
  default     = ""
}

# CloudWatch retention
variable "flow_log_retention_days" {
  description = "Retention (days) for the VPC flow logs CloudWatch log group"
  type        = number
  default     = 365
}
