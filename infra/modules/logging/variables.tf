variable "name_prefix" {
  type        = string
  description = "Prefix for naming resources"
}

variable "tags" {
  type        = map(string)
  description = "Common tags"
}

variable "alb_log_prefix" {
  type        = string
  description = "Prefix inside the S3 bucket for ALB access logs (must not contain 'AWSLogs')"
  default     = "alb-access"
}

variable "lifecycle_expire_days" {
  type    = number
  default = 365
}

variable "lifecycle_glacier_days" {
  type    = number
  default = 90
}

variable "replication_enabled" {
  type    = bool
  default = true
}

variable "replication_region" {
  type    = string
  default = "us-east-1"
}

