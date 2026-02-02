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
