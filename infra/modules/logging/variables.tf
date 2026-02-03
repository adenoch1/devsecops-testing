variable "name_prefix" {
  description = "Prefix for naming resources"
  type        = string
}

variable "tags" {
  description = "Common tags applied to resources"
  type        = map(string)
  default     = {}
}

variable "flow_log_retention_days" {
  description = "Retention (days) for the VPC flow logs CloudWatch log group"
  type        = number
  default     = 365
}
