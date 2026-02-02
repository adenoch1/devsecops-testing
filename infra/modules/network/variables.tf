variable "name_prefix" {
  type        = string
  description = "Prefix for naming resources"
}

variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR"
}

variable "tags" {
  type        = map(string)
  description = "Common tags"
}

variable "flow_log_retention_days" {
  type        = number
  description = "Retention (days) for VPC Flow Logs CloudWatch log group"
  default     = 30
}

variable "cloudwatch_logs_kms_key_arn" {
  type        = string
  description = "KMS Key ARN to encrypt CloudWatch log groups (ECS + VPC Flow Logs)"
}
