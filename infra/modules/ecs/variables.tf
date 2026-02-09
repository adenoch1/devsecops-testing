variable "name_prefix" {
  description = "Prefix used to name resources"
  type        = string
}

variable "tags" {
  description = "Common tags applied to resources"
  type        = map(string)
  default     = {}
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnet IDs for the ALB"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for ECS tasks"
  type        = list(string)
}

variable "app_port" {
  description = "Application port exposed by the container"
  type        = number
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for HTTPS listener"
  type        = string
}

variable "alb_log_bucket_name" {
  description = "S3 bucket name for ALB access logs"
  type        = string
}

variable "alb_log_prefix" {
  description = "S3 prefix for ALB access logs"
  type        = string
  default     = "alb-access"
}

variable "cloudwatch_logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch log group encryption"
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 14
}

variable "ecr_repository_url" {
  description = "ECR repository URL (without tag)"
  type        = string
}

variable "container_image_tag" {
  description = "Container image tag to deploy"
  type        = string
}

variable "task_cpu" {
  description = "Fargate task CPU"
  type        = number
  default     = 256
}

variable "task_memory" {
  description = "Fargate task memory"
  type        = number
  default     = 512
}

variable "desired_count" {
  description = "Desired number of tasks"
  type        = number
  default     = 2
}

variable "ecs_task_execution_role_arn" {
  description = "IAM role ARN for ECS task execution role"
  type        = string
}

variable "ecs_task_role_arn" {
  description = "IAM role ARN for ECS task role"
  type        = string
}

# ------------------------------------------------------------
# WAF Logs bucket lifecycle controls (used in ecs/main.tf)
# ------------------------------------------------------------
variable "lifecycle_expire_days" {
  description = "Days before objects expire in WAF logging buckets"
  type        = number
  default     = 90
}

variable "lifecycle_glacier_days" {
  description = "Days before objects transition to Glacier in WAF logging buckets"
  type        = number
  default     = 30
}
