variable "name_prefix" {
  type        = string
  description = "Prefix for naming resources"
}

variable "tags" {
  type        = map(string)
  description = "Common tags"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID"
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "Public subnet IDs (ALB here)"
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnet IDs (ECS tasks here)"
}

variable "ecr_repository_url" {
  type        = string
  description = "ECR repository URL"
}

variable "ecs_task_execution_role_arn" {
  type        = string
  description = "ECS task execution role ARN"
}

variable "ecs_task_role_arn" {
  type        = string
  description = "ECS task role ARN"
}

variable "app_port" {
  type        = number
  description = "Application port"
}

variable "container_image_tag" {
  type        = string
  description = "Image tag"
  default     = "latest"
}

variable "desired_count" {
  type        = number
  description = "Desired tasks"
  default     = 1
}

variable "task_cpu" {
  type        = number
  description = "Fargate CPU"
  default     = 256
}

variable "task_memory" {
  type        = number
  description = "Fargate memory (MB)"
  default     = 512
}

# Week 3 hardening
variable "acm_certificate_arn" {
  type        = string
  description = "ACM certificate ARN for the ALB HTTPS listener (must be in same region)"
}

variable "alb_log_bucket_name" {
  type        = string
  description = "S3 bucket name to store ALB access logs"
}

variable "alb_log_prefix" {
  type        = string
  description = "S3 prefix for ALB access logs (must not contain 'AWSLogs')"
  default     = "alb-access"
}

variable "cloudwatch_logs_kms_key_arn" {
  type        = string
  description = "KMS key ARN to encrypt CloudWatch log groups"
}

variable "log_retention_days" {
  type        = number
  description = "Retention (days) for ECS CloudWatch logs"
  default     = 14
}


