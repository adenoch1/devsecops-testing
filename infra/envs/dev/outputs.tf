output "alb_dns_name" {
  description = "ALB DNS name (if ECS module is enabled)"
  value       = try(module.ecs.alb_dns_name, null)
}

output "ecr_repository_url" {
  description = "ECR repository URL (if ECR module is enabled)"
  value       = try(module.ecr.repository_url, null)
}

output "alb_arn" {
  description = "ALB ARN (if ECS module is enabled)"
  value       = try(module.ecs.alb_arn, null)
}
