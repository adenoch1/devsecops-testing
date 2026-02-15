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


output "alb_target_group_arn" {
  description = "ALB Target Group ARN"
  value       = try(module.ecs.alb_target_group_arn, null)
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = try(module.ecs.ecs_cluster_name, null)
}

output "ecs_service_name" {
  description = "ECS service name"
  value       = try(module.ecs.ecs_service_name, null)
}
