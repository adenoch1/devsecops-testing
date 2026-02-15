output "alb_dns_name" {
  value = aws_lb.this.dns_name
}

output "alb_arn" {
  value = aws_lb.this.arn
}

output "alb_name" {
  value = aws_lb.this.name
}


output "alb_target_group_arn" {
  value       = aws_lb_target_group.app.arn
  description = "Target Group ARN for health checks"
}

output "ecs_cluster_name" {
  value       = aws_ecs_cluster.this.name
  description = "ECS cluster name"
}

output "ecs_service_name" {
  value       = aws_ecs_service.app.name
  description = "ECS service name"
}
