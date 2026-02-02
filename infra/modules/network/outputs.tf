output "vpc_id" {
  value = aws_vpc.this.id
}

output "public_subnet_ids" {
  value = [for s in aws_subnet.public : s.id]
}

output "private_subnet_ids" {
  value = [for s in aws_subnet.private : s.id]
}

output "vpc_flow_log_group_name" {
  value       = aws_cloudwatch_log_group.vpc_flow.name
  description = "CloudWatch Log Group name for VPC Flow Logs"
}
