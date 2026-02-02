output "alb_log_bucket_name" {
  value       = aws_s3_bucket.alb_logs.bucket
  description = "S3 bucket name for ALB access logs"
}

output "alb_log_prefix" {
  value       = var.alb_log_prefix
  description = "Prefix inside the S3 bucket for ALB access logs"
}

output "cloudwatch_logs_kms_key_arn" {
  value       = aws_kms_key.cloudwatch_logs.arn
  description = "KMS key ARN for encrypting CloudWatch Log Groups"
}
