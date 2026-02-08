output "alb_log_bucket_name" {
  description = "S3 bucket name for ALB access logs"
  value       = aws_s3_bucket.alb_logs.bucket
}

output "alb_log_bucket_arn" {
  description = "S3 bucket ARN for ALB access logs"
  value       = aws_s3_bucket.alb_logs.arn
}

output "alb_logs_kms_key_arn" {
  description = "KMS key ARN used to encrypt the ALB logs bucket"
  value       = aws_kms_key.alb_logs.arn
}

output "cloudwatch_logs_kms_key_arn" {
  description = "KMS key ARN used to encrypt CloudWatch Logs"
  value       = aws_kms_key.cloudwatch_logs.arn
}

output "region" {
  description = "AWS region of the logging module"
  value       = data.aws_region.current.id
}

output "account_id" {
  description = "AWS account id used to name logging resources"
  value       = data.aws_caller_identity.current.account_id
}
