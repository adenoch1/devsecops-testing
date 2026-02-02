output "alb_log_prefix" {
  value       = var.alb_log_prefix
  description = "Prefix inside the S3 bucket for ALB access logs"
}


output "alb_logs_bucket_name" {
  description = "Name of the S3 bucket that receives ALB access logs"
  value       = aws_s3_bucket.alb_logs.bucket
}

output "cloudwatch_logs_kms_key_arn" {
  description = "KMS key ARN used to encrypt CloudWatch log groups"
  value       = aws_kms_key.cloudwatch_logs.arn
}

