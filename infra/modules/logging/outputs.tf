output "alb_log_bucket_name" {
  description = "S3 bucket name where ALB access logs are delivered"
  value       = aws_s3_bucket.alb_logs.bucket
}

output "alb_log_access_bucket_name" {
  description = "S3 bucket name that receives S3 server access logs for the ALB logs bucket"
  value       = aws_s3_bucket.alb_logs_access.bucket
}

output "cloudwatch_logs_kms_key_arn" {
  description = "KMS CMK ARN for CloudWatch Log Groups encryption"
  value       = aws_kms_key.cloudwatch_logs.arn
}
