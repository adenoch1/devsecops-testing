output "alb_log_bucket_name" {
  description = "S3 bucket name where ALB access logs are delivered"
  value       = aws_s3_bucket.alb_logs.bucket
}

output "alb_log_access_bucket_name" {
  description = "S3 bucket name that receives S3 server access logs for the ALB logs bucket"
  value       = aws_s3_bucket.alb_logs_access.bucket
}

output "alb_log_audit_bucket_name" {
  description = "S3 bucket name that receives access logs from the access bucket (audit bucket)"
  value       = aws_s3_bucket.alb_logs_audit.bucket
}

output "alb_log_audit_access_bucket_name" {
  description = "Terminal S3 bucket name that receives access logs for the audit bucket (end of chain)"
  value       = aws_s3_bucket.alb_logs_audit_access.bucket
}

output "alb_logs_kms_key_arn" {
  description = "KMS CMK ARN used for encrypting the ALB log buckets (SSE-KMS)"
  value       = aws_kms_key.alb_logs.arn
}

output "cloudwatch_logs_kms_key_arn" {
  description = "KMS CMK ARN for CloudWatch Log Groups encryption"
  value       = aws_kms_key.cloudwatch_logs.arn
}

output "sns_kms_key_arn" {
  description = "KMS CMK ARN used to encrypt the SNS topic"
  value       = aws_kms_key.sns.arn
}
