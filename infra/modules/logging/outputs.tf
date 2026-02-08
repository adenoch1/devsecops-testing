output "alb_log_bucket_name" {
  description = "S3 bucket name where ALB access logs are delivered"
  value       = aws_s3_bucket.alb_logs.bucket
}

output "alb_log_access_bucket_name" {
  description = "S3 bucket name that receives S3 server access logs for the ALB logs bucket"
  value       = aws_s3_bucket.alb_logs_access.bucket
}

output "alb_logs_kms_key_arn" {
  description = "KMS CMK ARN used for encrypting the ALB log buckets (SSE-KMS)"
  value       = aws_kms_key.alb_logs.arn
}

output "s3_log_events_topic_arn" {
  description = "SNS topic ARN that receives S3 log bucket event notifications"
  value       = aws_sns_topic.s3_log_events.arn
}

output "cloudwatch_logs_kms_key_arn" {
  description = "KMS CMK ARN for CloudWatch Log Groups encryption"
  value       = aws_kms_key.cloudwatch_logs.arn
}
