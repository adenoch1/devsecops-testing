output "alb_logs_bucket_name" {
  description = "S3 bucket name where ALB access logs are stored"
  value       = aws_s3_bucket.alb_logs.bucket
}

output "alb_logs_access_bucket_name" {
  description = "S3 bucket name used for S3 access logging"
  value       = aws_s3_bucket.alb_logs_access.bucket
}

output "cloudwatch_logs_kms_key_arn" {
  description = "KMS key ARN used to encrypt CloudWatch log groups"
  value       = aws_kms_key.alb_logs.arn
}

output "alb_logs_kms_key_arn" {
  description = "KMS key ARN used to encrypt ALB logs buckets"
  value       = aws_kms_key.alb_logs.arn
}

output "vpc_flow_log_group_name" {
  description = "CloudWatch log group name for VPC flow logs"
  value       = aws_cloudwatch_log_group.vpc_flow.name
}

output "alb_logs_events_queue_arn" {
  description = "SQS queue ARN used for ALB log event notifications"
  value       = aws_sqs_queue.alb_logs_events.arn
}
