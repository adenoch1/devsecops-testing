output "state_bucket_name" {
  value       = aws_s3_bucket.tfstate.bucket
  description = "Remote state S3 bucket name"
}

output "lock_table_name" {
  value       = aws_dynamodb_table.tflocks.name
  description = "DynamoDB lock table name"
}
