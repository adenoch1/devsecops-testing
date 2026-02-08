output "state_bucket_name" {
  value       = aws_s3_bucket.tfstate.bucket
  description = "Remote state S3 bucket name"
}

output "lock_table_name" {
  value       = aws_dynamodb_table.tflocks.name
  description = "DynamoDB lock table name"
}

output "tfstate_kms_key_arn" {
  value       = aws_kms_key.tfstate.arn
  description = "KMS key ARN used to encrypt tfstate"
}

output "tflocks_kms_key_arn" {
  value       = aws_kms_key.tflocks.arn
  description = "KMS key ARN used to encrypt DynamoDB locks"
}
