output "tfstate_bucket_name" {
  value       = aws_s3_bucket.tfstate.bucket
  description = "Terraform remote state bucket name"
}

output "lock_table_name" {
  value       = aws_dynamodb_table.tflocks.name
  description = "Terraform state lock DynamoDB table name"
}

output "tfstate_kms_key_arn" {
  value       = aws_kms_key.tfstate.arn
  description = "KMS key ARN for Terraform state encryption"
}

output "logs_bucket_name" {
  value       = aws_s3_bucket.logs.bucket
  description = "Logs bucket name"
}

output "logs_kms_key_arn" {
  value       = aws_kms_key.logs.arn
  description = "KMS key ARN for logs encryption"
}
