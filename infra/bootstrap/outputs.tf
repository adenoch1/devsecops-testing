output "tfstate_bucket_name" {
  description = "S3 bucket name for Terraform remote state"
  value       = aws_s3_bucket.tfstate.bucket
}

output "tflocks_table_name" {
  description = "DynamoDB table name for Terraform state locking"
  value       = aws_dynamodb_table.tflocks.name
}

output "tfstate_kms_key_arn" {
  description = "KMS key ARN used for encrypting the Terraform state bucket (SSE-KMS)"
  value       = aws_kms_key.tfstate.arn
}

output "tflocks_kms_key_arn" {
  description = "KMS key ARN used for encrypting the DynamoDB lock table (SSE-KMS)"
  value       = aws_kms_key.tflocks.arn
}
