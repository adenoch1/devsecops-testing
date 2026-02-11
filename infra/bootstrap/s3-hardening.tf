# Additional S3 hardening / defaults
# NOTE: Some settings (like Object Lock) require special bucket creation flags and cannot be enabled after creation.

# Optional: lifecycle policy for logs bucket (example: move to IA / expire)
resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "logs-lifecycle"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 365
    }
  }
}

# Optional: lifecycle policy for tfstate bucket (generally you keep state long-term; keep minimal)
resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    id     = "tfstate-lifecycle"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}
