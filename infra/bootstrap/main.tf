provider "aws" {
  region = var.aws_region
}

# -----------------------------
# KMS key for tfstate encryption (SSE-KMS)
# -----------------------------
resource "aws_kms_key" "tfstate" {
  description             = "KMS key for Terraform remote state encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = merge(var.tags, {
    Name = "tfstate-kms"
  })
}

resource "aws_kms_alias" "tfstate" {
  name          = "alias/devsecops-tfstate"
  target_key_id = aws_kms_key.tfstate.key_id
}

# -----------------------------
# S3 bucket for Terraform state
# -----------------------------
resource "aws_s3_bucket" "tfstate" {
  bucket = var.state_bucket_name

  tags = merge(var.tags, {
    Name = var.state_bucket_name
  })
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.tfstate.arn
    }
  }
}

# Enforce TLS-only access to the tfstate bucket
data "aws_iam_policy_document" "tfstate_deny_insecure" {
  statement {
    sid = "DenyInsecureTransport"

    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.tfstate.arn,
      "${aws_s3_bucket.tfstate.arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  policy = data.aws_iam_policy_document.tfstate_deny_insecure.json
}

# Lifecycle policy (keep bucket tidy but safe)
resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    id     = "noncurrent-version-expiry"
    status = "Enabled"

    # REQUIRED by provider (even if you want it to apply to everything)
    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}


# -----------------------------
# DynamoDB table for state locking
# -----------------------------
resource "aws_dynamodb_table" "tflocks" {
  name         = var.lock_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(var.tags, {
    Name = var.lock_table_name
  })
}
