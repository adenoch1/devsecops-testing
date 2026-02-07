terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

# -----------------------------
# KMS for TF State (CMK)
# -----------------------------
resource "aws_kms_key" "tfstate" {
  description             = "KMS key for Terraform remote state encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = merge(var.tags, {
    Name = "tfstate-kms"
  })
}

data "aws_iam_policy_document" "tfstate_kms_policy" {
  statement {
    sid     = "EnableRootPermissions"
    effect  = "Allow"
    actions = ["kms:*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    resources = ["*"]
  }
}

resource "aws_kms_key_policy" "tfstate" {
  key_id = aws_kms_key.tfstate.id
  policy = data.aws_iam_policy_document.tfstate_kms_policy.json
}

# -----------------------------
# KMS for DynamoDB Locks (CMK)
# -----------------------------
resource "aws_kms_key" "tflocks" {
  description             = "KMS key for Terraform DynamoDB locks encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = merge(var.tags, {
    Name = "tflocks-kms"
  })
}

data "aws_iam_policy_document" "tflocks_kms_policy" {
  statement {
    sid     = "EnableRootPermissions"
    effect  = "Allow"
    actions = ["kms:*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    resources = ["*"]
  }
}

resource "aws_kms_key_policy" "tflocks" {
  key_id = aws_kms_key.tflocks.id
  policy = data.aws_iam_policy_document.tflocks_kms_policy.json
}

# -----------------------------
# S3 bucket for TF State logs (target for access logging)
# -----------------------------
resource "aws_s3_bucket" "tfstate_logs" {
  bucket = "${var.state_bucket_name}-logs"

  tags = merge(var.tags, {
    Name = "${var.state_bucket_name}-logs"
  })
}

resource "aws_s3_bucket_public_access_block" "tfstate_logs" {
  bucket                  = aws_s3_bucket.tfstate_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "tfstate_logs" {
  bucket = aws_s3_bucket.tfstate_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate_logs" {
  bucket = aws_s3_bucket.tfstate_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# -----------------------------
# S3 bucket for Terraform remote state
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

# ✅ CKV_AWS_18: Access logging enabled (log target bucket + logging config)
resource "aws_s3_bucket_logging" "tfstate" {
  bucket        = aws_s3_bucket.tfstate.id
  target_bucket = aws_s3_bucket.tfstate_logs.id
  target_prefix = "tfstate/"
}

# ✅ CKV_AWS_300: Abort incomplete multipart uploads + noncurrent expiry
resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "noncurrent-version-expiry"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# -----------------------------
# ✅ CKV2_AWS_62: S3 Event Notifications enabled
# (Minimal, production-valid: send events to SNS topic)
# -----------------------------
resource "aws_sns_topic" "tfstate_events" {
  name = "${var.state_bucket_name}-events"

  tags = merge(var.tags, {
    Name = "${var.state_bucket_name}-events"
  })
}

data "aws_iam_policy_document" "sns_allow_s3_publish" {
  statement {
    sid    = "AllowS3Publish"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.tfstate_events.arn]

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.tfstate.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "tfstate_events" {
  arn    = aws_sns_topic.tfstate_events.arn
  policy = data.aws_iam_policy_document.sns_allow_s3_publish.json
}

resource "aws_s3_bucket_notification" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  topic {
    topic_arn = aws_sns_topic.tfstate_events.arn
    events    = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
  }

  depends_on = [aws_sns_topic_policy.tfstate_events]
}

# -----------------------------
# DynamoDB table for state locking
# ✅ CKV_AWS_119: CMK encryption (kms_key_arn)
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
    enabled     = true
    kms_key_arn = aws_kms_key.tflocks.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(var.tags, {
    Name = var.lock_table_name
  })
}

# -----------------------------
# Outputs (handy for bootstrap)
# -----------------------------
output "tfstate_bucket_name" {
  value = aws_s3_bucket.tfstate.bucket
}

output "tfstate_kms_key_arn" {
  value = aws_kms_key.tfstate.arn
}

output "tflocks_table_name" {
  value = aws_dynamodb_table.tflocks.name
}

output "tflocks_kms_key_a_
