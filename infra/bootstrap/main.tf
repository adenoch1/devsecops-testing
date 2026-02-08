data "aws_caller_identity" "current" {}

# -----------------------------
# KMS keys
# -----------------------------
resource "aws_kms_key" "tfstate" {
  description             = "KMS key for Terraform remote state encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = merge(var.tags, { Name = "tfstate-kms" })
}

data "aws_iam_policy_document" "tfstate_kms_policy" {
  # Root admin (break-glass)
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

  # Allow principals in this account to use the key, but ONLY via S3 in this region.
  # This supports SSE-KMS on the Terraform state bucket without hardcoding role names in the key policy.
  statement {
    sid    = "AllowAccountUseViaS3"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key_policy" "tfstate" {
  key_id = aws_kms_key.tfstate.id
  policy = data.aws_iam_policy_document.tfstate_kms_policy.json
}

resource "aws_kms_key" "tflocks" {
  description             = "KMS key for Terraform DynamoDB locks encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = merge(var.tags, { Name = "tflocks-kms" })
}

data "aws_iam_policy_document" "tflocks_kms_policy" {
  # Root admin (break-glass)
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

  # Allow principals in this account to use the key, but ONLY via DynamoDB in this region.
  # This supports SSE-KMS on the Terraform lock table without hardcoding role names in the key policy.
  statement {
    sid    = "AllowAccountUseViaDynamoDB"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["dynamodb.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key_policy" "tflocks" {
  key_id = aws_kms_key.tflocks.id
  policy = data.aws_iam_policy_document.tflocks_kms_policy.json
}

# -----------------------------
# KMS key for S3 access logs bucket (SSE-KMS)
# -----------------------------
data "aws_iam_policy_document" "tfstate_logs_kms_policy" {
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

  statement {
    sid    = "AllowS3UseForAccessLogsBucket"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "tfstate_logs" {
  description             = "KMS key for Terraform state access logs bucket encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = merge(var.tags, { Name = "tfstate-logs-kms" })
}

resource "aws_kms_key_policy" "tfstate_logs" {
  key_id = aws_kms_key.tfstate_logs.id
  policy = data.aws_iam_policy_document.tfstate_logs_kms_policy.json
}

# -----------------------------
# DynamoDB table for state locking
# -----------------------------
resource "aws_dynamodb_table" "tflocks" {
  name         = "${var.name_prefix}-tflocks"
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

  tags = merge(var.tags, { Name = "${var.name_prefix}-tflocks" })
}

# -----------------------------
# S3 bucket for remote state
# -----------------------------
resource "aws_s3_bucket" "tfstate" {
  bucket        = "${var.name_prefix}-tfstate-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = merge(var.tags, { Name = "${var.name_prefix}-tfstate" })
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
  versioning_configuration { status = "Enabled" }
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

resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}

# -----------------------------
# Access logs bucket for state bucket (optional but recommended)
# -----------------------------
resource "aws_s3_bucket" "tfstate_access_logs" {
  bucket        = "${var.name_prefix}-tfstate-access-${data.aws_caller_identity.current.account_id}"

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.tfstate_logs.arn]
    }
  }
}

resource "aws_s3_bucket_logging" "tfstate" {
  bucket        = aws_s3_bucket.tfstate.id
  target_bucket = aws_s3_bucket.tfstate_access_logs.id
  target_prefix = "s3-access/${var.name_prefix}/"
}
