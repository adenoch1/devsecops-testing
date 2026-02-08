data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  log_bucket_name        = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-alb-logs"
  log_access_bucket_name = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-alb-logs-access"
}

# ------------------------------------------------------------
# Access-logs bucket (target for S3 server access logs)
# ------------------------------------------------------------
resource "aws_s3_bucket" "alb_logs_access" {
  bucket        = local.log_access_bucket_name
  force_destroy = true

  tags = merge(var.tags, {
    Name = local.log_access_bucket_name
  })
}

resource "aws_s3_bucket_public_access_block" "alb_logs_access" {
  bucket                  = aws_s3_bucket.alb_logs_access.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "alb_logs_access" {
  bucket = aws_s3_bucket.alb_logs_access.id
  versioning_configuration {
    status = "Enabled"
  }
}

# ✅ Use SSE-S3 for reliability with service-delivered logs
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs_access" {
  bucket = aws_s3_bucket.alb_logs_access.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs_access" {
  bucket = aws_s3_bucket.alb_logs_access.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }

    expiration {
      days = var.lifecycle_expire_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.lifecycle_expire_days
    }
  }
}

# ------------------------------------------------------------
# Main ALB Logs bucket (the bucket ALB writes to)
# ------------------------------------------------------------
resource "aws_s3_bucket" "alb_logs" {
  bucket        = local.log_bucket_name
  force_destroy = true

  tags = merge(var.tags, {
    Name = local.log_bucket_name
  })
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# ✅ Use SSE-S3 for reliability with ALB log delivery
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }

    expiration {
      days = var.lifecycle_expire_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.lifecycle_expire_days
    }
  }
}

# ✅ ALB logs bucket writes its SERVER ACCESS LOGS into access bucket
resource "aws_s3_bucket_logging" "alb_logs" {
  bucket        = aws_s3_bucket.alb_logs.id
  target_bucket = aws_s3_bucket.alb_logs_access.id
  target_prefix = "s3-access/${var.name_prefix}/"
}

# ------------------------------------------------------------
# Bucket policies
# ------------------------------------------------------------

# ✅ ALB access logs delivery -> alb_logs bucket
data "aws_iam_policy_document" "alb_logs_bucket_policy" {
  statement {
    sid    = "AllowELBLogDeliveryAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.alb_logs.arn]
  }

  statement {
    sid    = "AllowELBLogDeliveryWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }

    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.alb_logs.arn}/${var.alb_log_prefix}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
    ]

    # ✅ tight safety scope
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = data.aws_iam_policy_document.alb_logs_bucket_policy.json
}

# ✅ S3 server access logs delivery -> MUST be on the TARGET bucket (alb_logs_access)
data "aws_iam_policy_document" "alb_logs_access_bucket_policy" {
  statement {
    sid    = "AllowS3ServerAccessLogsAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.alb_logs_access.arn]
  }

  statement {
    sid    = "AllowS3ServerAccessLogsWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.alb_logs_access.arn}/s3-access/${var.name_prefix}/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs_access" {
  bucket = aws_s3_bucket.alb_logs_access.id
  policy = data.aws_iam_policy_document.alb_logs_access_bucket_policy.json
}

# -----------------------------------------------------------
# KMS key for CloudWatch Log Groups (keep KMS where it matters)
# -----------------------------------------------------------
resource "aws_kms_key" "cloudwatch_logs" {
  description             = "KMS key for CloudWatch Logs (${var.name_prefix})"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchLogsUse"
        Effect    = "Allow"
        Principal = { Service = "logs.${data.aws_region.current.id}.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = "${data.aws_caller_identity.current.account_id}"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, { Name = "${var.name_prefix}-cloudwatch-logs-kms" })
}

resource "aws_kms_alias" "cloudwatch_logs" {
  name          = "alias/${var.name_prefix}-cloudwatch-logs"
  target_key_id = aws_kms_key.cloudwatch_logs.key_id
}
