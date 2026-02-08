data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.id

  log_bucket_name              = "${var.name_prefix}-alb-logs-${local.account_id}"
  log_access_bucket_name       = "${var.name_prefix}-alb-logs-access-${local.account_id}"
  log_audit_bucket_name        = "${var.name_prefix}-alb-audit-logs-${local.account_id}"
  log_audit_access_bucket_name = "${var.name_prefix}-alb-audit-logs-access-${local.account_id}"

  # Bucket that stores access logs for the access-log buckets
  access_audit_bucket_name = "${var.name_prefix}-alb-access-audit-${local.account_id}"

  # Final sink bucket so the audit bucket itself can have logging enabled (tfsec)
  access_audit_sink_bucket_name = "${var.name_prefix}-alb-access-audit-sink-${local.account_id}"
}

# ------------------------------------------------------------
# KMS keys (for ALB logs and CloudWatch Logs)
# ------------------------------------------------------------
resource "aws_kms_key" "alb_logs" {
  description             = "KMS key for ALB access log buckets"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowS3UseOfKey"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.tags, { Name = "${var.name_prefix}-alb-logs-kms" })
}

resource "aws_kms_alias" "alb_logs" {
  name          = "alias/${var.name_prefix}-alb-logs"
  target_key_id = aws_kms_key.alb_logs.key_id
}

resource "aws_kms_key" "cloudwatch_logs" {
  description             = "KMS key for CloudWatch Logs"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchLogsUseOfKey"
        Effect    = "Allow"
        Principal = { Service = "logs.${local.region}.amazonaws.com" }
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
            "aws:SourceAccount" = local.account_id
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

# ------------------------------------------------------------
# Final sink bucket (stores access logs for access_audit bucket)
# ------------------------------------------------------------
resource "aws_s3_bucket" "access_audit_sink" {
  bucket        = local.access_audit_sink_bucket_name
  force_destroy = true

  tags = merge(var.tags, { Name = local.access_audit_sink_bucket_name })
}

resource "aws_s3_bucket_public_access_block" "access_audit_sink" {
  bucket                  = aws_s3_bucket.access_audit_sink.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "access_audit_sink" {
  bucket = aws_s3_bucket.access_audit_sink.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_audit_sink" {
  bucket = aws_s3_bucket.access_audit_sink.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.alb_logs.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_audit_sink" {
  bucket = aws_s3_bucket.access_audit_sink.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = var.lifecycle_expire_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.lifecycle_expire_days
    }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

# ------------------------------------------------------------
# Access-Audit bucket (stores logs for the access-log buckets)
# ------------------------------------------------------------
resource "aws_s3_bucket" "access_audit" {
  bucket        = local.access_audit_bucket_name
  force_destroy = true

  tags = merge(var.tags, { Name = local.access_audit_bucket_name })
}

resource "aws_s3_bucket_public_access_block" "access_audit" {
  bucket                  = aws_s3_bucket.access_audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "access_audit" {
  bucket = aws_s3_bucket.access_audit.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_audit" {
  bucket = aws_s3_bucket.access_audit.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.alb_logs.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_audit" {
  bucket = aws_s3_bucket.access_audit.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = var.lifecycle_expire_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.lifecycle_expire_days
    }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

# ✅ tfsec fix: enable logging for access_audit bucket (to sink)
resource "aws_s3_bucket_logging" "access_audit" {
  bucket        = aws_s3_bucket.access_audit.id
  target_bucket = aws_s3_bucket.access_audit_sink.id
  target_prefix = "${var.alb_log_prefix}/access-audit/"
}

# ------------------------------------------------------------
# Access logs bucket for main ALB logs bucket
# ------------------------------------------------------------
resource "aws_s3_bucket" "alb_logs_access" {
  bucket        = local.log_access_bucket_name
  force_destroy = true

  tags = merge(var.tags, { Name = local.log_access_bucket_name })
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
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs_access" {
  bucket = aws_s3_bucket.alb_logs_access.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.alb_logs.arn
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

    expiration {
      days = var.lifecycle_expire_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.lifecycle_expire_days
    }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_logging" "alb_logs_access" {
  bucket        = aws_s3_bucket.alb_logs_access.id
  target_bucket = aws_s3_bucket.access_audit.id
  target_prefix = "${var.alb_log_prefix}/access-bucket/"
}

# ------------------------------------------------------------
# Main ALB logs bucket
# ------------------------------------------------------------
resource "aws_s3_bucket" "alb_logs" {
  bucket        = local.log_bucket_name
  force_destroy = true

  tags = merge(var.tags, { Name = local.log_bucket_name })
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
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.alb_logs.arn
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

    expiration {
      days = var.lifecycle_expire_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.lifecycle_expire_days
    }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_logging" "alb_logs" {
  bucket        = aws_s3_bucket.alb_logs.id
  target_bucket = aws_s3_bucket.alb_logs_access.id
  target_prefix = "${var.alb_log_prefix}/"
}

# ------------------------------------------------------------
# Audit logs bucket + its access bucket
# ------------------------------------------------------------
resource "aws_s3_bucket" "alb_logs_audit" {
  bucket        = local.log_audit_bucket_name
  force_destroy = true

  tags = merge(var.tags, { Name = local.log_audit_bucket_name })
}

resource "aws_s3_bucket_public_access_block" "alb_logs_audit" {
  bucket                  = aws_s3_bucket.alb_logs_audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "alb_logs_audit" {
  bucket = aws_s3_bucket.alb_logs_audit.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs_audit" {
  bucket = aws_s3_bucket.alb_logs_audit.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.alb_logs.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs_audit" {
  bucket = aws_s3_bucket.alb_logs_audit.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = var.lifecycle_expire_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.lifecycle_expire_days
    }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket" "alb_logs_audit_access" {
  bucket        = local.log_audit_access_bucket_name
  force_destroy = true

  tags = merge(var.tags, { Name = local.log_audit_access_bucket_name })
}

resource "aws_s3_bucket_public_access_block" "alb_logs_audit_access" {
  bucket                  = aws_s3_bucket.alb_logs_audit_access.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "alb_logs_audit_access" {
  bucket = aws_s3_bucket.alb_logs_audit_access.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs_audit_access" {
  bucket = aws_s3_bucket.alb_logs_audit_access.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.alb_logs.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs_audit_access" {
  bucket = aws_s3_bucket.alb_logs_audit_access.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = var.lifecycle_expire_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.lifecycle_expire_days
    }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_logging" "alb_logs_audit_access" {
  bucket        = aws_s3_bucket.alb_logs_audit_access.id
  target_bucket = aws_s3_bucket.access_audit.id
  target_prefix = "${var.alb_log_prefix}/audit-access-bucket/"
}

resource "aws_s3_bucket_logging" "alb_logs_audit" {
  bucket        = aws_s3_bucket.alb_logs_audit.id
  target_bucket = aws_s3_bucket.alb_logs_audit_access.id
  target_prefix = "${var.alb_log_prefix}/audit/"
}

# -----------------------------
# S3 Event Notifications (Checkov CKV2_AWS_62)
# -----------------------------
resource "aws_sns_topic" "s3_events" {
  name              = "${var.name_prefix}-alb-logs-s3-events"
  kms_master_key_id = aws_kms_key.alb_logs.arn

  tags = merge(var.tags, { Name = "${var.name_prefix}-alb-logs-s3-events" })
}

data "aws_iam_policy_document" "s3_events_topic_policy" {
  statement {
    sid    = "AllowS3Publish"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.s3_events.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values = [
        aws_s3_bucket.alb_logs.arn,
        aws_s3_bucket.alb_logs_access.arn,
        aws_s3_bucket.alb_logs_audit.arn,
        aws_s3_bucket.alb_logs_audit_access.arn,
        aws_s3_bucket.access_audit.arn,
        aws_s3_bucket.access_audit_sink.arn
      ]
    }
  }
}

resource "aws_sns_topic_policy" "s3_events" {
  arn    = aws_sns_topic.s3_events.arn
  policy = data.aws_iam_policy_document.s3_events_topic_policy.json
}

resource "aws_s3_bucket_notification" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic_policy.s3_events]
}

resource "aws_s3_bucket_notification" "alb_logs_access" {
  bucket = aws_s3_bucket.alb_logs_access.id

  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic_policy.s3_events]
}

resource "aws_s3_bucket_notification" "alb_logs_audit" {
  bucket = aws_s3_bucket.alb_logs_audit.id

  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic_policy.s3_events]
}

resource "aws_s3_bucket_notification" "alb_logs_audit_access" {
  bucket = aws_s3_bucket.alb_logs_audit_access.id

  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic_policy.s3_events]
}

resource "aws_s3_bucket_notification" "access_audit" {
  bucket = aws_s3_bucket.access_audit.id

  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic_policy.s3_events]
}

resource "aws_s3_bucket_notification" "access_audit_sink" {
  bucket = aws_s3_bucket.access_audit_sink.id

  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic_policy.s3_events]
}
