data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  log_bucket_name        = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-alb-logs"
  log_access_bucket_name = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-alb-logs-access"
}

# -------------------------------------------------------------
# KMS CMK for ALB Logs bucket encryption (source region)
# -------------------------------------------------------------
resource "aws_kms_key" "alb_logs" {
  description             = "CMK for ALB logs buckets (${var.name_prefix})"
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
      }
    ]
  })

  tags = merge(var.tags, { Name = "${var.name_prefix}-alb-logs-kms" })
}

resource "aws_kms_alias" "alb_logs" {
  name          = "alias/${var.name_prefix}-alb-logs"
  target_key_id = aws_kms_key.alb_logs.key_id
}

# ------------------------------------------------------------
# Access-logging target bucket ("log of logs")
# Satisfies CKV_AWS_18 for the MAIN ALB logs bucket.
# ------------------------------------------------------------
resource "aws_s3_bucket" "alb_logs_access" {
  bucket        = local.log_access_bucket_name
  force_destroy = false

  # Replication is intentionally NOT implemented for this demo env.
  #checkov:skip=CKV_AWS_144: "Cross-region replication intentionally disabled for this environment"

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-alb-logs-access"
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

# Enable access logging on the ACCESS bucket (logs-of-logs) to satisfy tfsec aws-s3-enable-bucket-logging
# We point it to the main logs bucket to avoid logging to itself.
resource "aws_s3_bucket_logging" "alb_logs_access" {
  bucket        = aws_s3_bucket.alb_logs_access.id
  target_bucket = aws_s3_bucket.alb_logs.id
  target_prefix = "s3-access/${var.name_prefix}/"
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

# CKV2_AWS_61 + CKV_AWS_300: lifecycle + abort incomplete multipart uploads (access bucket too)
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
  force_destroy = false

  # Replication is intentionally NOT implemented for this demo env.
  #checkov:skip=CKV_AWS_144: "Cross-region replication intentionally disabled for this environment"

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-alb-logs"
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

# CKV_AWS_145: default encryption with CMK (aws:kms)
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.alb_logs.arn
    }
  }
}

# CKV_AWS_18: enable access logging on the ALB logs bucket itself
resource "aws_s3_bucket_logging" "alb_logs" {
  bucket        = aws_s3_bucket.alb_logs.id
  target_bucket = aws_s3_bucket.alb_logs_access.id
  target_prefix = "s3-access/${local.log_bucket_name}/"
}

# CKV2_AWS_61 + CKV_AWS_300: lifecycle configuration + abort multipart uploads
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

# ------------------------------------------------------------
# Allow ALB log delivery (service principal)
# ------------------------------------------------------------
data "aws_iam_policy_document" "alb_logs_bucket_policy" {
  statement {
    sid    = "AllowALBLogDelivery"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }

    actions = ["s3:PutObject"]

    resources = [
      "arn:aws:s3:::${aws_s3_bucket.alb_logs.bucket}/${var.alb_log_prefix}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
    ]
  }
  statement {
    sid    = "AllowS3ServerAccessLogsDelivery"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    actions = ["s3:PutObject"]

    resources = [
      "arn:aws:s3:::${aws_s3_bucket.alb_logs.bucket}/s3-access/${var.name_prefix}/*"
    ]

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

# ------------------------------------------------------------
# KMS CMK for SQS (to satisfy CKV2_AWS_73 / tfsec CMK guidance)
# ------------------------------------------------------------
resource "aws_kms_key" "sqs_sse" {
  description             = "CMK for SQS encryption (${var.name_prefix})"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EnableRootPermissions"
        Effect   = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid      = "AllowSQSUseOfTheKey"
        Effect   = "Allow"
        Principal = {
          Service = "sqs.amazonaws.com"
        }
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
}

resource "aws_kms_alias" "sqs_sse" {
  name          = "alias/${var.name_prefix}-sqs-cmk"
  target_key_id = aws_kms_key.sqs_sse.key_id
}


# ------------------------------------------------------------
# CKV2_AWS_62: S3 event notifications enabled (SQS)
# Also satisfies CKV_AWS_27: SQS encryption.
# ------------------------------------------------------------
resource "aws_sqs_queue" "alb_logs_events" {
  name              = "${var.name_prefix}-alb-logs-events"
  kms_master_key_id = aws_kms_key.sqs_sse.arn

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-alb-logs-events"
  })
}

# Allow both buckets to send events to the same SQS queue
data "aws_iam_policy_document" "alb_logs_events_queue_policy" {
  statement {
    sid    = "AllowS3SendMessageFromAlbLogsBucket"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.alb_logs_events.arn]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.alb_logs.arn]
    }
  }

  statement {
    sid    = "AllowS3SendMessageFromAlbLogsAccessBucket"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.alb_logs_events.arn]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.alb_logs_access.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "alb_logs_events" {
  queue_url = aws_sqs_queue.alb_logs_events.id
  policy    = data.aws_iam_policy_document.alb_logs_events_queue_policy.json
}

# Notifications for MAIN ALB logs bucket
resource "aws_s3_bucket_notification" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  queue {
    queue_arn     = aws_sqs_queue.alb_logs_events.arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = "${var.alb_log_prefix}/"
  }

  depends_on = [aws_sqs_queue_policy.alb_logs_events]
}

# Notifications for ACCESS bucket (log-of-logs)  ✅ This fixes CKV2_AWS_62 for alb_logs_access
resource "aws_s3_bucket_notification" "alb_logs_access" {
  bucket = aws_s3_bucket.alb_logs_access.id

  queue {
    queue_arn = aws_sqs_queue.alb_logs_events.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sqs_queue_policy.alb_logs_events]
}

# ------------------------------------------------------------
# KMS key for CloudWatch Log Groups (ECS logs + VPC Flow Logs)
# ------------------------------------------------------------
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
        Sid    = "AllowCloudWatchLogsUse"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.id}.amazonaws.com"
        }
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

  tags = merge(var.tags, { Name = "${var.name_prefix}-cw-logs-kms" })
}

resource "aws_kms_alias" "cloudwatch_logs" {
  name          = "alias/${var.name_prefix}-cw-logs"
  target_key_id = aws_kms_key.cloudwatch_logs.key_id
}
