data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  log_bucket_name        = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-alb-logs"
  log_access_bucket_name = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-alb-logs-access"
}

# -------------------------------------------------------------
# KMS CMK for ALB Logs bucket encryption (S3)
# -------------------------------------------------------------
resource "aws_kms_key" "alb_logs" {
  description             = "CMK for ALB Logs bucket encryption (${var.name_prefix})"
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

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-alb-logs-cmk"
  })
}

resource "aws_kms_alias" "alb_logs" {
  name          = "alias/${var.name_prefix}-alb-logs-cmk"
  target_key_id = aws_kms_key.alb_logs.key_id
}

# -------------------------------------------------------------
# S3 bucket for ALB logs
# -------------------------------------------------------------
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

# ✅ CKV_AWS_300 fixed: add abort_incomplete_multipart_upload
resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "expire-alb-logs"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = var.flow_log_retention_days
    }
  }
}

resource "aws_s3_bucket_logging" "alb_logs" {
  bucket        = aws_s3_bucket.alb_logs.id
  target_bucket = aws_s3_bucket.alb_logs_access.id
  target_prefix = "s3-access/${var.name_prefix}/"
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

# -------------------------------------------------------------
# S3 bucket for S3 server access logs (for the ALB logs bucket)
# -------------------------------------------------------------
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

# ✅ CKV_AWS_300 fixed: add abort_incomplete_multipart_upload
resource "aws_s3_bucket_lifecycle_configuration" "alb_logs_access" {
  bucket = aws_s3_bucket.alb_logs_access.id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = var.flow_log_retention_days
    }
  }
}

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

# ------------------------------------------------------------
# S3 bucket policy (ALB log delivery + S3 access log delivery)
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
      "arn:aws:s3:::${aws_s3_bucket.alb_logs.id}/${var.alb_log_prefix}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
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
      "arn:aws:s3:::${aws_s3_bucket.alb_logs.id}/s3-access/${var.name_prefix}/*"
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
# KMS key for SQS encryption (used by S3 event notifications)
# ✅ FIX: add CreateGrant + ViaService + CallerAccount + GrantIsForAWSResource
# ------------------------------------------------------------
resource "aws_kms_key" "sqs_sse" {
  description             = "CMK for SQS encryption (${var.name_prefix})"
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
        Sid       = "AllowSQSUseOfTheKey"
        Effect    = "Allow"
        Principal = { Service = "sqs.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService"    = "sqs.${data.aws_region.current.name}.amazonaws.com",
            "kms:CallerAccount" = "${data.aws_caller_identity.current.account_id}"
          }
          Bool = {
            "kms:GrantIsForAWSResource" = "true"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-sqs-cmk"
  })
}

resource "aws_kms_alias" "sqs_sse" {
  name          = "alias/${var.name_prefix}-sqs-cmk"
  target_key_id = aws_kms_key.sqs_sse.key_id
}

# ------------------------------------------------------------
# SQS queue for S3 event notifications
# ------------------------------------------------------------
resource "aws_sqs_queue" "alb_logs_events" {
  name              = "${var.name_prefix}-alb-logs-events"
  kms_master_key_id = aws_kms_key.sqs_sse.arn

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-alb-logs-events"
  })
}

# ✅ FIX: add SourceAccount to both statements (helps validation + best practice)
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

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
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

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sqs_queue_policy" "alb_logs_events" {
  queue_url = aws_sqs_queue.alb_logs_events.id
  policy    = data.aws_iam_policy_document.alb_logs_events_queue_policy.json
}

# ------------------------------------------------------------
# S3 bucket notifications -> SQS
# ✅ FIX: depend on queue + policy + KMS alias to avoid eventual consistency
# ------------------------------------------------------------
resource "aws_s3_bucket_notification" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  queue {
    queue_arn     = aws_sqs_queue.alb_logs_events.arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = "${var.alb_log_prefix}/"
  }

  depends_on = [
    aws_kms_alias.sqs_sse,
    aws_sqs_queue.alb_logs_events,
    aws_sqs_queue_policy.alb_logs_events
  ]
}

resource "aws_s3_bucket_notification" "alb_logs_access" {
  bucket = aws_s3_bucket.alb_logs_access.id

  queue {
    queue_arn = aws_sqs_queue.alb_logs_events.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [
    aws_kms_alias.sqs_sse,
    aws_sqs_queue.alb_logs_events,
    aws_sqs_queue_policy.alb_logs_events
  ]
}

# ------------------------------------------------------------
# KMS key for CloudWatch Log Groups
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
        Sid       = "AllowCloudWatchLogsUseOfTheKey"
        Effect    = "Allow"
        Principal = { Service = "logs.${data.aws_region.current.name}.amazonaws.com" }
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

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-cloudwatch-logs-cmk"
  })
}

resource "aws_kms_alias" "cloudwatch_logs" {
  name          = "alias/${var.name_prefix}-cloudwatch-logs-cmk"
  target_key_id = aws_kms_key.cloudwatch_logs.key_id
}
