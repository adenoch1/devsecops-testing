data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  log_bucket_name        = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-alb-logs"
  log_access_bucket_name = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-alb-logs-access"
}

# -------------------------------------------------------------
# KMS CMK for ALB Logs bucket encryption (S3)
# IMPORTANT: allow S3/ELB log delivery to use the key (SSE-KMS)
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
      },

      # Allow S3 to use the CMK for objects in these buckets (SSE-KMS)
      {
        Sid       = "AllowS3UseOfTheKey"
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
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
            "kms:ViaService"    = "s3.${data.aws_region.current.id}.amazonaws.com"
          }
        }
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

# ✅ Correct: ALB logs bucket writes its SERVER ACCESS LOGS into access bucket
resource "aws_s3_bucket_logging" "alb_logs" {
  bucket        = aws_s3_bucket.alb_logs.id
  target_bucket = aws_s3_bucket.alb_logs_access.id
  target_prefix = "s3-access/${var.name_prefix}/"
}

# ------------------------------------------------------------
# Bucket policies
#   1) ALB log delivery -> alb_logs bucket
#   2) S3 server access logs delivery -> alb_logs_access bucket
# ------------------------------------------------------------

# ✅ ALB access logging policy (this fixes your Access Denied)
data "aws_iam_policy_document" "alb_logs_bucket_policy" {
  statement {
    sid    = "AllowELBLogDeliveryAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }

    actions = ["s3:GetBucketAcl"]
    resources = [
      aws_s3_bucket.alb_logs.arn
    ]
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
      # ALB will write to: <prefix>/AWSLogs/<account-id>/...
      "${aws_s3_bucket.alb_logs.arn}/${var.alb_log_prefix}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
    ]

    # Required by ELB log delivery
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    # Recommended safety
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

# ✅ S3 server access logs delivery policy MUST be on the TARGET bucket (alb_logs_access)
data "aws_iam_policy_document" "alb_logs_access_bucket_policy" {
  statement {
    sid    = "AllowS3ServerAccessLogsAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    actions = ["s3:GetBucketAcl"]
    resources = [
      aws_s3_bucket.alb_logs_access.arn
    ]
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

    # S3 access logs typically require this ACL
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs_access" {
  bucket = aws_s3_bucket.alb_logs_access.id
  policy = data.aws_iam_policy_document.alb_logs_access_bucket_policy.json
}

# -----------------------------------------------------------
# KMS CMK for SQS encryption (required by CKV2_AWS_73)
# -----------------------------------------------------------
resource "aws_kms_key" "sqs_sse" {
  description             = "CMK for SQS encryption (${var.name_prefix})"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      {
        Sid    = "EnableRootPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },

      {
        Sid    = "AllowSQSUseOfTheKey"
        Effect = "Allow"
        Principal = {
          Service = "sqs.amazonaws.com"
        }
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
            "kms:ViaService"    = "sqs.${data.aws_region.current.id}.amazonaws.com"
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
          Bool = {
            "kms:GrantIsForAWSResource" = "true"
          }
        }
      },

      {
        Sid    = "AllowS3ToUseKeyViaSQS"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "sqs.${data.aws_region.current.id}.amazonaws.com"
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
# SQS queue for S3 event notifications (encrypted with CMK)
# ------------------------------------------------------------
resource "aws_sqs_queue" "alb_logs_events" {
  name              = "${var.name_prefix}-alb-logs-events"
  kms_master_key_id = aws_kms_key.sqs_sse.arn

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-alb-logs-events"
  })
}

data "aws_iam_policy_document" "alb_logs_events_queue_policy" {
  statement {
    sid    = "AllowS3UseQueueFromAlbLogsBucket"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions = [
      "sqs:SendMessage",
      "sqs:GetQueueAttributes"
    ]

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
    sid    = "AllowS3UseQueueFromAlbLogsAccessBucket"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions = [
      "sqs:SendMessage",
      "sqs:GetQueueAttributes"
    ]

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

resource "time_sleep" "wait_for_sqs_policy" {
  create_duration = "120s"
  depends_on = [
    aws_kms_alias.sqs_sse,
    aws_sqs_queue.alb_logs_events,
    aws_sqs_queue_policy.alb_logs_events
  ]
}

resource "aws_s3_bucket_notification" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  queue {
    queue_arn     = aws_sqs_queue.alb_logs_events.arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = "${var.alb_log_prefix}/"
  }

  depends_on = [time_sleep.wait_for_sqs_policy]
}

resource "aws_s3_bucket_notification" "alb_logs_access" {
  bucket = aws_s3_bucket.alb_logs_access.id

  queue {
    queue_arn = aws_sqs_queue.alb_logs_events.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [time_sleep.wait_for_sqs_policy]
}

# -----------------------------------------------------------
# KMS key for CloudWatch Log Groups
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
