data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  log_bucket_name        = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-alb-logs"
  log_access_bucket_name = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-alb-logs-access"
}

# -------------------------------------------------------------
# KMS (CMK) used for:
# - SQS queue encryption
# - CloudWatch Log Group encryption
# -------------------------------------------------------------
resource "aws_kms_key" "logs" {
  description             = "CMK for logging components (SQS + CloudWatch Logs)"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = data.aws_iam_policy_document.kms_key_policy.json

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-logs-kms"
  })
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${var.name_prefix}-logs"
  target_key_id = aws_kms_key.logs.key_id
}

# Note: Checkov often flags KMS key policies because they require Resource="*".
# We skip those checks at the workflow level (recommended).
data "aws_iam_policy_document" "kms_key_policy" {
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
    sid    = "AllowCloudWatchLogsUse"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]

    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.id}.amazonaws.com"]
    }

    resources = ["*"]
  }

  statement {
    sid    = "AllowS3Use"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    resources = ["*"]
  }

  statement {
    sid    = "AllowSQSUse"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]

    principals {
      type        = "Service"
      identifiers = ["sqs.amazonaws.com"]
    }

    resources = ["*"]
  }
}

# -------------------------------------------------------------
# S3 Bucket: ALB logs bucket (target)
# Inline encryption is used (policy-friendly for Conftest)
# -------------------------------------------------------------
#checkov:skip=CKV_AWS_144: "Cross-region replication intentionally disabled for this environment"
resource "aws_s3_bucket" "alb_logs" {
  bucket        = local.log_bucket_name
  force_destroy = false

  # ✅ INLINE encryption so Conftest sees it in the plan
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        # SSE-S3 is enough for your Conftest rule (SSE-S3 or SSE-KMS).
        sse_algorithm = "AES256"
      }
    }
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-alb-logs"
  })
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

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

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "log-lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }

    expiration {
      days = var.lifecycle_expire_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# -------------------------------------------------------------
# S3 Bucket: Access bucket (destination for server access logs)
# Inline encryption is used (policy-friendly for Conftest)
# -------------------------------------------------------------
#checkov:skip=CKV_AWS_144: "Cross-region replication intentionally disabled for this environment"
resource "aws_s3_bucket" "alb_logs_access" {
  bucket        = local.log_access_bucket_name
  force_destroy = false

  # ✅ INLINE encryption so Conftest sees it in the plan
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-alb-logs-access"
  })
}

resource "aws_s3_bucket_public_access_block" "alb_logs_access" {
  bucket = aws_s3_bucket.alb_logs_access.id

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

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs_access" {
  bucket = aws_s3_bucket.alb_logs_access.id

  rule {
    id     = "log-lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }

    expiration {
      days = var.lifecycle_expire_days
    }

    abort_incomplete_multipart_upload {
      days = var.lifecycle_expire_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# -------------------------------------------------------------
# Bucket logging (tfsec aws-s3-enable-bucket-logging)
# - alb_logs logs -> alb_logs_access
# - alb_logs_access logs -> alb_logs (so BOTH have logging enabled)
# -------------------------------------------------------------
resource "aws_s3_bucket_logging" "alb_logs" {
  bucket        = aws_s3_bucket.alb_logs.id
  target_bucket = aws_s3_bucket.alb_logs_access.id
  target_prefix = "s3-access/${var.name_prefix}/alb-logs/"
}

resource "aws_s3_bucket_logging" "alb_logs_access" {
  bucket        = aws_s3_bucket.alb_logs_access.id
  target_bucket = aws_s3_bucket.alb_logs.id
  target_prefix = "s3-access/${var.name_prefix}/alb-logs-access/"
}

# -------------------------------------------------------------
# ALB log delivery bucket policy (allows ALB to write logs)
# -------------------------------------------------------------
data "aws_elb_service_account" "this" {}

data "aws_iam_policy_document" "alb_logs_bucket_policy" {
  statement {
    sid     = "AWSALBAccessLogsWrite"
    effect  = "Allow"
    actions = ["s3:PutObject"]

    principals {
      type        = "AWS"
      identifiers = [data.aws_elb_service_account.this.arn]
    }

    resources = ["${aws_s3_bucket.alb_logs.arn}/*"]
  }

  statement {
    sid     = "AWSALBAccessLogsAclCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]

    principals {
      type        = "AWS"
      identifiers = [data.aws_elb_service_account.this.arn]
    }

    resources = [aws_s3_bucket.alb_logs.arn]
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = data.aws_iam_policy_document.alb_logs_bucket_policy.json
}

# -------------------------------------------------------------
# CloudWatch Log Group for VPC Flow Logs (encrypted with CMK)
# -------------------------------------------------------------
resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/aws/vpc/flowlogs/${var.name_prefix}"
  retention_in_days = var.flow_log_retention_days
  kms_key_id        = aws_kms_key.logs.arn

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-vpc-flow"
  })
}

# -------------------------------------------------------------
# SQS queue for S3 event notifications (Checkov CKV2_AWS_62)
# -------------------------------------------------------------
resource "aws_sqs_queue" "alb_logs_events" {
  name              = "${var.name_prefix}-alb-logs-events"
  kms_master_key_id = aws_kms_key.logs.arn

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-alb-logs-events"
  })
}

data "aws_iam_policy_document" "s3_to_sqs" {
  statement {
    sid    = "AllowS3SendMessage"
    effect = "Allow"

    actions = ["sqs:SendMessage"]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    resources = [aws_sqs_queue.alb_logs_events.arn]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values = [
        aws_s3_bucket.alb_logs.arn,
        aws_s3_bucket.alb_logs_access.arn
      ]
    }
  }
}

resource "aws_sqs_queue_policy" "alb_logs_events" {
  queue_url = aws_sqs_queue.alb_logs_events.id
  policy    = data.aws_iam_policy_document.s3_to_sqs.json
}

resource "aws_s3_bucket_notification" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  queue {
    queue_arn = aws_sqs_queue.alb_logs_events.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sqs_queue_policy.alb_logs_events]
}

resource "aws_s3_bucket_notification" "alb_logs_access" {
  bucket = aws_s3_bucket.alb_logs_access.id

  queue {
    queue_arn = aws_sqs_queue.alb_logs_events.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sqs_queue_policy.alb_logs_events]
}
