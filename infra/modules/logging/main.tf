data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  log_bucket_name        = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-alb-logs"
  log_access_bucket_name = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-alb-logs-access"
  replica_bucket_name    = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-alb-logs-replica"
}

# ------------------------------------------------------------
# KMS CMK for ALB Logs bucket (source region)
# ------------------------------------------------------------
resource "aws_kms_key" "alb_logs" {
  description             = "CMK for ALB logs bucket (${var.name_prefix})"
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
# Access-logging target bucket ("log of logs") to satisfy CKV_AWS_18
# ------------------------------------------------------------
resource "aws_s3_bucket" "alb_logs_access" {
  bucket        = local.log_access_bucket_name
  force_destroy = false

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

# ------------------------------------------------------------
# Main ALB Logs bucket
# ------------------------------------------------------------
resource "aws_s3_bucket" "alb_logs" {
  bucket        = local.log_bucket_name
  force_destroy = false

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
  versioning_configuration { status = "Enabled" }
}

# CKV_AWS_145: default encryption with CMK
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

# CKV2_AWS_61: lifecycle configuration
resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

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
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = data.aws_iam_policy_document.alb_logs_bucket_policy.json
}

# ------------------------------------------------------------
# CKV2_AWS_62: S3 event notifications enabled (SQS)
# ------------------------------------------------------------
resource "aws_sqs_queue" "alb_logs_events" {
  name = "${var.name_prefix}-alb-logs-events"

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-alb-logs-events"
  })
}

data "aws_iam_policy_document" "alb_logs_events_queue_policy" {
  statement {
    sid    = "AllowS3SendMessage"
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
}

resource "aws_sqs_queue_policy" "alb_logs_events" {
  queue_url = aws_sqs_queue.alb_logs_events.id
  policy    = data.aws_iam_policy_document.alb_logs_events_queue_policy.json
}

resource "aws_s3_bucket_notification" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  queue {
    queue_arn     = aws_sqs_queue.alb_logs_events.arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = "${var.alb_log_prefix}/"
  }

  depends_on = [aws_sqs_queue_policy.alb_logs_events]
}

# ------------------------------------------------------------
# CKV_AWS_144: Cross-region replication (optional but "fix all")
# Requires a second provider alias: aws.replica
# ------------------------------------------------------------
resource "aws_kms_key" "alb_logs_replica" {
  provider                = aws.replica
  description             = "CMK for replicated ALB logs bucket (${var.name_prefix})"
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

  tags = merge(var.tags, { Name = "${var.name_prefix}-alb-logs-replica-kms" })
}

resource "aws_s3_bucket" "alb_logs_replica" {
  provider      = aws.replica
  bucket        = local.replica_bucket_name
  force_destroy = false

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-alb-logs-replica"
  })
}

resource "aws_s3_bucket_public_access_block" "alb_logs_replica" {
  provider                = aws.replica
  bucket                  = aws_s3_bucket.alb_logs_replica.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "alb_logs_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.alb_logs_replica.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.alb_logs_replica.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.alb_logs_replica.arn
    }
  }
}

# Replication role
data "aws_iam_policy_document" "replication_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "replication" {
  name               = "${var.name_prefix}-s3-replication"
  assume_role_policy = data.aws_iam_policy_document.replication_assume_role.json
  tags               = var.tags
}

data "aws_iam_policy_document" "replication_policy" {
  # Read from source bucket
  statement {
    effect = "Allow"
    actions = [
      "s3:GetReplicationConfiguration",
      "s3:ListBucket"
    ]
    resources = [aws_s3_bucket.alb_logs.arn]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionTagging",
      "s3:GetObjectRetention",
      "s3:GetObjectLegalHold"
    ]
    resources = ["${aws_s3_bucket.alb_logs.arn}/*"]
  }

  # Write to destination bucket
  statement {
    effect = "Allow"
    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
      "s3:ObjectOwnerOverrideToBucketOwner"
    ]
    resources = ["${aws_s3_bucket.alb_logs_replica.arn}/*"]
  }

  # KMS use (source + replica)
  statement {
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = [
      aws_kms_key.alb_logs.arn,
      aws_kms_key.alb_logs_replica.arn
    ]
  }
}

resource "aws_iam_role_policy" "replication" {
  name   = "${var.name_prefix}-s3-replication-policy"
  role   = aws_iam_role.replication.id
  policy = data.aws_iam_policy_document.replication_policy.json
}

resource "aws_s3_bucket_replication_configuration" "alb_logs" {
  count  = var.replication_enabled ? 1 : 0
  bucket = aws_s3_bucket.alb_logs.id
  role   = aws_iam_role.replication.arn

  rule {
    id     = "replicate-all"
    status = "Enabled"

    filter { prefix = "" }

    destination {
      bucket        = aws_s3_bucket.alb_logs_replica.arn
      storage_class = "STANDARD"

      encryption_configuration {
        replica_kms_key_id = aws_kms_key.alb_logs_replica.arn
      }
    }

    delete_marker_replication {
      status = "Enabled"
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.alb_logs,
    aws_s3_bucket_versioning.alb_logs_replica
  ]
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
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
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
