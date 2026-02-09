data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.id

  # ALB log buckets
  log_bucket_name              = "${var.name_prefix}-alb-logs-${local.account_id}"
  log_access_bucket_name       = "${var.name_prefix}-alb-logs-access-${local.account_id}"
  log_audit_bucket_name        = "${var.name_prefix}-alb-audit-logs-${local.account_id}"
  log_audit_access_bucket_name = "${var.name_prefix}-alb-audit-logs-access-${local.account_id}"

  # Access audit buckets
  access_audit_bucket_name      = "${var.name_prefix}-alb-access-audit-${local.account_id}"
  access_audit_sink_bucket_name = "${var.name_prefix}-alb-access-audit-sink-${local.account_id}"

  # "final sink" (as you designed)
  final_sink_bucket_name = "${var.name_prefix}-alb-final-sink-${local.account_id}"

  # PRODUCTION-GRADE FIX:
  # Dedicated buckets for S3 server access logging (avoid source==target logging)
  server_access_logs_bucket_name = "${var.name_prefix}-s3-server-access-logs-${local.account_id}"
  ultimate_sink_bucket_name      = "${var.name_prefix}-s3-ultimate-sink-${local.account_id}"

  # ALB access log object prefix pattern
  alb_log_key_prefix = var.alb_log_prefix != "" ? "${var.alb_log_prefix}/AWSLogs/${local.account_id}/*" : "AWSLogs/${local.account_id}/*"

  # Used for ownership controls loop (bucket names)
  log_buckets = {
    ultimate_sink         = local.ultimate_sink_bucket_name
    server_access_logs    = local.server_access_logs_bucket_name
    final_sink            = local.final_sink_bucket_name
    access_audit_sink     = local.access_audit_sink_bucket_name
    access_audit          = local.access_audit_bucket_name
    alb_logs_access       = local.log_access_bucket_name
    alb_logs              = local.log_bucket_name
    alb_logs_audit        = local.log_audit_bucket_name
    alb_logs_audit_access = local.log_audit_access_bucket_name
  }
}

# ------------------------------------------------------------
# KMS keys
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
        Sid       = "AllowCloudWatchLogs"
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
      }
    ]
  })

  tags = merge(var.tags, { Name = "${var.name_prefix}-cloudwatch-logs-kms" })
}

resource "aws_kms_alias" "cloudwatch_logs" {
  name          = "alias/${var.name_prefix}-cloudwatch-logs"
  target_key_id = aws_kms_key.cloudwatch_logs.key_id
}

# SNS encryption KMS (tfsec aws-sns-enable-topic-encryption + Checkov CKV_AWS_26)
resource "aws_kms_key" "sns" {
  description             = "KMS key for SNS topic encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  # IMPORTANT: SNS needs Encrypt as well (S3 notification validation can fail without it)
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
        Sid       = "AllowSNSUseOfKey"
        Effect    = "Allow"
        Principal = { Service = "sns.amazonaws.com" }
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

  tags = merge(var.tags, { Name = "${var.name_prefix}-sns-kms" })
}

resource "aws_kms_alias" "sns" {
  name          = "alias/${var.name_prefix}-sns"
  target_key_id = aws_kms_key.sns.key_id
}

# ------------------------------------------------------------
# SNS topic for S3 notifications (encrypted)
# ------------------------------------------------------------
resource "aws_sns_topic" "s3_events" {
  name              = "${var.name_prefix}-s3-events"
  kms_master_key_id = aws_kms_key.sns.arn
  tags              = merge(var.tags, { Name = "${var.name_prefix}-s3-events" })
}

# ------------------------------------------------------------
# Buckets
# ------------------------------------------------------------
resource "aws_s3_bucket" "ultimate_sink" {
  bucket        = local.ultimate_sink_bucket_name
  force_destroy = true
  tags          = merge(var.tags, { Name = local.ultimate_sink_bucket_name })
}

resource "aws_s3_bucket" "server_access_logs" {
  bucket        = local.server_access_logs_bucket_name
  force_destroy = true
  tags          = merge(var.tags, { Name = local.server_access_logs_bucket_name })
}

resource "aws_s3_bucket" "final_sink" {
  bucket        = local.final_sink_bucket_name
  force_destroy = true
  tags          = merge(var.tags, { Name = local.final_sink_bucket_name })
}

resource "aws_s3_bucket" "access_audit_sink" {
  bucket        = local.access_audit_sink_bucket_name
  force_destroy = true
  tags          = merge(var.tags, { Name = local.access_audit_sink_bucket_name })
}

resource "aws_s3_bucket" "access_audit" {
  bucket        = local.access_audit_bucket_name
  force_destroy = true
  tags          = merge(var.tags, { Name = local.access_audit_bucket_name })
}

resource "aws_s3_bucket" "alb_logs_access" {
  bucket        = local.log_access_bucket_name
  force_destroy = true
  tags          = merge(var.tags, { Name = local.log_access_bucket_name })
}

# checkov:skip=CKV_AWS_145: ALB access log destination bucket must use SSE-S3 (AES256); SSE-KMS breaks ALB log delivery.
resource "aws_s3_bucket" "alb_logs" {
  bucket        = local.log_bucket_name
  force_destroy = true
  tags          = merge(var.tags, { Name = local.log_bucket_name })
}

resource "aws_s3_bucket" "alb_logs_audit" {
  bucket        = local.log_audit_bucket_name
  force_destroy = true
  tags          = merge(var.tags, { Name = local.log_audit_bucket_name })
}

resource "aws_s3_bucket" "alb_logs_audit_access" {
  bucket        = local.log_audit_access_bucket_name
  force_destroy = true
  tags          = merge(var.tags, { Name = local.log_audit_access_bucket_name })
}

# ------------------------------------------------------------
# Public access blocks
# ------------------------------------------------------------
resource "aws_s3_bucket_public_access_block" "ultimate_sink" {
  bucket                  = aws_s3_bucket.ultimate_sink.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "server_access_logs" {
  bucket                  = aws_s3_bucket.server_access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "final_sink" {
  bucket                  = aws_s3_bucket.final_sink.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "access_audit_sink" {
  bucket                  = aws_s3_bucket.access_audit_sink.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "access_audit" {
  bucket                  = aws_s3_bucket.access_audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "alb_logs_access" {
  bucket                  = aws_s3_bucket.alb_logs_access.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "alb_logs_audit" {
  bucket                  = aws_s3_bucket.alb_logs_audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "alb_logs_audit_access" {
  bucket                  = aws_s3_bucket.alb_logs_audit_access.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ------------------------------------------------------------
# Ownership controls (disable ACLs)
# ------------------------------------------------------------
resource "aws_s3_bucket_ownership_controls" "log_buckets" {
  for_each = local.log_buckets
  bucket   = each.value

  # Ensure buckets exist before applying ownership controls (prevents NoSuchBucket race)
  depends_on = [
    aws_s3_bucket.ultimate_sink,
    aws_s3_bucket.server_access_logs,
    aws_s3_bucket.final_sink,
    aws_s3_bucket.access_audit_sink,
    aws_s3_bucket.access_audit,
    aws_s3_bucket.alb_logs_access,
    aws_s3_bucket.alb_logs,
    aws_s3_bucket.alb_logs_audit,
    aws_s3_bucket.alb_logs_audit_access
  ]

  rule {
    object_ownership = each.key == "alb_logs" ? "BucketOwnerPreferred" : "BucketOwnerEnforced"
  }
}

# ------------------------------------------------------------
# Versioning
# ------------------------------------------------------------
resource "aws_s3_bucket_versioning" "ultimate_sink" {
  bucket = aws_s3_bucket.ultimate_sink.id
  versioning_configuration { status = "Enabled" }
  depends_on = [aws_s3_bucket_ownership_controls.log_buckets]
}

resource "aws_s3_bucket_versioning" "server_access_logs" {
  bucket = aws_s3_bucket.server_access_logs.id
  versioning_configuration { status = "Enabled" }
  depends_on = [aws_s3_bucket_ownership_controls.log_buckets]
}

resource "aws_s3_bucket_versioning" "final_sink" {
  bucket = aws_s3_bucket.final_sink.id
  versioning_configuration { status = "Enabled" }
  depends_on = [aws_s3_bucket_ownership_controls.log_buckets]
}

resource "aws_s3_bucket_versioning" "access_audit_sink" {
  bucket = aws_s3_bucket.access_audit_sink.id
  versioning_configuration { status = "Enabled" }
  depends_on = [aws_s3_bucket_ownership_controls.log_buckets]
}

resource "aws_s3_bucket_versioning" "access_audit" {
  bucket = aws_s3_bucket.access_audit.id
  versioning_configuration { status = "Enabled" }
  depends_on = [aws_s3_bucket_ownership_controls.log_buckets]
}

resource "aws_s3_bucket_versioning" "alb_logs_access" {
  bucket = aws_s3_bucket.alb_logs_access.id
  versioning_configuration { status = "Enabled" }
  depends_on = [aws_s3_bucket_ownership_controls.log_buckets]
}

resource "aws_s3_bucket_versioning" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  versioning_configuration { status = "Enabled" }
  depends_on = [aws_s3_bucket_ownership_controls.log_buckets]
}

resource "aws_s3_bucket_versioning" "alb_logs_audit" {
  bucket = aws_s3_bucket.alb_logs_audit.id
  versioning_configuration { status = "Enabled" }
  depends_on = [aws_s3_bucket_ownership_controls.log_buckets]
}

resource "aws_s3_bucket_versioning" "alb_logs_audit_access" {
  bucket = aws_s3_bucket.alb_logs_audit_access.id
  versioning_configuration { status = "Enabled" }
  depends_on = [aws_s3_bucket_ownership_controls.log_buckets]
}

# ------------------------------------------------------------
# SSE-KMS
# ------------------------------------------------------------
resource "aws_s3_bucket_server_side_encryption_configuration" "ultimate_sink" {
  bucket = aws_s3_bucket.ultimate_sink.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.alb_logs.arn
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "server_access_logs" {
  bucket = aws_s3_bucket.server_access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.alb_logs.arn
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "final_sink" {
  bucket = aws_s3_bucket.final_sink.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.alb_logs.arn
    }
  }
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

resource "aws_s3_bucket_server_side_encryption_configuration" "access_audit" {
  bucket = aws_s3_bucket.access_audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.alb_logs.arn
    }
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

# trivy:ignore:AWS-0132
# Reason: ALB access logs delivery to S3 does not support SSE-KMS (CMK) encryption.
# Using SSE-KMS causes log delivery to fail with "Access Denied for bucket ...".
# For the ALB logs *destination* bucket, SSE-S3 (AES256) is the supported option.
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
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

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs_audit_access" {
  bucket = aws_s3_bucket.alb_logs_audit_access.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.alb_logs.arn
    }
  }
}

# ------------------------------------------------------------
# Lifecycle (CKV2_AWS_61)
# ------------------------------------------------------------
resource "aws_s3_bucket_lifecycle_configuration" "ultimate_sink" {
  bucket = aws_s3_bucket.ultimate_sink.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    abort_incomplete_multipart_upload { days_after_initiation = 7 }

    expiration { days = var.lifecycle_expire_days }

    noncurrent_version_expiration { noncurrent_days = var.lifecycle_expire_days }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "server_access_logs" {
  bucket = aws_s3_bucket.server_access_logs.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    abort_incomplete_multipart_upload { days_after_initiation = 7 }

    expiration { days = var.lifecycle_expire_days }

    noncurrent_version_expiration { noncurrent_days = var.lifecycle_expire_days }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "final_sink" {
  bucket = aws_s3_bucket.final_sink.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    abort_incomplete_multipart_upload { days_after_initiation = 7 }

    expiration { days = var.lifecycle_expire_days }

    noncurrent_version_expiration { noncurrent_days = var.lifecycle_expire_days }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_audit_sink" {
  bucket = aws_s3_bucket.access_audit_sink.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    abort_incomplete_multipart_upload { days_after_initiation = 7 }

    expiration { days = var.lifecycle_expire_days }

    noncurrent_version_expiration { noncurrent_days = var.lifecycle_expire_days }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_audit" {
  bucket = aws_s3_bucket.access_audit.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    abort_incomplete_multipart_upload { days_after_initiation = 7 }

    expiration { days = var.lifecycle_expire_days }

    noncurrent_version_expiration { noncurrent_days = var.lifecycle_expire_days }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs_access" {
  bucket = aws_s3_bucket.alb_logs_access.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    abort_incomplete_multipart_upload { days_after_initiation = 7 }

    expiration { days = var.lifecycle_expire_days }

    noncurrent_version_expiration { noncurrent_days = var.lifecycle_expire_days }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    abort_incomplete_multipart_upload { days_after_initiation = 7 }

    expiration { days = var.lifecycle_expire_days }

    noncurrent_version_expiration { noncurrent_days = var.lifecycle_expire_days }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs_audit" {
  bucket = aws_s3_bucket.alb_logs_audit.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    abort_incomplete_multipart_upload { days_after_initiation = 7 }

    expiration { days = var.lifecycle_expire_days }

    noncurrent_version_expiration { noncurrent_days = var.lifecycle_expire_days }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs_audit_access" {
  bucket = aws_s3_bucket.alb_logs_audit_access.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter { prefix = "" }

    abort_incomplete_multipart_upload { days_after_initiation = 7 }

    expiration { days = var.lifecycle_expire_days }

    noncurrent_version_expiration { noncurrent_days = var.lifecycle_expire_days }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

# ------------------------------------------------------------
# Logging chain (tfsec aws-s3-enable-bucket-logging)
# PRODUCTION-GRADE: no bucket logs to itself
# ------------------------------------------------------------
# server_access_logs -> ultimate_sink
resource "aws_s3_bucket_logging" "server_access_logs" {
  bucket        = aws_s3_bucket.server_access_logs.id
  target_bucket = aws_s3_bucket.ultimate_sink.id
  target_prefix = "${var.alb_log_prefix}/server-access-logs/"
}

# final_sink -> server_access_logs
resource "aws_s3_bucket_logging" "final_sink" {
  bucket        = aws_s3_bucket.final_sink.id
  target_bucket = aws_s3_bucket.server_access_logs.id
  target_prefix = "${var.alb_log_prefix}/final-sink/"
}

# access_audit_sink -> final_sink
resource "aws_s3_bucket_logging" "access_audit_sink" {
  bucket        = aws_s3_bucket.access_audit_sink.id
  target_bucket = aws_s3_bucket.final_sink.id
  target_prefix = "${var.alb_log_prefix}/access-audit-sink/"
}

# access_audit -> access_audit_sink
resource "aws_s3_bucket_logging" "access_audit" {
  bucket        = aws_s3_bucket.access_audit.id
  target_bucket = aws_s3_bucket.access_audit_sink.id
  target_prefix = "${var.alb_log_prefix}/access-audit/"
}

# alb_logs_access -> access_audit
resource "aws_s3_bucket_logging" "alb_logs_access" {
  bucket        = aws_s3_bucket.alb_logs_access.id
  target_bucket = aws_s3_bucket.access_audit.id
  target_prefix = "${var.alb_log_prefix}/access-bucket/"
}

# alb_logs -> alb_logs_access
resource "aws_s3_bucket_logging" "alb_logs" {
  bucket        = aws_s3_bucket.alb_logs.id
  target_bucket = aws_s3_bucket.alb_logs_access.id
  target_prefix = "${var.alb_log_prefix}/"
}

# alb_logs_audit -> alb_logs_audit_access
resource "aws_s3_bucket_logging" "alb_logs_audit" {
  bucket        = aws_s3_bucket.alb_logs_audit.id
  target_bucket = aws_s3_bucket.alb_logs_audit_access.id
  target_prefix = "${var.alb_log_prefix}/audit/"
}

# alb_logs_audit_access -> access_audit
resource "aws_s3_bucket_logging" "alb_logs_audit_access" {
  bucket        = aws_s3_bucket.alb_logs_audit_access.id
  target_bucket = aws_s3_bucket.access_audit.id
  target_prefix = "${var.alb_log_prefix}/audit-access/"
}

# ------------------------------------------------------------
# ALB log delivery bucket policy (no ACL condition, ACLs disabled)
# ------------------------------------------------------------
data "aws_iam_policy_document" "alb_logs_bucket_policy" {
  statement {
    sid       = "AWSLogDeliveryAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.alb_logs.arn]
    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }
  }

  statement {
    sid     = "AWSLogDeliveryWrite"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.alb_logs.arn}/${local.alb_log_key_prefix}"
    ]
    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }

    # ALB log delivery writes objects with this ACL so the bucket owner owns the logs.
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = data.aws_iam_policy_document.alb_logs_bucket_policy.json
}

# ------------------------------------------------------------
# SNS Topic Policy (FIX for S3 notification validation)
# - Requires aws:SourceArn for each bucket that will publish
# ------------------------------------------------------------
data "aws_iam_policy_document" "sns_topic_policy" {
  statement {
    sid       = "AllowS3PublishFromLogBuckets"
    effect    = "Allow"
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.s3_events.arn]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values = [
        aws_s3_bucket.ultimate_sink.arn,
        aws_s3_bucket.server_access_logs.arn,
        aws_s3_bucket.final_sink.arn,
        aws_s3_bucket.access_audit_sink.arn,
        aws_s3_bucket.access_audit.arn,
        aws_s3_bucket.alb_logs_access.arn,
        aws_s3_bucket.alb_logs.arn,
        aws_s3_bucket.alb_logs_audit.arn,
        aws_s3_bucket.alb_logs_audit_access.arn
      ]
    }
  }
}

resource "aws_sns_topic_policy" "s3_events" {
  arn    = aws_sns_topic.s3_events.arn
  policy = data.aws_iam_policy_document.sns_topic_policy.json
}

# ------------------------------------------------------------
# Bucket Notifications (Checkov CKV2_AWS_62)
# IMPORTANT: depends_on ensures topic policy exists before S3 validates destination
# ------------------------------------------------------------
resource "aws_s3_bucket_notification" "ultimate_sink" {
  bucket = aws_s3_bucket.ultimate_sink.id

  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic_policy.s3_events]
}

resource "aws_s3_bucket_notification" "server_access_logs" {
  bucket = aws_s3_bucket.server_access_logs.id

  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic_policy.s3_events]
}

resource "aws_s3_bucket_notification" "final_sink" {
  bucket = aws_s3_bucket.final_sink.id

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

resource "aws_s3_bucket_notification" "access_audit" {
  bucket = aws_s3_bucket.access_audit.id

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

resource "aws_s3_bucket_notification" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

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