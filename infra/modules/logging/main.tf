data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.id

  # S3 buckets (names must be globally unique)
  alb_logs_bucket_name           = "${var.name_prefix}-alb-logs-${local.account_id}"
  server_access_logs_bucket_name = "${var.name_prefix}-s3-server-access-logs-${local.account_id}"
  ultimate_sink_bucket_name      = "${var.name_prefix}-s3-ultimate-sink-${local.account_id}"

  # Standard ELB access log delivery prefix used by AWS
  alb_log_objects_prefix = "AWSLogs/${local.account_id}/"
}

# -----------------------------------------------------------
# KMS keys
# -----------------------------------------------------------

resource "aws_kms_key" "alb_logs" {
  description             = "KMS key used for S3 server access logs / sink buckets (SSE-KMS)"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Root admin
      {
        Sid       = "EnableRootPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },

      # Allow S3 to use the key (SSE-KMS for buckets in this account)
      {
        Sid       = "AllowS3UseForBuckets"
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
            "aws:SourceAccount" = local.account_id,
            "kms:ViaService"    = "s3.${local.region}.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, { Name = "${var.name_prefix}-s3-logs-kms" })
}

resource "aws_kms_alias" "alb_logs" {
  name          = "alias/${var.name_prefix}-alb-logs"
  target_key_id = aws_kms_key.alb_logs.key_id
}

resource "aws_kms_key" "cloudwatch_logs" {
  description             = "KMS key for CloudWatch Logs encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  # CloudWatch Logs must be allowed to use the key in this region.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Root admin
      {
        Sid       = "EnableRootPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },

      # Allow CloudWatch Logs service in this region to use the key
      {
        Sid       = "AllowCloudWatchLogsUse"
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
# S3 Buckets
# Goal: pass Week-3 scanners + OPA checks with minimal, real logging infra.
#
# Buckets:
# 1) alb_logs: destination for ALB access logs (used by ecs module)
# 2) server_access_logs: destination for S3 server access logs for alb_logs
# 3) ultimate_sink: destination for S3 server access logs for server_access_logs
#
# NOTE: We intentionally STOP the chain at ultimate_sink to avoid infinite logging loops.
# We document and skip the "bucket access logging enabled" scanner check for ultimate_sink.
# ------------------------------------------------------------

#checkov:skip=CKV_AWS_18:Ultimate sink bucket is the terminal target for S3 server access logs to avoid infinite log loops.
resource "aws_s3_bucket" "ultimate_sink" {
  bucket        = local.ultimate_sink_bucket_name
  force_destroy = true

  tags = merge(var.tags, {
    Name = local.ultimate_sink_bucket_name
    Role = "logging-sink"
  })
}

resource "aws_s3_bucket_public_access_block" "ultimate_sink" {
  bucket                  = aws_s3_bucket.ultimate_sink.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "ultimate_sink" {
  bucket = aws_s3_bucket.ultimate_sink.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "ultimate_sink" {
  bucket = aws_s3_bucket.ultimate_sink.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ultimate_sink" {
  bucket = aws_s3_bucket.ultimate_sink.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.alb_logs.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "ultimate_sink_https" {
  bucket = aws_s3_bucket.ultimate_sink.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.ultimate_sink.arn,
          "${aws_s3_bucket.ultimate_sink.arn}/*"
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.ultimate_sink, aws_s3_bucket_ownership_controls.ultimate_sink]
}

resource "aws_s3_bucket_lifecycle_configuration" "ultimate_sink" {
  bucket = aws_s3_bucket.ultimate_sink.id

  rule {
    id     = "lifecycle"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload { days_after_initiation = 7 }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }

    expiration { days = var.lifecycle_expire_days }
  }
}

# ---- server_access_logs bucket (logs access to alb_logs bucket) ----

resource "aws_s3_bucket" "server_access_logs" {
  bucket        = local.server_access_logs_bucket_name
  force_destroy = true

  tags = merge(var.tags, {
    Name = local.server_access_logs_bucket_name
    Role = "s3-server-access-logs"
  })
}

resource "aws_s3_bucket_public_access_block" "server_access_logs" {
  bucket                  = aws_s3_bucket.server_access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "server_access_logs" {
  bucket = aws_s3_bucket.server_access_logs.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "server_access_logs" {
  bucket = aws_s3_bucket.server_access_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "server_access_logs" {
  bucket = aws_s3_bucket.server_access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.alb_logs.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "server_access_logs_https" {
  bucket = aws_s3_bucket.server_access_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.server_access_logs.arn,
          "${aws_s3_bucket.server_access_logs.arn}/*"
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.server_access_logs, aws_s3_bucket_ownership_controls.server_access_logs]
}

resource "aws_s3_bucket_lifecycle_configuration" "server_access_logs" {
  bucket = aws_s3_bucket.server_access_logs.id

  rule {
    id     = "lifecycle"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload { days_after_initiation = 7 }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }

    expiration { days = var.lifecycle_expire_days }
  }
}

# Enable S3 server access logging for server_access_logs -> ultimate_sink
resource "aws_s3_bucket_logging" "server_access_logs" {
  bucket        = aws_s3_bucket.server_access_logs.id
  target_bucket = aws_s3_bucket.ultimate_sink.id
  target_prefix = "server-access-logs/"

  depends_on = [
    aws_s3_bucket_policy.ultimate_sink_https,
    aws_s3_bucket_ownership_controls.server_access_logs,
    aws_s3_bucket_ownership_controls.ultimate_sink
  ]
}

# ---- alb_logs bucket (destination for ALB access logs) ----
# checkov:skip=CKV_AWS_145: ALB access log destination bucket must use SSE-S3 (AES256); SSE-KMS breaks ALB log delivery (AccessDenied).
resource "aws_s3_bucket" "alb_logs" {
  # checkov:skip=CKV_AWS_145: see above; ALB log delivery requires SSE-S3.
  bucket        = local.alb_logs_bucket_name
  force_destroy = true

  tags = merge(var.tags, {
    Name = local.alb_logs_bucket_name
    Role = "alb-access-logs"
  })
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ✅ Pass CKV2_AWS_65: disable ACLs.
resource "aws_s3_bucket_ownership_controls" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  versioning_configuration { status = "Enabled" }
}

# Default encryption for the ALB access logs bucket (SSE-KMS).
# This is required to pass CKV_AWS_145 (KMS by default) while keeping the bucket private and HTTPS-only.
# Default encryption for the ALB access logs bucket.
#checkov:skip=CKV_AWS_145:ALB access logs support only SSE-S3 (AWS docs). Using SSE-S3 avoids log delivery failures while bucket remains private and HTTPS-only.
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
# Deny HTTP (must use HTTPS) + allow ALB access log delivery (new policy)
resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Force HTTPS
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.alb_logs.arn,
          "${aws_s3_bucket.alb_logs.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },

      # Allow ELB log delivery service to write logs.
      # Resource includes the AWSLogs/<account-id>/ prefix (and optionally an extra prefix before it).
      {
        Sid       = "AllowALBLogDeliveryWrite"
        Effect    = "Allow"
        Principal = { Service = "logdelivery.elasticloadbalancing.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource = [
          "${aws_s3_bucket.alb_logs.arn}/${local.alb_log_objects_prefix}*",
          "${aws_s3_bucket.alb_logs.arn}/*/${local.alb_log_objects_prefix}*"
        ]
      }

      ,
      {
        Sid       = "AllowALBLogDeliveryAclCheck"
        Effect    = "Allow"
        Principal = { Service = "logdelivery.elasticloadbalancing.amazonaws.com" }
        Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource  = aws_s3_bucket.alb_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      }
    ]
  })

  depends_on = [
    aws_s3_bucket_public_access_block.alb_logs,
    aws_s3_bucket_ownership_controls.alb_logs
  ]
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "lifecycle"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload { days_after_initiation = 7 }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }

    expiration { days = var.lifecycle_expire_days }
  }
}

# Enable S3 server access logging for alb_logs -> server_access_logs
resource "aws_s3_bucket_logging" "alb_logs" {
  bucket        = aws_s3_bucket.alb_logs.id
  target_bucket = aws_s3_bucket.server_access_logs.id
  target_prefix = "alb-logs/"

  depends_on = [
    aws_s3_bucket_policy.server_access_logs_https,
    aws_s3_bucket_ownership_controls.alb_logs,
    aws_s3_bucket_ownership_controls.server_access_logs
  ]
}
