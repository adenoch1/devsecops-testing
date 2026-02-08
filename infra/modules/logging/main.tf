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
# ALB access log delivery policy (required for ALB access_logs)
# ------------------------------------------------------------
locals {
  # ALB writes keys like: <prefix>/AWSLogs/<account-id>/elasticloadbalancing/<region>/...
  alb_log_key_prefix = var.alb_log_prefix != "" ? "${var.alb_log_prefix}/AWSLogs/${local.account_id}/*" : "AWSLogs/${local.account_id}/*"
}

data "aws_iam_policy_document" "alb_logs_bucket_policy" {
  statement {
    sid     = "AWSLogDeliveryAclCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [
      aws_s3_bucket.alb_logs.arn
    ]
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
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
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

# ------------------------------------------------------------
# Access audit sink bucket (final sink)
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

# ------------------------------------------------------------
# Access audit bucket (logs the access-log buckets)
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

resource "aws_s3_bucket_logging" "access_audit" {
  bucket        = aws_s3_bucket.access_audit.id
  target_bucket = aws_s3_bucket.access_audit_sink.id
  target_prefix = "${var.alb_log_prefix}/access-audit/"
}

# ------------------------------------------------------------
# Access bucket for ALB logs bucket (S3 server access logs target)
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

# ----------------------------------------------------
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

resource "aws_s3_bucket_logging" "alb_logs_audit" {
  bucket        = aws_s3_bucket.alb_logs_audit.id
  target_bucket = aws_s3_bucket.alb_logs_audit_access.id
  target_prefix = "${var.alb_log_prefix}/audit/"
}

resource "aws_s3_bucket_logging" "alb_logs_audit_access" {
  bucket        = aws_s3_bucket.alb_logs_audit_access.id
  target_bucket = aws_s3_bucket.access_audit.id
  target_prefix = "${var.alb_log_prefix}/audit-access/"
}

# ------------------------------------------------------------
# Ownership + ACLs for log delivery (keeps ALB/S3 log delivery compatible)
# ------------------------------------------------------------
locals {
  log_buckets = {
    alb_logs              = aws_s3_bucket.alb_logs.id
    alb_logs_access       = aws_s3_bucket.alb_logs_access.id
    alb_logs_audit        = aws_s3_bucket.alb_logs_audit.id
    alb_logs_audit_access = aws_s3_bucket.alb_logs_audit_access.id
    access_audit          = aws_s3_bucket.access_audit.id
    access_audit_sink     = aws_s3_bucket.access_audit_sink.id
  }
}

resource "aws_s3_bucket_ownership_controls" "log_buckets" {
  for_each = local.log_buckets
  bucket   = each.value

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "log_buckets" {
  for_each = local.log_buckets
  bucket   = each.value
  acl      = "private"

  depends_on = [
    aws_s3_bucket_ownership_controls.log_buckets
  ]
}

# Bucket policy that allows the ALB service to write access logs
resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = data.aws_iam_policy_document.alb_logs_bucket_policy.json
}

# S3 Server Access Logging targets need permission for logging.s3.amazonaws.com
locals {
  s3_access_log_targets = {
    alb_logs_access = {
      id  = aws_s3_bucket.alb_logs_access.id
      arn = aws_s3_bucket.alb_logs_access.arn
    }
    alb_logs_audit_access = {
      id  = aws_s3_bucket.alb_logs_audit_access.id
      arn = aws_s3_bucket.alb_logs_audit_access.arn
    }
    access_audit = {
      id  = aws_s3_bucket.access_audit.id
      arn = aws_s3_bucket.access_audit.arn
    }
    access_audit_sink = {
      id  = aws_s3_bucket.access_audit_sink.id
      arn = aws_s3_bucket.access_audit_sink.arn
    }
  }
}

data "aws_iam_policy_document" "s3_access_log_target" {
  for_each = local.s3_access_log_targets

  statement {
    sid     = "S3ServerAccessLogsWrite"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "${each.value.arn}/*"
    ]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid     = "S3ServerAccessLogsAclCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    resources = [
      each.value.arn
    ]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
  }
}

resource "aws_s3_bucket_policy" "s3_access_log_target" {
  for_each = local.s3_access_log_targets

  bucket = each.value.id
  policy = data.aws_iam_policy_document.s3_access_log_target[each.key].json
}
