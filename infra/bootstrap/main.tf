data "aws_caller_identity" "current" {}

# -----------------------------
# KMS keys
# -----------------------------
resource "aws_kms_key" "tfstate" {
  description             = "KMS key for Terraform remote state encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = merge(var.tags, { Name = "tfstate-kms" })
}

data "aws_iam_policy_document" "tfstate_kms_policy" {
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
}

resource "aws_kms_key_policy" "tfstate" {
  key_id = aws_kms_key.tfstate.id
  policy = data.aws_iam_policy_document.tfstate_kms_policy.json
}

resource "aws_kms_key" "tflocks" {
  description             = "KMS key for Terraform DynamoDB locks encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = merge(var.tags, { Name = "tflocks-kms" })
}

data "aws_iam_policy_document" "tflocks_kms_policy" {
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
}

resource "aws_kms_key_policy" "tflocks" {
  key_id = aws_kms_key.tflocks.id
  policy = data.aws_iam_policy_document.tflocks_kms_policy.json
}

# -----------------------------
# KMS key for S3 access logs bucket (SSE-KMS)
# -----------------------------
data "aws_iam_policy_document" "tfstate_logs_kms_policy" {
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
    sid    = "AllowS3UseForAccessLogsBucket"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:s3:::${var.state_bucket_name}-logs"]
    }
  }
}

resource "aws_kms_key" "tfstate_logs" {
  description             = "KMS key for Terraform access logs bucket encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = merge(var.tags, { Name = "tfstate-logs-kms" })
}

resource "aws_kms_key_policy" "tfstate_logs" {
  key_id = aws_kms_key.tfstate_logs.id
  policy = data.aws_iam_policy_document.tfstate_logs_kms_policy.json
}

resource "aws_kms_alias" "tfstate_logs" {
  name          = "alias/${var.state_bucket_name}-logs"
  target_key_id = aws_kms_key.tfstate_logs.key_id
}

# -----------------------------
# KMS key for SNS topic encryption (at rest)
# -----------------------------
data "aws_iam_policy_document" "tfstate_events_kms_policy" {
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
    sid    = "AllowSNSServiceUse"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_kms_key" "tfstate_events" {
  description             = "KMS key for Terraform state event SNS topic encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = merge(var.tags, { Name = "tfstate-events-kms" })
}

resource "aws_kms_key_policy" "tfstate_events" {
  key_id = aws_kms_key.tfstate_events.id
  policy = data.aws_iam_policy_document.tfstate_events_kms_policy.json
}

resource "aws_kms_alias" "tfstate_events" {
  name          = "alias/${var.state_bucket_name}-events"
  target_key_id = aws_kms_key.tfstate_events.key_id
}

# -----------------------------
# S3 bucket for access logs (target for tfstate access logging)
# -----------------------------
resource "aws_s3_bucket" "tfstate_logs" {
  bucket = "${var.state_bucket_name}-logs"
  tags   = merge(var.tags, { Name = "${var.state_bucket_name}-logs" })
}

resource "aws_s3_bucket_public_access_block" "tfstate_logs" {
  bucket                  = aws_s3_bucket.tfstate_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "tfstate_logs" {
  bucket = aws_s3_bucket.tfstate_logs.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "tfstate_logs" {
  bucket = aws_s3_bucket.tfstate_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate_logs" {
  bucket = aws_s3_bucket.tfstate_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.tfstate_logs.arn
    }
  }
}

# Lifecycle policy for access logs (transition + retention)
resource "aws_s3_bucket_lifecycle_configuration" "tfstate_logs" {
  bucket = aws_s3_bucket.tfstate_logs.id

  rule {
    id     = "access-logs-retention"
    status = "Enabled"
    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "noncurrent-version-expiry"
    status = "Enabled"
    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# Allow S3 server access logging service to write into the logs bucket
data "aws_iam_policy_document" "tfstate_logs_bucket_policy" {
  statement {
    sid    = "AllowS3ServerAccessLogs"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.tfstate_logs.arn}/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "tfstate_logs" {
  bucket = aws_s3_bucket.tfstate_logs.id
  policy = data.aws_iam_policy_document.tfstate_logs_bucket_policy.json
}

# -----------------------------
# Terraform remote state bucket
# -----------------------------
resource "aws_s3_bucket" "tfstate" {
  bucket = var.state_bucket_name
  tags   = merge(var.tags, { Name = var.state_bucket_name })
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.tfstate.arn
    }
  }
}

# Access logging for the tfstate bucket
resource "aws_s3_bucket_logging" "tfstate" {
  bucket        = aws_s3_bucket.tfstate.id
  target_bucket = aws_s3_bucket.tfstate_logs.id
  target_prefix = "tfstate/"
}

# Abort incomplete multipart uploads + expire noncurrent versions
resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "noncurrent-version-expiry"
    status = "Enabled"
    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# Require TLS (deny insecure transport)
data "aws_iam_policy_document" "tfstate_deny_insecure" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.tfstate.arn,
      "${aws_s3_bucket.tfstate.arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  policy = data.aws_iam_policy_document.tfstate_deny_insecure.json
}

# Minimal, production-valid event notifications (SNS topic)
resource "aws_sns_topic" "tfstate_events" {
  name              = "${var.state_bucket_name}-events"
  kms_master_key_id = aws_kms_key.tfstate_events.arn
  tags              = merge(var.tags, { Name = "${var.state_bucket_name}-events" })
}

data "aws_iam_policy_document" "sns_allow_s3_publish" {
  statement {
    sid    = "AllowS3Publish"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.tfstate_events.arn]

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.tfstate.arn, aws_s3_bucket.tfstate_logs.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "tfstate_events" {
  arn    = aws_sns_topic.tfstate_events.arn
  policy = data.aws_iam_policy_document.sns_allow_s3_publish.json
}

resource "aws_s3_bucket_notification" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  topic {
    topic_arn = aws_sns_topic.tfstate_events.arn
    events    = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
  }

  depends_on = [aws_sns_topic_policy.tfstate_events]
}

# Event notifications for the access logs bucket (meets logging/compliance checks)
resource "aws_s3_bucket_notification" "tfstate_logs" {
  bucket = aws_s3_bucket.tfstate_logs.id

  topic {
    topic_arn = aws_sns_topic.tfstate_events.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic_policy.tfstate_events]
}

# -----------------------------
# DynamoDB table for state locking (CMK encryption + PITR)
# -----------------------------
resource "aws_dynamodb_table" "tflocks" {
  name         = var.lock_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.tflocks.arn
  }

  point_in_time_recovery { enabled = true }

  tags = merge(var.tags, { Name = var.lock_table_name })
}
