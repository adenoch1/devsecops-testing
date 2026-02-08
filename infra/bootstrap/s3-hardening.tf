# -----------------------------
# S3 hardening (production-grade defaults)
# - Bucket owner enforced (no ACLs)
# - Deny non-TLS (aws:SecureTransport=false)
# - Deny unencrypted puts (require SSE-KMS)
# -----------------------------

# Enforce bucket owner ownership (recommended best practice)
resource "aws_s3_bucket_ownership_controls" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_ownership_controls" "tfstate_access_logs" {
  bucket = aws_s3_bucket.tfstate_access_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Deny non-TLS and require encryption for all puts to the tfstate bucket
data "aws_iam_policy_document" "tfstate_bucket_policy" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = [
      aws_s3_bucket.tfstate.arn,
      "${aws_s3_bucket.tfstate.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Require SSE-KMS on uploads
  statement {
    sid     = "DenyUnencryptedObjectUploads"
    effect  = "Deny"
    actions = ["s3:PutObject"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = ["${aws_s3_bucket.tfstate.arn}/*"]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid     = "DenyIncorrectKMSKey"
    effect  = "Deny"
    actions = ["s3:PutObject"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = ["${aws_s3_bucket.tfstate.arn}/*"]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.tfstate.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  policy = data.aws_iam_policy_document.tfstate_bucket_policy.json
}

# Deny non-TLS for the access logs bucket as well
data "aws_iam_policy_document" "tfstate_access_logs_deny_insecure" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = [
      aws_s3_bucket.tfstate_access_logs.arn,
      "${aws_s3_bucket.tfstate_access_logs.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# Merge the existing access-logs bucket policy (for log delivery) with the TLS deny policy
data "aws_iam_policy_document" "tfstate_access_logs_bucket_policy_merged" {
  source_policy_documents = [
    data.aws_iam_policy_document.tfstate_access_logs_bucket_policy.json,
    data.aws_iam_policy_document.tfstate_access_logs_deny_insecure.json,
  ]
}

resource "aws_s3_bucket_policy" "tfstate_access_logs_merged" {
  bucket = aws_s3_bucket.tfstate_access_logs.id
  policy = data.aws_iam_policy_document.tfstate_access_logs_bucket_policy_merged.json
}
