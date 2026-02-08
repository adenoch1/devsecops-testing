package terraform.security

# -------------------------------------------------------------------
# Conftest policy conventions:
# - Use `deny[msg]` partial rules (set of strings).
# - DO NOT define `default deny := ...` when using `deny[msg]`.
# -------------------------------------------------------------------

# -----------------------------
# Helpers
# -----------------------------

is_null(x) { x == null }

# True if an object has a key and that key is not null
has_key(obj, k) { obj[k] != null }

# Terraform plan JSON shape: input.resource_changes[*]
rc := input.resource_changes[_]

is_managed := rc.mode == "managed"
after := rc.change.after

# Some resources can have after == null (e.g., deletions). Ignore those safely.
has_after { not is_null(after) }

# -----------------------------
# 1) Block public SSH (0.0.0.0/0 on port 22)
# -----------------------------
deny[msg] {
  is_managed
  has_after
  rc.type == "aws_security_group_rule"
  after.type == "ingress"
  after.from_port <= 22
  after.to_port >= 22
  cidr := after.cidr_blocks[_]
  cidr == "0.0.0.0/0"
  msg := sprintf("SECURITY_GROUP_RULE: Public SSH (0.0.0.0/0:22) is forbidden: %v", [rc.address])
}

deny[msg] {
  is_managed
  has_after
  rc.type == "aws_security_group"
  rule := after.ingress[_]
  rule.from_port <= 22
  rule.to_port >= 22
  cidr := rule.cidr_blocks[_]
  cidr == "0.0.0.0/0"
  msg := sprintf("SECURITY_GROUP: Public SSH (0.0.0.0/0:22) is forbidden: %v", [rc.address])
}

# -----------------------------
# 2) Require S3 bucket encryption (SSE-KMS)
# Resource: aws_s3_bucket_server_side_encryption_configuration
# -----------------------------
deny[msg] {
  is_managed
  has_after
  rc.type == "aws_s3_bucket_server_side_encryption_configuration"

  # Must have at least one rule
  not has_key(after, "rule")
  msg := sprintf("S3: Bucket encryption configuration missing 'rule': %v", [rc.address])
}

deny[msg] {
  is_managed
  has_after
  rc.type == "aws_s3_bucket_server_side_encryption_configuration"

  rules := after.rule
  count(rules) == 0
  msg := sprintf("S3: Bucket encryption rules empty: %v", [rc.address])
}

deny[msg] {
  is_managed
  has_after
  rc.type == "aws_s3_bucket_server_side_encryption_configuration"

  # Enforce SSE-KMS (aws:kms)
  r := after.rule[_]
  def := r.apply_server_side_encryption_by_default
  is_null(def)
  msg := sprintf("S3: apply_server_side_encryption_by_default missing: %v", [rc.address])
}

deny[msg] {
  is_managed
  has_after
  rc.type == "aws_s3_bucket_server_side_encryption_configuration"

  r := after.rule[_]
  def := r.apply_server_side_encryption_by_default
  algo := def.sse_algorithm
  algo != "aws:kms"
  msg := sprintf("S3: SSE must be aws:kms (SSE-KMS). Found '%v': %v", [algo, rc.address])
}

# -----------------------------
# 3) Require S3 Public Access Block (all 4 flags true)
# Resource: aws_s3_bucket_public_access_block
# -----------------------------
deny[msg] {
  is_managed
  has_after
  rc.type == "aws_s3_bucket_public_access_block"
  is_null(after.block_public_acls)  # missing field
  msg := sprintf("S3: Public access block incomplete (block_public_acls missing): %v", [rc.address])
}

deny[msg] {
  is_managed
  has_after
  rc.type == "aws_s3_bucket_public_access_block"
  is_null(after.block_public_policy)
  msg := sprintf("S3: Public access block incomplete (block_public_policy missing): %v", [rc.address])
}

deny[msg] {
  is_managed
  has_after
  rc.type == "aws_s3_bucket_public_access_block"
  is_null(after.ignore_public_acls)
  msg := sprintf("S3: Public access block incomplete (ignore_public_acls missing): %v", [rc.address])
}

deny[msg] {
  is_managed
  has_after
  rc.type == "aws_s3_bucket_public_access_block"
  is_null(after.restrict_public_buckets)
  msg := sprintf("S3: Public access block incomplete (restrict_public_buckets missing): %v", [rc.address])
}

deny[msg] {
  is_managed
  has_after
  rc.type == "aws_s3_bucket_public_access_block"
  after.block_public_acls == false
  msg := sprintf("S3: block_public_acls must be true: %v", [rc.address])
}

deny[msg] {
  is_managed
  has_after
  rc.type == "aws_s3_bucket_public_access_block"
  after.block_public_policy == false
  msg := sprintf("S3: block_public_policy must be true: %v", [rc.address])
}

deny[msg] {
  is_managed
  has_after
  rc.type == "aws_s3_bucket_public_access_block"
  after.ignore_public_acls == false
  msg := sprintf("S3: ignore_public_acls must be true: %v", [rc.address])
}

deny[msg] {
  is_managed
  has_after
  rc.type == "aws_s3_bucket_public_access_block"
  after.restrict_public_buckets == false
  msg := sprintf("S3: restrict_public_buckets must be true: %v", [rc.address])
}

# ------------------------------
# 4) Require ALB HTTPS
# Resource: aws_lb_listener
#
# Production-grade rule:
# - Allow HTTPS:443 (must have certificate_arn)
# - Allow HTTP:80 ONLY if it redirects to HTTPS:443
# - Deny everything else for ALB listeners
# ------------------------------

is_https_443(listener) {
  listener.protocol == "HTTPS"
  listener.port == 443
}

has_cert(listener) {
  not is_null(listener.certificate_arn)
}

redirects_to_https_443(listener) {
  # Terraform schema: default_action is a list
  a := listener.default_action[_]
  a.type == "redirect"
  r := a.redirect
  r.protocol == "HTTPS"
  r.port == "443"  # redirect port is typically a string in TF schema
}

is_http_80_redirect(listener) {
  listener.protocol == "HTTP"
  listener.port == 80
  redirects_to_https_443(listener)
}

deny[msg] {
  is_managed
  has_after
  rc.type == "aws_lb_listener"

  # Must be either HTTPS:443, or HTTP:80 redirecting to HTTPS:443
  not is_https_443(after)
  not is_http_80_redirect(after)

  msg := sprintf("ALB: Listener must be HTTPS:443 OR HTTP:80 redirect -> HTTPS:443: %v", [rc.address])
}

deny[msg] {
  is_managed
  has_after
  rc.type == "aws_lb_listener"

  is_https_443(after)
  not has_cert(after)

  msg := sprintf("ALB: HTTPS:443 listener must have certificate_arn set: %v", [rc.address])
}
