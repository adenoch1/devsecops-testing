package terraform.security

# ------------------------------------------------------------
# Production-grade Conftest/OPA style:
# - deny is a PARTIAL SET rule: deny[msg] { ... }
# - Avoid top-level rc := input.resource_changes[_] (multi-output complete rule)
# ------------------------------------------------------------

# -----------------------------
# Helpers (safe)
# -----------------------------
is_null(x) { x == null }

has_after(rc) {
  not is_null(rc.change.after)
}

is_managed(rc) {
  rc.mode == "managed"
}

after(rc) := rc.change.after

# -----------------------------
# 1) Block public SSH (0.0.0.0/0 on port 22)
# -----------------------------
deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  has_after(rc)

  a := after(rc)
  rc.type == "aws_security_group_rule"
  a.type == "ingress"
  a.from_port <= 22
  a.to_port >= 22
  cidr := a.cidr_blocks[_]
  cidr == "0.0.0.0/0"

  msg := sprintf("SECURITY_GROUP_RULE: Public SSH (0.0.0.0/0:22) is forbidden: %v", [rc.address])
}

deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  has_after(rc)

  a := after(rc)
  rc.type == "aws_security_group"
  rule := a.ingress[_]
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
  rc := input.resource_changes[_]
  is_managed(rc)
  has_after(rc)

  a := after(rc)
  rc.type == "aws_s3_bucket_server_side_encryption_configuration"

  not a.rule
  msg := sprintf("S3: Bucket encryption missing 'rule': %v", [rc.address])
}

deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  has_after(rc)

  a := after(rc)
  rc.type == "aws_s3_bucket_server_side_encryption_configuration"

  count(a.rule) == 0
  msg := sprintf("S3: Bucket encryption rules empty: %v", [rc.address])
}

deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  has_after(rc)

  a := after(rc)
  rc.type == "aws_s3_bucket_server_side_encryption_configuration"

  r := a.rule[_]
  is_null(r.apply_server_side_encryption_by_default)
  msg := sprintf("S3: apply_server_side_encryption_by_default missing: %v", [rc.address])
}

deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  has_after(rc)

  a := after(rc)
  rc.type == "aws_s3_bucket_server_side_encryption_configuration"

  r := a.rule[_]
  algo := r.apply_server_side_encryption_by_default.sse_algorithm
  algo != "aws:kms"
  msg := sprintf("S3: SSE must be aws:kms (SSE-KMS). Found '%v': %v", [algo, rc.address])
}

# -----------------------------
# 3) Require S3 Public Access Block (all 4 flags true)
# Resource: aws_s3_bucket_public_access_block
# -----------------------------
deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  has_after(rc)

  a := after(rc)
  rc.type == "aws_s3_bucket_public_access_block"

  a.block_public_acls != true
  msg := sprintf("S3: block_public_acls must be true: %v", [rc.address])
}

deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  has_after(rc)

  a := after(rc)
  rc.type == "aws_s3_bucket_public_access_block"

  a.block_public_policy != true
  msg := sprintf("S3: block_public_policy must be true: %v", [rc.address])
}

deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  has_after(rc)

  a := after(rc)
  rc.type == "aws_s3_bucket_public_access_block"

  a.ignore_public_acls != true
  msg := sprintf("S3: ignore_public_acls must be true: %v", [rc.address])
}

deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  has_after(rc)

  a := after(rc)
  rc.type == "aws_s3_bucket_public_access_block"

  a.restrict_public_buckets != true
  msg := sprintf("S3: restrict_public_buckets must be true: %v", [rc.address])
}

# -----------------------------
# 4) Require ALB HTTPS
# Resource: aws_lb_listener
# Rule:
# - HTTPS 443 requires certificate_arn
# - HTTP 80 allowed ONLY if it redirects to HTTPS 443
# -----------------------------
is_https_443(a) {
  a.protocol == "HTTPS"
  a.port == 443
}

has_cert(a) {
  not is_null(a.certificate_arn)
}

redirects_to_https_443(a) {
  act := a.default_action[_]
  act.type == "redirect"
  r := act.redirect
  r.protocol == "HTTPS"
  r.port == "443"
}

is_http_80_redirect(a) {
  a.protocol == "HTTP"
  a.port == 80
  redirects_to_https_443(a)
}

deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  has_after(rc)

  a := after(rc)
  rc.type == "aws_lb_listener"

  not is_https_443(a)
  not is_http_80_redirect(a)

  msg := sprintf("ALB: Listener must be HTTPS:443 OR HTTP:80 redirect -> HTTPS:443: %v", [rc.address])
}

deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  has_after(rc)

  a := after(rc)
  rc.type == "aws_lb_listener"

  is_https_443(a)
  not has_cert(a)

  msg := sprintf("ALB: HTTPS:443 listener must have certificate_arn set: %v", [rc.address])
}
