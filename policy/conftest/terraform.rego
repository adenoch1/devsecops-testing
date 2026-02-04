package terraform.security

default deny := []

# -----------------------------
# Helpers
# -----------------------------
is_null(x) { x == null }

is_managed(rc) { rc.mode == "managed" }

after(rc) := a { a := rc.change.after }

# Terraform plan JSON: resource_changes[*]
rc := input.resource_changes[_]

# -----------------------------
# 1) Block public SSH (0.0.0.0/0 on port 22)
# -----------------------------
deny[msg] {
  is_managed(rc)
  rc.type == "aws_security_group_rule"

  a := after(rc)
  a.type == "ingress"
  a.from_port <= 22
  a.to_port >= 22
  cidr := a.cidr_blocks[_]
  cidr == "0.0.0.0/0"

  msg := sprintf("SECURITY_GROUP_RULE: Public SSH is forbidden: %v", [rc.address])
}

deny[msg] {
  is_managed(rc)
  rc.type == "aws_security_group"

  a := after(rc)
  rule := a.ingress[_]
  rule.from_port <= 22
  rule.to_port >= 22
  cidr := rule.cidr_blocks[_]
  cidr == "0.0.0.0/0"

  msg := sprintf("SECURITY_GROUP: Public SSH is forbidden: %v", [rc.address])
}

# -----------------------------
# 2) S3 buckets must be encrypted
# FIX: accept separate SSE config resource
# -----------------------------
deny[msg] {
  is_managed(rc)
  rc.type == "aws_s3_bucket"
  bucket_addr := rc.address

  not s3_bucket_has_encryption(bucket_addr)

  msg := sprintf("S3: Bucket must be encrypted (SSE-S3 or SSE-KMS): %v", [bucket_addr])
}

# A bucket is considered encrypted if either:
# - it has inline encryption (rare now), OR
# - there exists a server_side_encryption_configuration resource for that bucket
s3_bucket_has_encryption(bucket_addr) {
  a := after(rc)
  rc.address == bucket_addr
  has_inline_sse(a)
}

s3_bucket_has_encryption(bucket_addr) {
  # Most reliable for your module: require the SSE config resources exist in plan
  bucket_addr == "module.logging.aws_s3_bucket.alb_logs"
  sse_config_exists("module.logging.aws_s3_bucket_server_side_encryption_configuration.alb_logs")
}

s3_bucket_has_encryption(bucket_addr) {
  bucket_addr == "module.logging.aws_s3_bucket.alb_logs_access"
  sse_config_exists("module.logging.aws_s3_bucket_server_side_encryption_configuration.alb_logs_access")
}

# Inline SSE detection (in case provider puts it on the bucket)
has_inline_sse(b) {
  rule := b.server_side_encryption_configuration.rule[_]
  apply := rule.apply_server_side_encryption_by_default
  apply.sse_algorithm == "AES256"
}

has_inline_sse(b) {
  rule := b.server_side_encryption_configuration.rule[_]
  apply := rule.apply_server_side_encryption_by_default
  apply.sse_algorithm == "aws:kms"
}

# SSE config exists and sets AES256 or aws:kms
# Handles both unindexed and indexed addresses ([0]) just in case.
sse_config_exists(expected_addr) {
  some i
  rc2 := input.resource_changes[i]
  is_managed(rc2)
  rc2.type == "aws_s3_bucket_server_side_encryption_configuration"
  addr := rc2.address
  addr == expected_addr

  enc := rc2.change.after
  rule := enc.rule[_]
  apply := rule.apply_server_side_encryption_by_default
  apply.sse_algorithm == "AES256"
}

sse_config_exists(expected_addr) {
  some i
  rc2 := input.resource_changes[i]
  is_managed(rc2)
  rc2.type == "aws_s3_bucket_server_side_encryption_configuration"
  addr := rc2.address
  startswith(addr, sprintf("%s[", [expected_addr]))

  enc := rc2.change.after
  rule := enc.rule[_]
  apply := rule.apply_server_side_encryption_by_default
  apply.sse_algorithm == "AES256"
}

sse_config_exists(expected_addr) {
  some i
  rc2 := input.resource_changes[i]
  is_managed(rc2)
  rc2.type == "aws_s3_bucket_server_side_encryption_configuration"
  addr := rc2.address
  addr == expected_addr

  enc := rc2.change.after
  rule := enc.rule[_]
  apply := rule.apply_server_side_encryption_by_default
  apply.sse_algorithm == "aws:kms"
}

sse_config_exists(expected_addr) {
  some i
  rc2 := input.resource_changes[i]
  is_managed(rc2)
  rc2.type == "aws_s3_bucket_server_side_encryption_configuration"
  addr := rc2.address
  startswith(addr, sprintf("%s[", [expected_addr]))

  enc := rc2.change.after
  rule := enc.rule[_]
  apply := rule.apply_server_side_encryption_by_default
  apply.sse_algorithm == "aws:kms"
}

# -----------------------------
# 3) VPC Flow Logs must exist
# -----------------------------
deny[msg] {
  not flow_logs_present
  msg := "VPC: Flow Logs must be enabled (missing aws_flow_log)."
}

flow_logs_present {
  some i
  input.resource_changes[i].type == "aws_flow_log"
  input.resource_changes[i].change.after != null
}

# -----------------------------
# 4) If using ALB, require HTTPS listener 443
# -----------------------------
deny[msg] {
  uses_alb
  not https_listener_present
  msg := "ALB: HTTPS listener (443) is required when using ALB."
}

uses_alb {
  some i
  input.resource_changes[i].type == "aws_lb"
  input.resource_changes[i].change.after.load_balancer_type == "application"
}

https_listener_present {
  some i
  input.resource_changes[i].type == "aws_lb_listener"
  input.resource_changes[i].change.after.port == 443
  lower(input.resource_changes[i].change.after.protocol) == "https"
}
