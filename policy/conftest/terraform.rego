package terraform.security

# IMPORTANT:
# - Do NOT define `default deny := []` here.
# - Use only `deny[msg]` rules (partial set rules) so multiple rules can coexist.

# -----------------------------
# Helpers
# -----------------------------
is_null(x) { x == null }

is_managed(rc) { rc.mode == "managed" }

after(rc) := a { a := rc.change.after }

# -----------------------------
# 1) Block public SSH (0.0.0.0/0 on port 22)
# -----------------------------
deny[msg] {
  rc := input.resource_changes[_]
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
  rc := input.resource_changes[_]
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
# (match separate SSE resource by address)
# -----------------------------
deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  rc.type == "aws_s3_bucket"
  bucket_addr := rc.address

  bucket_addr == "module.logging.aws_s3_bucket.alb_logs"
  not sse_ok_for_addr("module.logging.aws_s3_bucket_server_side_encryption_configuration.alb_logs")

  msg := sprintf("S3: Bucket must be encrypted (SSE-S3 or SSE-KMS): %v", [bucket_addr])
}

deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  rc.type == "aws_s3_bucket"
  bucket_addr := rc.address

  bucket_addr == "module.logging.aws_s3_bucket.alb_logs_access"
  not sse_ok_for_addr("module.logging.aws_s3_bucket_server_side_encryption_configuration.alb_logs_access")

  msg := sprintf("S3: Bucket must be encrypted (SSE-S3 or SSE-KMS): %v", [bucket_addr])
}

# Accept AES256 or aws:kms, and handle indexed resources like [0]
sse_ok_for_addr(expected) {
  some i
  rc2 := input.resource_changes[i]
  is_managed(rc2)
  rc2.type == "aws_s3_bucket_server_side_encryption_configuration"

  addr := rc2.address
  addr == expected

  alg := rc2.change.after.rule[_].apply_server_side_encryption_by_default.sse_algorithm
  alg == "AES256" or alg == "aws:kms"
}

sse_ok_for_addr(expected) {
  some i
  rc2 := input.resource_changes[i]
  is_managed(rc2)
  rc2.type == "aws_s3_bucket_server_side_encryption_configuration"

  addr := rc2.address
  startswith(addr, sprintf("%s[", [expected]))

  alg := rc2.change.after.rule[_].apply_server_side_encryption_by_default.sse_algorithm
  alg == "AES256" or alg == "aws:kms"
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
