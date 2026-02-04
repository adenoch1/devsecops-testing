package terraform.security

# -----------------------------
# Helpers
# -----------------------------
is_managed(rc) { rc.mode == "managed" }

after(rc) := a { a := rc.change.after }

last(xs) := x {
  n := count(xs)
  n > 0
  x := xs[n - 1]
}

bucket_token(bucket_addr) := tok {
  parts := split(bucket_addr, ".")
  tok := last(parts)
}

# Get bucket fields safely (may be null/unknown in some plans)
bucket_id(b) := id { id := b.id }
bucket_id(b) := "" { not b.id }

bucket_name(b) := n { n := b.bucket }
bucket_name(b) := "" { not b.bucket }

# Normalize nested block shapes across Terraform JSON versions:
# apply_server_side_encryption_by_default can be an object OR [object]
sse_apply(rule) := apply {
  v := rule.apply_server_side_encryption_by_default
  is_array(v)
  count(v) > 0
  apply := v[0]
}

sse_apply(rule) := apply {
  v := rule.apply_server_side_encryption_by_default
  not is_array(v)
  apply := v
}

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
# 2) S3 buckets must be encrypted (SSE-S3 or SSE-KMS)
# -----------------------------
deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  rc.type == "aws_s3_bucket"

  b := after(rc)

  not s3_bucket_encrypted(rc.address, b)

  msg := sprintf("S3: Bucket must be encrypted (SSE-S3 or SSE-KMS): %v", [rc.address])
}

s3_bucket_encrypted(bucket_addr, b) {
  tok := bucket_token(bucket_addr)

  some i
  rc2 := input.resource_changes[i]
  is_managed(rc2)
  rc2.type == "aws_s3_bucket_server_side_encryption_configuration"

  enc := rc2.change.after

  # Match by address token (handles ...alb_logs and ...alb_logs[0])
  address_has_token(rc2.address, tok)

  sse_alg_ok(enc)
}

s3_bucket_encrypted(bucket_addr, b) {
  some i
  rc2 := input.resource_changes[i]
  is_managed(rc2)
  rc2.type == "aws_s3_bucket_server_side_encryption_configuration"

  enc := rc2.change.after

  # Match by bucket reference (name or id)
  encryption_points_to_bucket(enc, b)

  sse_alg_ok(enc)
}

address_has_token(addr, tok) {
  contains(addr, sprintf(".%s", [tok]))
}

# enc.bucket or enc.bucket_id may exist depending on provider/version
encryption_points_to_bucket(enc, b) {
  enc.bucket == bucket_id(b)
}

encryption_points_to_bucket(enc, b) {
  enc.bucket == bucket_name(b)
}

encryption_points_to_bucket(enc, b) {
  enc.bucket_id == bucket_id(b)
}

encryption_points_to_bucket(enc, b) {
  enc.bucket_id == bucket_name(b)
}

# SSE algorithm checks (handles apply_server_side_encryption_by_default as object OR list)
sse_alg_ok(enc) {
  rule := enc.rule[_]
  apply := sse_apply(rule)
  apply.sse_algorithm == "AES256"
}

sse_alg_ok(enc) {
  rule := enc.rule[_]
  apply := sse_apply(rule)
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
