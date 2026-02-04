package terraform.security

# -----------------------------
# Helpers
# -----------------------------
is_null(x) { x == null }

is_managed(rc) {
  rc.mode == "managed"
}

after(rc) := a {
  a := rc.change.after
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
# 2) IAM least privilege: deny wildcard actions/resources
# -----------------------------
has_policy(x) { not is_null(x.policy) }
has_policy(x) { not is_null(x.assume_role_policy) }

get_statements(x) := s {
  not is_null(x.policy)
  doc := json.unmarshal(x.policy)
  s := doc.Statement
}

get_statements(x) := s {
  not is_null(x.assume_role_policy)
  doc := json.unmarshal(x.assume_role_policy)
  s := doc.Statement
}

deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  startswith(rc.type, "aws_iam_")

  a := after(rc)
  has_policy(a)

  statement := get_statements(a)[_]
  action := statement.Action[_]
  action == "*"

  msg := sprintf("IAM: Wildcard Action '*' is forbidden: %v", [rc.address])
}

deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  startswith(rc.type, "aws_iam_")

  a := after(rc)
  has_policy(a)

  statement := get_statements(a)[_]
  res := statement.Resource[_]
  res == "*"

  msg := sprintf("IAM: Wildcard Resource '*' is forbidden: %v", [rc.address])
}

# -----------------------------
# 3) S3 buckets must be encrypted (SSE-S3 or SSE-KMS)
#    Support:
#    A) Inline SSE on aws_s3_bucket
#    B) Separate aws_s3_bucket_server_side_encryption_configuration
#       matched by address naming (most reliable in plan JSON)
# -----------------------------
deny[msg] {
  rc := input.resource_changes[_]
  is_managed(rc)
  rc.type == "aws_s3_bucket"

  b := after(rc)

  not s3_bucket_encrypted(rc, b)

  msg := sprintf("S3: Bucket must be encrypted (SSE-S3 or SSE-KMS): %v", [rc.address])
}

s3_bucket_encrypted(rc, b) {
  has_inline_sse(b)
}

s3_bucket_encrypted(rc, b) {
  has_matching_sse_resource(rc)
}

# Inline SSE block (some provider configs)
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

# Separate SSE config resource exists with same logical name as the bucket:
#   module.logging.aws_s3_bucket.alb_logs
#   module.logging.aws_s3_bucket_server_side_encryption_configuration.alb_logs
has_matching_sse_resource(bucket_rc) {
  expected := sprintf("%s_server_side_encryption_configuration%s", [
    "aws_s3_bucket",
    substring(bucket_rc.address, count(bucket_rc.address) - count(trim_prefix(bucket_rc.address, "module.logging.")), count(bucket_rc.address))
  ])
  # The above line is too clever for OPA. We'll implement it more directly below.
  false
}

# A simpler and robust approach:
# Build the expected SSE address by replacing the type portion in the address.
expected_sse_address(bucket_addr) := sse_addr {
  # Replace ".aws_s3_bucket." with ".aws_s3_bucket_server_side_encryption_configuration."
  sse_addr := replace(bucket_addr, ".aws_s3_bucket.", ".aws_s3_bucket_server_side_encryption_configuration.")
}

has_matching_sse_resource(bucket_rc) {
  sse_addr := expected_sse_address(bucket_rc.address)

  some i
  rc2 := input.resource_changes[i]
  is_managed(rc2)
  rc2.type == "aws_s3_bucket_server_side_encryption_configuration"
  rc2.address == sse_addr

  enc := rc2.change.after

  # Ensure it sets AES256 or aws:kms
  rule := enc.rule[_]
  apply := rule.apply_server_side_encryption_by_default
  apply.sse_algorithm == "AES256"
}

has_matching_sse_resource(bucket_rc) {
  sse_addr := expected_sse_address(bucket_rc.address)

  some i
  rc2 := input.resource_changes[i]
  is_managed(rc2)
  rc2.type == "aws_s3_bucket_server_side_encryption_configuration"
  rc2.address == sse_addr

  enc := rc2.change.after

  rule := enc.rule[_]
  apply := rule.apply_server_side_encryption_by_default
  apply.sse_algorithm == "aws:kms"
}

# -----------------------------
# 4) VPC Flow Logs must exist
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
# 5) If using ALB, require HTTPS listener 443
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

deny[msg] {
  rc := input.resource_changes[_]
  rc.type == "aws_lb_listener"

  listener := rc.change.after
  lower(listener.protocol) == "https"
  not startswith(listener.ssl_policy, "ELBSecurityPolicy-TLS13")

  msg := sprintf("ALB HTTPS listener must use TLS 1.2+ or TLS 1.3 policy. Found: %v", [listener.ssl_policy])
}
