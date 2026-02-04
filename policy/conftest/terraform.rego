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

last(xs) := x {
  n := count(xs)
  x := xs[n - 1]
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
#       matched robustly by logical token (e.g. alb_logs / alb_logs_access),
#       including indexed resources (e.g. ...alb_logs[0])
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
  has_matching_sse_resource_by_token(rc)
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

# Extract the bucket's logical token from its address.
# e.g. module.logging.aws_s3_bucket.alb_logs -> "alb_logs"
bucket_token(bucket_rc) := tok {
  parts := split(bucket_rc.address, ".")
  tok := last(parts)
}

# Match SSE config resources that contain ".<token>" or ".<token>["
# This handles:
# - exact name match
# - indexed resources like [0]
# - minor address nesting differences
has_matching_sse_resource_by_token(bucket_rc) {
  tok := bucket_token(bucket_rc)

  some i
  rc2 := input.resource_changes[i]
  is_managed(rc2)
  rc2.type == "aws_s3_bucket_server_side_encryption_configuration"

  contains(rc2.address, sprintf(".%s", [tok]))

  enc := rc2.change.after
  rule := enc.rule[_]
  apply := rule.apply_server_side_encryption_by_default
  apply.sse_algorithm == "AES256"
}

has_matching_sse_resource_by_token(bucket_rc) {
  tok := bucket_token(bucket_rc)

  some i
  rc2 := input.resource_changes[i]
  is_managed(rc2)
  rc2.type == "aws_s3_bucket_server_side_encryption_configuration"

  contains(rc2.address, sprintf(".%s", [tok]))

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
