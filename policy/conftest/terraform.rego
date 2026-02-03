package terraform.security

# -----------------------------
# Helpers
# -----------------------------
is_null(x) { x == null }

# Terraform plan JSON: resource_changes[*]
rc := input.resource_changes[_]

is_managed := rc.mode == "managed"
after := rc.change.after

# -----------------------------
# 1) Block public SSH (0.0.0.0/0 on port 22)
# -----------------------------
deny[msg] {
  is_managed
  rc.type == "aws_security_group_rule"
  after.type == "ingress"
  after.from_port <= 22
  after.to_port >= 22
  cidr := after.cidr_blocks[_]
  cidr == "0.0.0.0/0"
  msg := sprintf("SECURITY_GROUP_RULE: Public SSH is forbidden: %v", [rc.address])
}

deny[msg] {
  is_managed
  rc.type == "aws_security_group"
  rule := after.ingress[_]
  rule.from_port <= 22
  rule.to_port >= 22
  cidr := rule.cidr_blocks[_]
  cidr == "0.0.0.0/0"
  msg := sprintf("SECURITY_GROUP: Public SSH is forbidden: %v", [rc.address])
}

# -----------------------------
# 2) IAM least privilege: deny wildcard actions or resources
# -----------------------------
deny[msg] {
  is_managed
  startswith(rc.type, "aws_iam_")
  has_policy(after)
  statement := get_statements(after)[_]
  action := statement.Action[_]
  action == "*"
  msg := sprintf("IAM: Wildcard Action '*' is forbidden: %v", [rc.address])
}

deny[msg] {
  is_managed
  startswith(rc.type, "aws_iam_")
  has_policy(after)
  statement := get_statements(after)[_]
  res := statement.Resource[_]
  res == "*"
  msg := sprintf("IAM: Wildcard Resource '*' is forbidden: %v", [rc.address])
}

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

# -----------------------------
# 3) S3 buckets must be encrypted (SSE-S3 or SSE-KMS)
# -----------------------------
deny[msg] {
  is_managed
  rc.type == "aws_s3_bucket"
  not has_sse(after)
  msg := sprintf("S3: Bucket must be encrypted (SSE-S3 or SSE-KMS): %v", [rc.address])
}

has_sse(b) {
  rule := b.server_side_encryption_configuration.rule[_]
  apply := rule.apply_server_side_encryption_by_default
  apply.sse_algorithm == "AES256"
}

has_sse(b) {
  rule := b.server_side_encryption_configuration.rule[_]
  apply := rule.apply_server_side_encryption_by_default
  apply.sse_algorithm == "aws:kms"
}

deny[msg] {
  is_managed
  rc.type == "aws_s3_bucket_public_access_block"
  after.block_public_acls != true
  msg := sprintf("S3: block_public_acls must be true: %v", [rc.address])
}

deny[msg] {
  is_managed
  rc.type == "aws_s3_bucket_public_access_block"
  after.block_public_policy != true
  msg := sprintf("S3: block_public_policy must be true: %v", [rc.address])
}

deny[msg] {
  is_managed
  rc.type == "aws_s3_bucket_public_access_block"
  after.restrict_public_buckets != true
  msg := sprintf("S3: restrict_public_buckets must be true: %v", [rc.address])
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

# Enforce strong TLS on ALB HTTPS listeners
deny[msg] {
  input.resource_changes[_].type == "aws_lb_listener"
  listener := input.resource_changes[_].change.after
  lower(listener.protocol) == "https"
  not startswith(listener.ssl_policy, "ELBSecurityPolicy-TLS13")
  msg := sprintf("ALB HTTPS listener must use TLS 1.2+ or TLS 1.3 policy. Found: %v", [listener.ssl_policy])
}
