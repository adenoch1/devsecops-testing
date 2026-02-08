package terraform.security

# Conftest expects deny to be a collection of strings.
default deny := set()

# -----------------------------
# Helpers
# -----------------------------
is_null(x) { x == null }

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
# 2) Require S3 bucket encryption (SSE-KMS)
# -----------------------------
deny[msg] {
  is_managed
  rc.type == "aws_s3_bucket_server_side_encryption_configuration"
  rules := after.rule
  count(rules) == 0
  msg := sprintf("S3: Bucket encryption config missing: %v", [rc.address])
}

# -----------------------------
# 3) Require S3 Public Access Block
# -----------------------------
deny[msg] {
  is_managed
  rc.type == "aws_s3_bucket_public_access_block"

  is_null(after.block_public_acls)  # missing fields
  msg := sprintf("S3: Public access block incomplete: %v", [rc.address])
}

deny[msg] {
  is_managed
  rc.type == "aws_s3_bucket_public_access_block"
  after.block_public_acls == false
  msg := sprintf("S3: block_public_acls must be true: %v", [rc.address])
}

deny[msg] {
  is_managed
  rc.type == "aws_s3_bucket_public_access_block"
  after.block_public_policy == false
  msg := sprintf("S3: block_public_policy must be true: %v", [rc.address])
}

deny[msg] {
  is_managed
  rc.type == "aws_s3_bucket_public_access_block"
  after.ignore_public_acls == false
  msg := sprintf("S3: ignore_public_acls must be true: %v", [rc.address])
}

deny[msg] {
  is_managed
  rc.type == "aws_s3_bucket_public_access_block"
  after.restrict_public_buckets == false
  msg := sprintf("S3: restrict_public_buckets must be true: %v", [rc.address])
}

# -----------------------------
# 4) Require ALB HTTPS listener (port 443)
# -----------------------------
deny[msg] {
  is_managed
  rc.type == "aws_lb_listener"
  after.port != 443
  msg := sprintf("ALB: Listener must be HTTPS on 443: %v", [rc.address])
}

deny[msg] {
  is_managed
  rc.type == "aws_lb_listener"
  after.protocol != "HTTPS"
  msg := sprintf("ALB: Listener protocol must be HTTPS: %v", [rc.address])
}
