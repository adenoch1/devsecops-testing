package terraform.security

default deny := []

# Terraform plan JSON uses input.resource_changes[*]
rc := input.resource_changes[_]

after := rc.change.after

is_managed := rc.mode == "managed"

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
# 2) Enforce TLS on ALB listener (if present)
# -----------------------------
deny[msg] {
  is_managed
  rc.type == "aws_lb_listener"
  after.port == 80
  msg := sprintf("ALB_LISTENER: HTTP(80) listeners are forbidden; use HTTPS(443): %v", [rc.address])
}
