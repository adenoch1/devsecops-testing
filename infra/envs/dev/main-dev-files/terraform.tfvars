aws_region  = "ca-central-1"
project     = "devsecops-flask"
environment = "dev"
owner       = "enoch"

# REQUIRED (your variables.tf requires this; no default exists) Note
vpc_cidr = "192.168.0.0/16"

# REQUIRED for HTTPS listener
acm_certificate_arn = "arn:aws:acm:ca-central-1:476532114555:certificate/8729f39e-2512-42ec-8592-bdfd726f8018"

# ✅ Checkov CKV_AWS_150 requires this
alb_deletion_protection = true

# Optional / defaults are fine, but keeping explicit is okay
alb_log_prefix          = "alb-access"
log_retention_days      = 365
flow_log_retention_days = 365
