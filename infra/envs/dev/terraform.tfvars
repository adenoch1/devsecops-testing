aws_region          = "ca-central-1"
project             = "devsecops-flask"
environment         = "dev"
owner               = "enoch"
acm_certificate_arn = "arn:aws:acm:ca-central-1:476532114555:certificate/8729f39e-2512-42ec-8592-bdfd726f8018"

# Week 3: REQUIRED to pass policy (HTTPS listener 443)
# Create/validate a certificate in ACM (same region where ALB is running) and paste the ARN here as done above.

# Optional
alb_log_prefix          = "alb-access"
flow_log_retention_days = 30
ecs_log_retention_days  = 14
