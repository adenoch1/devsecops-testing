############################################################
# ECS MODULE - main.tf (FULL, corrected HCL)
# - Public ALB (HTTPS) + WAFv2 + WAF Logging (Firehose->S3)
# - ECS Fargate service behind ALB
# - Security groups without dependency cycles
############################################################

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# --------------------------------
# CloudWatch Logs (encrypted with KMS)
# --------------------------------
resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${var.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.cloudwatch_logs_kms_key_arn

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-logs"
  })
}

# -----------------------------
# Security Groups (no cycle)
# -----------------------------
# ALB SG: internet ingress 443, egress restricted to VPC CIDR on app port (breaks SG cycle)
#tfsec:ignore:aws-ec2-no-public-ingress-sgr
resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb-sg"
  description = "ALB security group"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from internet (IPv4)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description      = "HTTPS from internet (IPv6)"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    description = "ALB to targets on app port within VPC CIDR"
    from_port   = var.app_port
    to_port     = var.app_port
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-alb-sg"
  })
}

resource "aws_security_group" "ecs" {
  name        = "${var.name_prefix}-ecs-sg"
  description = "ECS tasks security group"
  vpc_id      = var.vpc_id

  ingress {
    description     = "App traffic from ALB only"
    from_port       = var.app_port
    to_port         = var.app_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Outbound HTTPS for AWS APIs
  #tfsec:ignore:aws-ec2-no-public-egress-sgr
  egress {
    description = "Outbound HTTPS (IPv4)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # DNS to VPC resolver (UDP/TCP 53)
  egress {
    description = "DNS to VPC resolver (UDP)"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "DNS to VPC resolver (TCP)"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ecs-sg"
  })
}

# ------------------------------
# Application Load Balancer (HTTPS enforced)
# ------------------------------
# NOTE: Public ALB is expected for an internet-facing app.
# If you want scanners 100% green with no ignore, move to CloudFront (public) + internal ALB.
#tfsec:ignore:aws-elb-alb-not-public
resource "aws_lb" "this" {
  name               = "${var.name_prefix}-alb"
  load_balancer_type = "application"
  internal           = false

  security_groups            = [aws_security_group.alb.id]
  subnets                    = var.public_subnet_ids
  drop_invalid_header_fields = true

  enable_deletion_protection = true

  access_logs {
    bucket  = var.alb_log_bucket_name
    prefix  = var.alb_log_prefix
    enabled = true
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-alb"
  })
}

resource "aws_lb_target_group" "app" {
  name        = "${var.name_prefix}-tg"
  port        = var.app_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    interval            = 30
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    matcher             = "200-399"
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-tg"
  })
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# ------------------------------
# WAFv2 (CKV2_AWS_28)
# ------------------------------
resource "aws_wafv2_web_acl" "alb" {
  name        = "${var.name_prefix}-waf"
  description = "WAF for public ALB"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-waf"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesKnownBadInputsRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesAmazonIpReputationList"
      sampled_requests_enabled   = true
    }
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-waf" })
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.this.arn
  web_acl_arn  = aws_wafv2_web_acl.alb.arn
}

# ------------------------------------------------------------
# WAF Logging (CKV2_AWS_31) + hardening for scanners
# WAF logs -> Kinesis Firehose -> S3
# ------------------------------------------------------------

resource "aws_kms_key" "waf_logs" {
  description             = "CMK for WAF logs bucket and Firehose encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowFirehoseUseOfKey"
        Effect    = "Allow"
        Principal = { Service = "firehose.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid       = "AllowS3UseOfKey"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.tags, { Name = "${var.name_prefix}-waf-logs-kms" })
}

resource "aws_kms_alias" "waf_logs" {
  name          = "alias/${var.name_prefix}-waf-logs"
  target_key_id = aws_kms_key.waf_logs.key_id
}

resource "aws_s3_bucket" "waf_logs_access" {
  bucket        = "${var.name_prefix}-waf-logs-access-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags          = merge(var.tags, { Name = "${var.name_prefix}-waf-logs-access" })
}

resource "aws_s3_bucket_public_access_block" "waf_logs_access" {
  bucket                  = aws_s3_bucket.waf_logs_access.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "waf_logs_access" {
  bucket = aws_s3_bucket.waf_logs_access.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "waf_logs_access" {
  bucket = aws_s3_bucket.waf_logs_access.id

  versioning_configuration {
    status = "Enabled"
  }

  depends_on = [aws_s3_bucket_ownership_controls.waf_logs_access]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs_access" {
  bucket = aws_s3_bucket.waf_logs_access.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.waf_logs.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "waf_logs_access" {
  bucket = aws_s3_bucket.waf_logs_access.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter {
      prefix = ""
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = var.lifecycle_expire_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.lifecycle_expire_days
    }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket" "waf_logs" {
  bucket        = "${var.name_prefix}-waf-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags          = merge(var.tags, { Name = "${var.name_prefix}-waf-logs" })
}

resource "aws_s3_bucket_public_access_block" "waf_logs" {
  bucket                  = aws_s3_bucket.waf_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  versioning_configuration {
    status = "Enabled"
  }

  depends_on = [aws_s3_bucket_ownership_controls.waf_logs]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.waf_logs.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    id     = "lifecycle"
    status = "Enabled"

    filter {
      prefix = ""
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = var.lifecycle_expire_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.lifecycle_expire_days
    }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_logging" "waf_logs" {
  bucket        = aws_s3_bucket.waf_logs.id
  target_bucket = aws_s3_bucket.waf_logs_access.id
  target_prefix = "waf-logs-access/"
}

resource "aws_sns_topic" "waf_bucket_events" {
  name              = "${var.name_prefix}-waf-bucket-events"
  kms_master_key_id = aws_kms_key.waf_logs.arn
  tags              = merge(var.tags, { Name = "${var.name_prefix}-waf-bucket-events" })
}

data "aws_iam_policy_document" "waf_bucket_events_policy" {
  statement {
    sid       = "AllowS3Publish"
    effect    = "Allow"
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.waf_bucket_events.arn]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "waf_bucket_events" {
  arn    = aws_sns_topic.waf_bucket_events.arn
  policy = data.aws_iam_policy_document.waf_bucket_events_policy.json
}

resource "aws_s3_bucket_notification" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  topic {
    topic_arn = aws_sns_topic.waf_bucket_events.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

resource "aws_iam_role" "firehose_waf" {
  name = "${var.name_prefix}-firehose-waf-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.tags, { Name = "${var.name_prefix}-firehose-waf-role" })
}

data "aws_iam_policy_document" "firehose_waf" {
  statement {
    effect = "Allow"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:PutObject"
    ]
    resources = [
      aws_s3_bucket.waf_logs.arn,
      "${aws_s3_bucket.waf_logs.arn}/*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = [aws_kms_key.waf_logs.arn]
  }
}

resource "aws_iam_role_policy" "firehose_waf" {
  name   = "${var.name_prefix}-firehose-waf-policy"
  role   = aws_iam_role.firehose_waf.id
  policy = data.aws_iam_policy_document.firehose_waf.json
}

resource "aws_kinesis_firehose_delivery_stream" "waf" {
  # WAF logging requires the Firehose stream name to start with "aws-waf-logs-"
  # (AWS validation fails otherwise, even if the ARN looks correct).
  name        = "aws-waf-logs-${var.name_prefix}"
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = aws_kms_key.waf_logs.arn
  }

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose_waf.arn
    bucket_arn = aws_s3_bucket.waf_logs.arn

    prefix              = "waf-logs/"
    error_output_prefix = "waf-errors/"

    buffering_size     = 5
    buffering_interval = 300

    compression_format = "GZIP"
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-waf-firehose" })
}

resource "aws_wafv2_web_acl_logging_configuration" "alb" {
  resource_arn = aws_wafv2_web_acl.alb.arn

  log_destination_configs = [
    aws_kinesis_firehose_delivery_stream.waf.arn
  ]

  depends_on = [aws_wafv2_web_acl.alb]
}

# ------------------------------------------------------------
# ECS Cluster + Task + Service (Fargate)
# ------------------------------------------------------------
resource "aws_ecs_cluster" "this" {
  name = "${var.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-cluster" })
}

resource "aws_ecs_task_definition" "app" {
  family                   = "${var.name_prefix}-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = var.ecs_task_execution_role_arn
  task_role_arn            = var.ecs_task_role_arn

  container_definitions = jsonencode([
    {
      name      = "app"
      image     = "${var.ecr_repository_url}:${var.container_image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = var.app_port
          hostPort      = var.app_port
          protocol      = "tcp"
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.app.name
          awslogs-region        = data.aws_region.current.id
          awslogs-stream-prefix = "ecs"
        }
      }
      environment = [
        { name = "PORT", value = tostring(var.app_port) }
      ]
    }
  ])

  tags = merge(var.tags, { Name = "${var.name_prefix}-task" })
}

resource "aws_ecs_service" "app" {
  name            = "${var.name_prefix}-service"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "app"
    container_port   = var.app_port
  }

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  enable_ecs_managed_tags = true
  propagate_tags          = "SERVICE"

  depends_on = [
    aws_lb_listener.https
  ]

  tags = merge(var.tags, { Name = "${var.name_prefix}-service" })
}

# ----------------------------------------------------------
# Event notifications for waf_logs_access bucket (CKV2_AWS_62)
# ------------------------------------------------------------
resource "aws_s3_bucket_notification" "waf_logs_access" {
  bucket = aws_s3_bucket.waf_logs_access.id

  topic {
    topic_arn = aws_sns_topic.waf_bucket_events.arn
    events    = ["s3:ObjectCreated:*"]
  }
}
