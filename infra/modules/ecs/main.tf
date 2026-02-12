############################################################
# ECS MODULE - main.tf (FULL, updated for remaining Checkov)
# Fixes:
# - CKV2_AWS_61: add lifecycle configuration to waf_logs_access bucket
# - CKV_AWS_145: encrypt waf_logs_access bucket with KMS by default
############################################################

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  app_port        = var.app_port
  container_image = "${var.ecr_repository_url}:${var.container_image_tag}"
}

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
# ALB SG: internet ingress 443, egress restricted to VPC CIDR on app port
#tfsec:ignore:aws-ec2-no-public-ingress-sgr
resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb-sg"
  description = "ALB security group"
  vpc_id      = var.vpc_id

  ingress {
    description      = "HTTPS from Internet"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    description = "ALB to targets in VPC on app port"
    from_port   = local.app_port
    to_port     = local.app_port
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-alb-sg" })
}

resource "aws_security_group" "ecs_tasks" {
  name        = "${var.name_prefix}-tasks-sg"
  description = "ECS tasks security group"
  vpc_id      = var.vpc_id

  ingress {
    description     = "App traffic from ALB SG"
    from_port       = local.app_port
    to_port         = local.app_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "DNS to VPC"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "DNS to VPC (tcp fallback)"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "HTTPS to VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-tasks-sg" })
}

# ------------------------------------------------------------
# Application Load Balancer (ALB) + Target Group + Listener (HTTPS)
# ------------------------------------------------------------

# Public ALB is intentional in this project (internet-facing entrypoint)
#tfsec:ignore:aws-0053
resource "aws_lb" "this" {
  name               = "${var.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  enable_deletion_protection = true
  drop_invalid_header_fields = true

  access_logs {
    bucket  = var.alb_log_bucket_name
    enabled = true
    prefix  = var.alb_log_prefix
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-alb" })
}

resource "aws_lb_target_group" "app" {
  name        = "${var.name_prefix}-tg"
  port        = local.app_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  health_check {
    enabled             = true
    path                = var.health_check_path
    matcher             = "200-399"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-tg" })
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

  tags = merge(var.tags, { Name = "${var.name_prefix}-https-listener" })
}

# ------------------------------------------------------------
# WAFv2 (ALB) - Managed Rules
# ------------------------------------------------------------
resource "aws_wafv2_web_acl" "alb" {
  name        = "${var.name_prefix}-waf"
  description = "WAF for ALB"
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
# WAF Logging: Firehose -> S3 (encrypted)
# ------------------------------------------------------------

# KMS key for S3 buckets (waf logs + access logs) to satisfy CKV_AWS_145
resource "aws_kms_key" "s3_logs" {
  description             = "KMS CMK for S3 logging buckets (WAF logs + access logs)"
  deletion_window_in_days = 7
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

  tags = merge(var.tags, { Name = "${var.name_prefix}-s3-logs-kms" })
}

resource "aws_kms_alias" "s3_logs" {
  name          = "alias/${var.name_prefix}-s3-logs"
  target_key_id = aws_kms_key.s3_logs.key_id
}

# Access logs bucket for WAF logs bucket
resource "aws_s3_bucket" "waf_logs_access" {
  bucket        = "${var.name_prefix}-waf-logs-access-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-waf-logs-access"
  })
}

resource "aws_s3_bucket_public_access_block" "waf_logs_access" {
  bucket                  = aws_s3_bucket.waf_logs_access.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "waf_logs_access" {
  bucket = aws_s3_bucket.waf_logs_access.id
  versioning_configuration {
    status = "Enabled"
  }
}

# CKV_AWS_145: KMS encryption by default (not AES256)
resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs_access" {
  bucket = aws_s3_bucket.waf_logs_access.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_logs.arn
    }
  }
}

# CKV2_AWS_61: lifecycle for access logs bucket (keep it short)
resource "aws_s3_bucket_lifecycle_configuration" "waf_logs_access" {
  bucket = aws_s3_bucket.waf_logs_access.id

  rule {
    id     = "access-logs-lifecycle"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = 30
    }
  }
}

# Main WAF logs bucket
resource "aws_s3_bucket" "waf_logs" {
  bucket        = "${var.name_prefix}-waf-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-waf-logs"
  })
}

resource "aws_s3_bucket_public_access_block" "waf_logs" {
  bucket                  = aws_s3_bucket.waf_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_logs.arn
    }
  }
}

# enable access logging on the WAF logs bucket
resource "aws_s3_bucket_logging" "waf_logs" {
  bucket        = aws_s3_bucket.waf_logs.id
  target_bucket = aws_s3_bucket.waf_logs_access.id
  target_prefix = "access-logs/"
}

resource "aws_s3_bucket_lifecycle_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    id     = "waf-logs-lifecycle"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = var.lifecycle_expire_days
    }

    transition {
      days          = var.lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }
}

# Firehose delivery + KMS for Firehose itself
resource "aws_iam_role" "firehose_waf" {
  name = "${var.name_prefix}-firehose-waf"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "firehose.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.tags, { Name = "${var.name_prefix}-firehose-waf-role" })
}

resource "aws_kms_key" "waf_logs" {
  description             = "KMS CMK for WAF logs (Firehose)"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "key-default-1"
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },

      # Firehose service principal (normal path)
      {
        Sid       = "AllowFirehoseServiceUseOfKey"
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
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = "${data.aws_caller_identity.current.account_id}"
            "kms:ViaService"    = "firehose.${data.aws_region.current.region}.amazonaws.com"
          }
        }
      },
      {
        Sid       = "AllowFirehoseCreateGrant"
        Effect    = "Allow"
        Principal = { Service = "firehose.amazonaws.com" }
        Action = [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant",
          "kms:RetireGrant"
        ]
        Resource = "*"
        Condition = {
          Bool = { "kms:GrantIsForAWSResource" = "true" }
          StringEquals = {
            "kms:CallerAccount" = "${data.aws_caller_identity.current.account_id}"
            "kms:ViaService"    = "firehose.${data.aws_region.current.region}.amazonaws.com"
          }
        }
      },

      # ✅ Firehose service principal (StartDeliveryStreamEncryption can be missing kms:ViaService)
      {
        Sid       = "AllowFirehoseServiceUseOfKeyNoViaService"
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
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = "${data.aws_caller_identity.current.account_id}"
          }
        }
      },
      {
        Sid       = "AllowFirehoseServiceCreateGrantNoViaService"
        Effect    = "Allow"
        Principal = { Service = "firehose.amazonaws.com" }
        Action = [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant",
          "kms:RetireGrant"
        ]
        Resource = "*"
        Condition = {
          Bool = { "kms:GrantIsForAWSResource" = "true" }
          StringEquals = {
            "kms:CallerAccount" = "${data.aws_caller_identity.current.account_id}"
          }
        }
      },

      # Firehose delivery role (allow use)
      {
        Sid       = "AllowFirehoseRoleUseOfKey"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.firehose_waf.arn }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = "${data.aws_caller_identity.current.account_id}"
          }
        }
      },

      # Firehose delivery role (allow grant management)
      {
        Sid       = "AllowFirehoseRoleCreateGrant"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.firehose_waf.arn }
        Action = [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant",
          "kms:RetireGrant"
        ]
        Resource = "*"
        Condition = {
          Bool = { "kms:GrantIsForAWSResource" = "true" }
          StringEquals = {
            "kms:CallerAccount" = "${data.aws_caller_identity.current.account_id}"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, { Name = "${var.name_prefix}-waf-logs-kms" })
}

resource "aws_kms_alias" "waf_logs" {
  name          = "alias/${var.name_prefix}-waf-logs"
  target_key_id = aws_kms_key.waf_logs.key_id
}

resource "aws_iam_role_policy" "firehose_waf" {
  name = "${var.name_prefix}-firehose-waf-policy"
  role = aws_iam_role.firehose_waf.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3Put"
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.waf_logs.arn,
          "${aws_s3_bucket.waf_logs.arn}/*"
        ]
      },
      {
        Sid    = "AllowKMS"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = [aws_kms_key.waf_logs.arn]
      }
    ]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "waf" {
  name        = "${var.name_prefix}-waf-logs"
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = aws_kms_key.waf_logs.arn
  }

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose_waf.arn
    bucket_arn          = aws_s3_bucket.waf_logs.arn
    prefix              = "waf-logs/!{timestamp:yyyy}/!{timestamp:MM}/!{timestamp:dd}/"
    error_output_prefix = "waf-logs-errors/!{firehose:error-output-type}/!{timestamp:yyyy}/!{timestamp:MM}/!{timestamp:dd}/"

    buffering_size     = 5
    buffering_interval = 300

    compression_format = "GZIP"
    kms_key_arn        = aws_kms_key.waf_logs.arn
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
      image     = local.container_image
      essential = true

      readonlyRootFilesystem = true

      portMappings = [
        {
          containerPort = local.app_port
          protocol      = "tcp"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.app.name
          awslogs-region        = data.aws_region.current.region
          awslogs-stream-prefix = "ecs"
        }
      }

      environment = var.container_environment
    }
  ])

  tags = merge(var.tags, { Name = "${var.name_prefix}-task" })
}

resource "aws_ecs_service" "app" {
  name            = "${var.name_prefix}-svc"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "app"
    container_port   = local.app_port
  }

  depends_on = [aws_lb_listener.https]

  tags = merge(var.tags, { Name = "${var.name_prefix}-svc" })
}
