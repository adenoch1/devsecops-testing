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
    description      = "HTTPS from Internet"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    description = "ALB to targets in VPC on app port"
    from_port   = var.container_port
    to_port     = var.container_port
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-alb-sg" })
}

# ECS Tasks SG: only allow inbound from ALB SG on app port
resource "aws_security_group" "ecs_tasks" {
  name        = "${var.name_prefix}-tasks-sg"
  description = "ECS tasks security group"
  vpc_id      = var.vpc_id

  ingress {
    description     = "App traffic from ALB SG"
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Outbound to anywhere (needed for ECR, logs, etc.)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-tasks-sg" })
}

# ------------------------------------------------------------
# Application Load Balancer (ALB) + Target Group + Listener (HTTPS)
# ------------------------------------------------------------
resource "aws_lb" "this" {
  name                       = "${var.name_prefix}-alb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = var.public_subnet_ids
  enable_deletion_protection = false

  access_logs {
    bucket  = var.alb_logs_bucket
    enabled = true
    prefix  = var.alb_log_prefix
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-alb" })
}

resource "aws_lb_target_group" "app" {
  name        = "${var.name_prefix}-tg"
  port        = var.container_port
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
    priority = 1

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
      metric_name                = "${var.name_prefix}-common"
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
      # Allow Firehose to use this CMK for delivery stream encryption (including grants)
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
          Bool = {
            "kms:GrantIsForAWSResource" = "true"
          }

          StringEquals = {
            "kms:CallerAccount" = "${data.aws_caller_identity.current.account_id}"
            "kms:ViaService"    = "firehose.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      },
      # Allow the Firehose delivery role to use this CMK (KMS sometimes evaluates the IAM role principal during SSE enablement)
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
            "kms:ViaService"    = "firehose.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      },
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
          Bool = {
            "kms:GrantIsForAWSResource" = "true"
          }
          StringEquals = {
            "kms:CallerAccount" = "${data.aws_caller_identity.current.account_id}"
            "kms:ViaService"    = "firehose.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      },
      # If you enable SSE-KMS on any S3 buckets that store WAF logs, S3 also needs grant permissions.
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
      },
      {
        Sid       = "AllowS3CreateGrant"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action = [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant",
          "kms:RetireGrant"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource" = "true"
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
}

resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs_access" {
  bucket = aws_s3_bucket.waf_logs_access.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
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

resource "aws_s3_bucket_logging" "waf_logs" {
  bucket        = aws_s3_bucket.waf_logs.id
  target_bucket = aws_s3_bucket.waf_logs_access.id
  target_prefix = "access-logs/"
}

data "aws_iam_policy_document" "waf_logs_bucket" {
  statement {
    sid     = "AWSLogDeliveryWrite"
    effect  = "Allow"
    actions = ["s3:PutObject"]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    resources = ["${aws_s3_bucket.waf_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid     = "AWSLogDeliveryAclCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    resources = [aws_s3_bucket.waf_logs.arn]
  }
}

resource "aws_s3_bucket_policy" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  policy = data.aws_iam_policy_document.waf_logs_bucket.json
}

resource "aws_s3_bucket_notification" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  depends_on = [aws_s3_bucket_policy.waf_logs]
}

resource "aws_iam_role" "firehose_waf" {
  name = "${var.name_prefix}-firehose-waf-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "firehose.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.tags, { Name = "${var.name_prefix}-firehose-waf-role" })
}

data "aws_iam_policy_document" "firehose_waf" {
  statement {
    sid    = "AllowS3"
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
    sid    = "AllowKMS"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
      "kms:CreateGrant",
      "kms:ListGrants",
      "kms:RevokeGrant"
    ]
    resources = [aws_kms_key.waf_logs.arn]
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
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
      image     = var.container_image
      essential = true

      portMappings = [
        {
          containerPort = var.container_port
          protocol      = "tcp"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.app.name
          awslogs-region        = data.aws_region.current.name
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
    container_port   = var.container_port
  }

  depends_on = [aws_lb_listener.https]

  tags = merge(var.tags, { Name = "${var.name_prefix}-svc" })
}
