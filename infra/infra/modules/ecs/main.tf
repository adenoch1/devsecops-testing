data "aws_region" "current" {}

# ----------------------------------
# CloudWatch Logs (encrypted with KMS)
# ----------------------------------
resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${var.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.cloudwatch_logs_kms_key_arn

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-logs"
  })
}

# -----------------------------
# Security Groups
# -----------------------------
#tfsec:ignore:aws-ec2-no-public-ingress-sgr  # Public HTTPS (443) is required for the demo ALB
resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb-sg"
  description = "ALB security group"
  vpc_id      = var.vpc_id

  ingress {
    description      = "HTTPS from internet"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
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

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ecs-sg"
  })
}

# ALB egress: only to ECS tasks on app port
resource "aws_security_group_rule" "alb_to_ecs_app_port" {
  type                     = "egress"
  description              = "ALB to ECS tasks on app port"
  security_group_id        = aws_security_group.alb.id
  from_port                = var.app_port
  to_port                  = var.app_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
}

# ECS tasks egress: HTTPS only (for pulling images, talking to AWS APIs, etc.)
#tfsec:ignore:aws-ec2-no-public-egress-sgr  # Egress HTTPS required for AWS APIs / ECR pulls (can be tightened with VPC endpoints)
resource "aws_security_group_rule" "ecs_egress_https" {
  type              = "egress"
  description       = "ECS tasks outbound HTTPS only"
  security_group_id = aws_security_group.ecs.id
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
}

# -----------------------------
# Application Load Balancer (HTTPS enforced)
# -----------------------------
#tfsec:ignore:aws-elb-alb-not-public  # This environment uses a public ALB; WAF is attached below
resource "aws_lb" "this" {
  name                       = "${var.name_prefix}-alb"
  load_balancer_type         = "application"
  internal                   = false
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


# -----------------------------
# WAFv2 Web ACL (managed rules)
# - Satisfies Checkov CKV2_AWS_76 by attaching a WebACL to the ALB
# - Includes AWS Managed Rules that cover common exploits (including Log4j patterns)
# -----------------------------
resource "aws_wafv2_web_acl" "alb" {
  name  = "${var.name_prefix}-alb-web-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # AWS managed rules (Common)
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
      metric_name                = "${var.name_prefix}-waf-common"
      sampled_requests_enabled   = true
    }
  }

  # AWS managed rules (Known Bad Inputs) - includes protections for known exploit payloads
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
      metric_name                = "${var.name_prefix}-waf-knownbad"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-waf"
    sampled_requests_enabled   = true
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-alb-web-acl"
  })
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.this.arn
  web_acl_arn  = aws_wafv2_web_acl.alb.arn
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

# -----------------------------
# WAFv2 (with Log4j/AMR coverage + Logging)
# -----------------------------

# CloudWatch log group for WAF logs (satisfies WAF logging requirement)
resource "aws_cloudwatch_log_group" "waf" {
  name              = "/aws/wafv2/${var.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.cloudwatch_logs_kms_key_arn

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-waf-logs"
  })
}

resource "aws_wafv2_web_acl" "this" {
  name  = "${var.name_prefix}-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-waf"
    sampled_requests_enabled   = true
  }

  # Common protections (XSS, size limits, bad bots patterns, etc.)
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
      metric_name                = "CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Known bad inputs (helps satisfy Log4j/AMR-related checks)
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

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
      metric_name                = "KnownBadInputs"
      sampled_requests_enabled   = true
    }
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-waf"
  })
}

# Attach WAF to the ALB
resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.this.arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

# Enable WAF logging (Checkov CKV2_AWS_31)
resource "aws_wafv2_web_acl_logging_configuration" "this" {
  resource_arn = aws_wafv2_web_acl.this.arn

  log_destination_configs = [
    aws_cloudwatch_log_group.waf.arn
  ]

  # Optional: redact sensitive headers
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
}

# -----------------------------
# ECS Cluster
# -----------------------------
resource "aws_ecs_cluster" "this" {
  name = "${var.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-cluster"
  })
}

# -----------------------------
# ECS Task Definition
# -----------------------------
resource "aws_ecs_task_definition" "this" {
  family                   = "${var.name_prefix}-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.task_cpu)
  memory                   = tostring(var.task_memory)

  execution_role_arn = var.ecs_task_execution_role_arn
  task_role_arn      = var.ecs_task_role_arn

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

      environment = [
        { name = "FLASK_ENV", value = "production" }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.app.name
          awslogs-region        = data.aws_region.current.id
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-taskdef"
  })
}

# -----------------------------
# ECS Service
# -----------------------------
resource "aws_ecs_service" "this" {
  name            = "${var.name_prefix}-svc"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
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

  depends_on = [
    aws_lb_listener.https,
    aws_wafv2_web_acl_association.alb,
    aws_wafv2_web_acl_logging_configuration.this
  ]

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-service"
  })
}
