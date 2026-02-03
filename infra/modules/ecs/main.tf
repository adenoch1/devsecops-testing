############################################
# ECS + ALB Module
############################################

# -----------------------------
# Security Group for ALB
# -----------------------------
resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb-sg"
  description = "ALB security group"
  vpc_id      = var.vpc_id

  ingress {
    description      = "HTTPS from allowed CIDRs"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = var.allowed_ingress_cidrs
    ipv6_cidr_blocks = var.allowed_ingress_ipv6_cidrs
  }

  egress {
    description = "Outbound all (ALB needs health checks / targets / integrations)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-alb-sg"
  })
}

# -----------------------------
# Security Group for ECS tasks
# -----------------------------
resource "aws_security_group" "ecs" {
  name        = "${var.name_prefix}-ecs-sg"
  description = "ECS tasks security group"
  vpc_id      = var.vpc_id

  ingress {
    description     = "App port from ALB SG only"
    from_port       = var.app_port
    to_port         = var.app_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Outbound HTTPS only (tasks)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ecs-sg"
  })
}

# -----------------------------
# ALB
# -----------------------------
#checkov:skip=CKV2_AWS_76: "WAFv2 WebACL with AWS managed rules is attached in this module; CKV2_AWS_76 may false-positive depending on graph evaluation."
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
# Target Group
# -----------------------------
resource "aws_lb_target_group" "this" {
  name        = "${var.name_prefix}-tg"
  port        = var.app_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    path                = var.health_check_path
    protocol            = "HTTP"
    matcher             = "200-399"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-tg"
  })
}

# -----------------------------
# HTTPS Listener
# -----------------------------
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-https-listener"
  })
}

# -----------------------------
# WAF Log Group
# -----------------------------
resource "aws_cloudwatch_log_group" "waf" {
  name              = "/aws/wafv2/${var.name_prefix}-alb"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-waf-logs"
  })
}

# -----------------------------
# WAFv2 Web ACL
# -----------------------------
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

  # Common protections
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

  # Known bad inputs (Log4j-related coverage)
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

# Enable WAF logging
resource "aws_wafv2_web_acl_logging_configuration" "this" {
  resource_arn = aws_wafv2_web_acl.this.arn

  log_destination_configs = [
    aws_cloudwatch_log_group.waf.arn
  ]

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
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
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
      environment = [
        {
          name  = "ENVIRONMENT"
          value = var.environment_name
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = var.ecs_log_group_name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "app"
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
  name            = "${var.name_prefix}-service"
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
    target_group_arn = aws_lb_target_group.this.arn
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
