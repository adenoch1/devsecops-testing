locals {
  tags = {
    Project     = var.project
    Environment = var.environment
    Owner       = var.owner
    ManagedBy   = "Terraform"
  }

  name_prefix = "${var.project}-${var.environment}"
}

module "logging" {
  source      = "../../modules/logging"
  name_prefix = local.name_prefix
  tags        = local.tags

  alb_log_prefix = var.alb_log_prefix

  # Security hardening controls (these should exist as variables in the logging module)
  lifecycle_expire_days  = var.lifecycle_expire_days
  lifecycle_glacier_days = var.lifecycle_glacier_days

  # Replication is OPTIONAL (set replication_enabled=false in tfvars if you don't want it)
  replication_enabled = var.replication_enabled
  replication_region  = var.replication_region

  # Only needed if your logging module uses aws.replica provider for replication resources.
  # Keep this if you have provider "aws" { alias = "replica" ... } in providers.tf
  providers = {
    aws         = aws
    aws.replica = aws.replica
  }
}

module "network" {
  source      = "../../modules/network"
  name_prefix = local.name_prefix
  vpc_cidr    = var.vpc_cidr
  tags        = local.tags

  flow_log_retention_days     = var.flow_log_retention_days
  cloudwatch_logs_kms_key_arn = module.logging.cloudwatch_logs_kms_key_arn
}

module "ecr" {
  source      = "../../modules/ecr"
  name_prefix = local.name_prefix
  tags        = local.tags
}

module "iam" {
  source      = "../../modules/iam"
  name_prefix = local.name_prefix
  tags        = local.tags
}

module "ecs" {
  source      = "../../modules/ecs"
  name_prefix = local.name_prefix
  tags        = local.tags

  vpc_id             = module.network.vpc_id
  public_subnet_ids  = module.network.public_subnet_ids
  private_subnet_ids = module.network.private_subnet_ids

  ecr_repository_url = module.ecr.repository_url

  ecs_task_execution_role_arn = module.iam.ecs_task_execution_role_arn
  ecs_task_role_arn           = module.iam.ecs_task_role_arn

  app_port            = var.app_port
  container_image_tag = var.container_image_tag

  desired_count = var.desired_count
  task_cpu      = var.task_cpu
  task_memory   = var.task_memory

  # Week 3 hardening
  acm_certificate_arn         = var.acm_certificate_arn
  alb_log_bucket_name         = module.logging.alb_logs_bucket_name
  alb_log_prefix              = var.alb_log_prefix
  cloudwatch_logs_kms_key_arn = module.logging.cloudwatch_logs_kms_key_arn
  log_retention_days          = var.log_retention_days
}
