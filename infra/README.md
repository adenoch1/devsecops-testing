# Week 2 - Terraform AWS Infra (ECS Fargate)

## What this creates
- VPC (2 AZs)
- Public subnets (ALB + NAT)
- Private subnets (ECS tasks)
- IGW + NAT + routes
- ECR repository (scan on push)
- IAM roles for ECS tasks
- ECS Fargate cluster/service + ALB
- CloudWatch logs for containers

## Run it
```bash
cd infra/envs/dev
terraform init
terraform fmt -recursive
terraform validate
terraform plan
terraform apply
