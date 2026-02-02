terraform {
  backend "s3" {
    bucket         = "devsecops-project1-tfstate-ca-central-1"
    key            = "dev/envs/dev/terraform.tfstate"
    region         = "ca-central-1"
    dynamodb_table = "devsecops-project1-tflocks"
    encrypt        = true
  }
}
