terraform {
  required_version = ">= 1.9, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.70.0"
    }
  }
}

provider "aws" {
  region              = var.home_region
  allowed_account_ids = [var.management_account_id]
  default_tags {
    tags = { Project = "AWS Security and Governance Hardening Lab", ManagedBy = "Terraform" }
  }
}
