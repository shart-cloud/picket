terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.40" }
  }
}

provider "aws" {
  region = "us-east-1"
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = "my-prod-cluster"
  cluster_version = "1.30"

  vpc_id     = "vpc-xxxxxxxx"
  subnet_ids = ["subnet-aaa", "subnet-bbb", "subnet-ccc"]

  cluster_enabled_log_types = ["audit", "authenticator", "api"]

  eks_managed_node_groups = {
    default = {
      min_size     = 2
      max_size     = 5
      desired_size = 3
    }
  }
}

module "picket_audit_forwarder" {
  source = "../.."

  cluster_name = module.eks.cluster_name
  ingest_url   = "https://k8s-audit.picket.example"
  ingest_token = var.picket_ingest_token

  depends_on = [module.eks]
}

variable "picket_ingest_token" {
  type      = string
  sensitive = true
}

output "forwarder_lambda_arn" {
  value = module.picket_audit_forwarder.lambda_function_arn
}
