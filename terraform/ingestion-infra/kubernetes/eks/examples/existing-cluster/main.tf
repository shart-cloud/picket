terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.40" }
  }
}

provider "aws" {
  region = "us-east-1"
}

module "picket_audit_forwarder" {
  source = "../.."

  cluster_name = "prod-use1"
  ingest_url   = "https://k8s-audit.picket.example"
  ingest_token = var.picket_ingest_token

  forwarded_log_stream_prefixes = [
    "kube-apiserver-audit-",
    "authenticator-",
  ]

  tags = {
    Environment = "prod"
    Owner       = "security"
  }
}

variable "picket_ingest_token" {
  type      = string
  sensitive = true
}
