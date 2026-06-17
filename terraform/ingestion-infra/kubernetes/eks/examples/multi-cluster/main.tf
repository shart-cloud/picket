terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.40" }
  }
}

provider "aws" {
  alias  = "use1"
  region = "us-east-1"
}

provider "aws" {
  alias  = "euw1"
  region = "eu-west-1"
}

module "audit_use1" {
  source    = "../.."
  providers = { aws = aws.use1 }

  cluster_name = "prod-use1"
  ingest_url   = var.ingest_url
  ingest_token = var.ingest_token
}

module "audit_euw1" {
  source    = "../.."
  providers = { aws = aws.euw1 }

  cluster_name = "prod-euw1"
  ingest_url   = var.ingest_url
  ingest_token = var.ingest_token
}

variable "ingest_url" { type = string }
variable "ingest_token" {
  type      = string
  sensitive = true
}
