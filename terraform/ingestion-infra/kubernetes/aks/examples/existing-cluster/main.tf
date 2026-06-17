terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.100" }
  }
}

provider "azurerm" {
  features {}
}

module "picket_audit_forwarder" {
  source = "../.."

  resource_group_name = "rg-prod-eus"
  cluster_name        = "aks-prod-eus"

  ingest_url   = "https://k8s-audit.picket.example"
  ingest_token = var.picket_ingest_token

  include_kube_audit_admin = true
  include_kube_audit       = false

  tags = {
    environment = "prod"
    owner       = "security"
  }
}

variable "picket_ingest_token" {
  type      = string
  sensitive = true
}
