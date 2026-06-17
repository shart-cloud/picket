terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.100" }
  }
}

provider "azurerm" {
  features {}
}

module "aks" {
  source  = "Azure/aks/azurerm"
  version = "~> 9.0"

  resource_group_name = "rg-prod-eus"
  cluster_name        = "aks-prod-eus"
  prefix              = "prod"
  location            = "eastus"

  # AKS audit goes through diagnostic settings, not a cluster-level toggle —
  # so nothing special is required on the cluster itself.
}

module "picket_audit_forwarder" {
  source = "../.."

  resource_group_name = "rg-prod-eus"
  cluster_name        = module.aks.aks_name

  ingest_url   = "https://k8s-audit.picket.example"
  ingest_token = var.picket_ingest_token

  depends_on = [module.aks]
}

variable "picket_ingest_token" {
  type      = string
  sensitive = true
}

output "forwarder_function_name" {
  value = module.picket_audit_forwarder.function_app_name
}
