terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.100" }
  }
}

provider "azurerm" {
  features {}
}

module "audit_eus" {
  source = "../.."

  resource_group_name = "rg-prod-eus"
  cluster_name        = "aks-prod-eus"

  ingest_url   = var.ingest_url
  ingest_token = var.ingest_token
}

module "audit_weu" {
  source = "../.."

  resource_group_name = "rg-prod-weu"
  cluster_name        = "aks-prod-weu"

  ingest_url   = var.ingest_url
  ingest_token = var.ingest_token
}

variable "ingest_url" { type = string }
variable "ingest_token" {
  type      = string
  sensitive = true
}
