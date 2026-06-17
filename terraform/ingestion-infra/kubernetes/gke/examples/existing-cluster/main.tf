terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = { source = "hashicorp/google", version = ">= 5.30" }
  }
}

provider "google" {
  project = "my-prod-project"
  region  = "us-central1"
}

module "picket_audit_forwarder" {
  source = "../.."

  project_id       = "my-prod-project"
  cluster_name     = "prod-usc1"
  cluster_location = "us-central1"

  ingest_url   = "https://k8s-audit.picket.example"
  ingest_token = var.picket_ingest_token

  include_data_access_logs = false

  labels = {
    environment = "prod"
    owner       = "security"
  }
}

variable "picket_ingest_token" {
  type      = string
  sensitive = true
}
