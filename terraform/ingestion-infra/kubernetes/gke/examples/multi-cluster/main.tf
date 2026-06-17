terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = { source = "hashicorp/google", version = ">= 5.30" }
  }
}

provider "google" {
  alias   = "usc1"
  project = "my-prod-project"
  region  = "us-central1"
}

provider "google" {
  alias   = "euw1"
  project = "my-prod-project"
  region  = "europe-west1"
}

module "audit_usc1" {
  source    = "../.."
  providers = { google = google.usc1 }

  project_id       = "my-prod-project"
  cluster_name     = "prod-usc1"
  cluster_location = "us-central1"
  region           = "us-central1"

  ingest_url   = var.ingest_url
  ingest_token = var.ingest_token
}

module "audit_euw1" {
  source    = "../.."
  providers = { google = google.euw1 }

  project_id       = "my-prod-project"
  cluster_name     = "prod-euw1"
  cluster_location = "europe-west1"
  region           = "europe-west1"

  ingest_url   = var.ingest_url
  ingest_token = var.ingest_token
}

variable "ingest_url" { type = string }
variable "ingest_token" {
  type      = string
  sensitive = true
}
