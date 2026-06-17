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

module "gke" {
  source  = "terraform-google-modules/kubernetes-engine/google"
  version = "~> 31.0"

  project_id        = "my-prod-project"
  name              = "prod-usc1"
  region            = "us-central1"
  network           = "default"
  subnetwork        = "default"
  ip_range_pods     = "pods"
  ip_range_services = "services"
}

module "picket_audit_forwarder" {
  source = "../.."

  project_id       = "my-prod-project"
  cluster_name     = module.gke.name
  cluster_location = module.gke.location
  region           = "us-central1"

  ingest_url   = "https://k8s-audit.picket.example"
  ingest_token = var.picket_ingest_token

  depends_on = [module.gke]
}

variable "picket_ingest_token" {
  type      = string
  sensitive = true
}

output "forwarder_function_name" {
  value = module.picket_audit_forwarder.function_name
}
