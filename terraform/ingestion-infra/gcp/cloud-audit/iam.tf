resource "google_service_account" "forwarder" {
  project      = var.project_id
  account_id   = substr("${var.name_prefix}-${local.instance_suffix}", 0, 30)
  display_name = "picket GCP Cloud Audit forwarder"
}

resource "google_secret_manager_secret" "ingest_token" {
  project   = var.project_id
  secret_id = local.resource_name
  labels    = local.common_labels

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "ingest_token" {
  secret      = google_secret_manager_secret.ingest_token.id
  secret_data = var.ingest_token
}

resource "google_secret_manager_secret_iam_member" "forwarder_accessor" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.ingest_token.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.forwarder.email}"
}
