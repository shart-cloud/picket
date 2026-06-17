resource "google_service_account" "forwarder" {
  project      = var.project_id
  account_id   = substr("${var.name_prefix}-${substr(sha1(var.cluster_name), 0, 8)}", 0, 30)
  display_name = "picket GKE audit forwarder (${var.cluster_name})"
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
