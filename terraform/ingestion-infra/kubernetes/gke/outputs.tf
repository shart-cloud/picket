output "pubsub_topic" {
  description = "Pub/Sub topic that receives the GKE audit log sink."
  value       = google_pubsub_topic.audit.id
}

output "log_sink_name" {
  description = "Cloud Logging sink name."
  value       = google_logging_project_sink.audit.name
}

output "log_sink_filter" {
  description = "Effective Cloud Logging filter applied by the sink."
  value       = google_logging_project_sink.audit.filter
}

output "function_name" {
  description = "Cloud Function name."
  value       = google_cloudfunctions2_function.forwarder.name
}

output "function_service_account" {
  description = "Service account email assumed by the forwarder Cloud Function."
  value       = google_service_account.forwarder.email
}

output "ingest_token_secret_id" {
  description = "Secret Manager secret ID storing the ingestion bearer token."
  value       = google_secret_manager_secret.ingest_token.secret_id
}
