output "pubsub_topic_id" {
  description = "Pub/Sub topic receiving Cloud Audit log entries."
  value       = google_pubsub_topic.audit.id
}

output "logging_sink_id" {
  description = "Cloud Logging sink forwarding Cloud Audit logs."
  value       = google_logging_project_sink.audit.id
}

output "forwarder_function_name" {
  description = "Cloud Function name for the forwarder."
  value       = google_cloudfunctions2_function.forwarder.name
}

output "forwarder_service_account_email" {
  description = "Service account used by the forwarder function."
  value       = google_service_account.forwarder.email
}

output "ingest_token_secret_id" {
  description = "Secret Manager secret ID storing the Picket ingest API key."
  value       = google_secret_manager_secret.ingest_token.id
}
