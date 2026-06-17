output "namespace" {
  description = "Namespace where the Fluent Bit DaemonSet is installed."
  value       = var.namespace
}

output "release_name" {
  description = "Helm release name for the Fluent Bit audit forwarder."
  value       = helm_release.fluent_bit.name
}

output "ingest_secret_name" {
  description = "Name of the Kubernetes secret holding the ingestion bearer token."
  value       = kubernetes_secret_v1.ingest.metadata[0].name
}
