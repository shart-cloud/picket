output "logpush_job_id" {
  description = "Cloudflare Logpush job ID for Audit Logs v2."
  value       = cloudflare_logpush_job.audit_logs.id
}

output "destination_url" {
  description = "Picket ingest URL used by the Logpush job, without sensitive header query parameters."
  value       = local.ingest_events_url
}
