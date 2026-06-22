output "r2_bucket_name" {
  description = "R2 bucket name for the picket lake."
  value       = cloudflare_r2_bucket.lake.name
}

output "d1_database_id" {
  description = "D1 database ID for alert state."
  value       = cloudflare_d1_database.alert_state.id
}

output "auth_d1_database_id" {
  description = "D1 database ID for picket-auth (api keys, better-auth schema)."
  value       = cloudflare_d1_database.picket_auth.id
}

output "alert_queue_name" {
  description = "Cloudflare Queue name for alert fanout."
  value       = cloudflare_queue.alerts.queue_name
}

output "kv_namespace_id" {
  description = "Workers KV namespace ID for config and enrichment."
  value       = cloudflare_workers_kv_namespace.config.id
}

output "r2_catalog_warehouse" {
  description = "R2 SQL warehouse identifier (`<account_id>_<bucket_name>`). Set as PICKET_R2_WAREHOUSE for the CLI / pass via --warehouse."
  value       = "${var.cloudflare_account_id}_${cloudflare_r2_bucket.lake.name}"
}

output "r2_catalog_uri" {
  description = "Iceberg REST catalog URI for clients that talk to the catalog directly (PyIceberg, Spark, etc.)."
  value       = "https://${var.cloudflare_account_id}.r2.cloudflarestorage.com/iceberg/${cloudflare_r2_bucket.lake.name}"
}

output "pipeline_ids" {
  description = "Map of source key → pipeline ID. Reference these IDs from `wrangler.jsonc` pipelines bindings if you bind by ID instead of name."
  value       = { for k, p in cloudflare_pipeline.flow : k => p.id }
}

output "pipeline_names" {
  description = "Map of source key → pipeline name. Cloudflare normalizes hyphens to underscores at apply time."
  value       = { for k, p in cloudflare_pipeline.flow : k => p.name }
}

output "stream_ids" {
  description = <<EOT
Map of source key → stream ID. These IDs are what `workers/*/wrangler.jsonc`
`pipelines[].pipeline` fields need — Worker pipeline bindings reject stream
names and pipeline names, so always use the ID. After `terraform apply`, run
`pnpm gen:wrangler` to substitute these into the generated wrangler configs.
EOT
  value       = { for k, s in cloudflare_pipeline_stream.source : k => s.id }
}

output "stream_names" {
  description = "Map of source key → stream name (informational only; bindings need stream_ids)."
  value       = { for k, s in cloudflare_pipeline_stream.source : k => s.name }
}

output "cf_access_team_domain" {
  description = "Zero Trust team auth domain (e.g. `yourteam.cloudflareaccess.com`). Consumed by `pnpm gen:wrangler` as admin vars.CF_ACCESS_TEAM_DOMAIN."
  value       = data.cloudflare_zero_trust_organization.this.auth_domain
}

output "cf_access_aud" {
  description = "AUD claim of the picket-admin Access application. Null until `picket_admin_worker_deployed = true`. Consumed by `pnpm gen:wrangler` as admin vars.CF_ACCESS_AUD once populated."
  value       = length(cloudflare_zero_trust_access_application.picket_admin) == 0 ? null : cloudflare_zero_trust_access_application.picket_admin[0].aud
}

output "picket_admin_access_app_id" {
  description = "ID of the picket-admin Access application. Null until `picket_admin_worker_deployed = true`."
  value       = length(cloudflare_zero_trust_access_application.picket_admin) == 0 ? null : cloudflare_zero_trust_access_application.picket_admin[0].id
}

output "r2_catalog_table_suffix" {
  description = "Random suffix appended to the Iceberg table names (workaround for CF Pipelines open-beta 1012 cache bug). Pass to the CLI as --table-suffix or via PICKET_TABLE_SUFFIX so preset queries hit the right tables."
  value       = local.table_suffix
}

output "picket_admin_url" {
  description = "Public URL for picket-admin. Live once `picket_admin_worker_deployed = true`."
  value       = "https://${var.picket_admin_domain}"
}

output "picket_ingest_url" {
  description = "Public URL for picket-ingest. Forwarders POST to this URL with x-api-key; no Cloudflare Access token is required."
  value       = "https://${var.picket_ingest_domain}"
}
