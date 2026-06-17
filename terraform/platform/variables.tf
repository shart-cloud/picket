variable "cloudflare_account_id" {
  description = "Cloudflare account ID where picket resources will be created."
  type        = string
}

variable "cloudflare_api_token" {
  description = "Cloudflare API token used by the Terraform provider. Set with TF_VAR_cloudflare_api_token or provider-specific environment configuration; do not commit it in terraform.tfvars."
  type        = string
  sensitive   = true
}

variable "name_prefix" {
  description = "Prefix used for Cloudflare resource names."
  type        = string
  default     = "picket"
}

variable "r2_bucket_name" {
  description = "R2 bucket name for the future event lake."
  type        = string
  default     = "picket-lake"
}

variable "d1_database_name" {
  description = "D1 database name for mutable alert state."
  type        = string
  default     = "picket-alert-state"
}

variable "auth_d1_database_name" {
  description = "D1 database name for picket-ingest / picket-admin authentication (better-auth schema, api keys)."
  type        = string
  default     = "picket-auth"
}

variable "alert_queue_name" {
  description = "Cloudflare Queue name for alert fanout."
  type        = string
  default     = "picket-alerts"
}

variable "query_jobs_queue_name" {
  description = "Cloudflare Queue name for async R2 SQL query jobs. picket-admin produces, picket-query-runner consumes."
  type        = string
  default     = "picket-query-jobs"
}

variable "kv_namespace_title" {
  description = "Workers KV namespace title for configuration and enrichment data."
  type        = string
  default     = "picket-config"
}

variable "r2_catalog_namespace" {
  description = "Iceberg namespace inside the R2 Data Catalog for picket tables."
  type        = string
  default     = "default"
}

variable "r2_catalog_token" {
  description = <<EOT
R2 API token used by Cloudflare Pipelines sinks to authenticate against the
R2 Data Catalog. Requires "R2 Admin Read & Write" (or catalog-write +
storage-write permission groups). Create via dashboard → R2 → Manage R2 API
Tokens. This token is consumed by the pipelines themselves, not by callers
of R2 SQL — query callers use WRANGLER_R2_SQL_AUTH_TOKEN separately.
EOT
  type        = string
  sensitive   = true
}

variable "pipeline_roll_interval_seconds" {
  description = "How often pipeline sinks roll over to a new Iceberg file. Lower = lower query latency and more files; higher = better compression and slower visibility."
  type        = number
  default     = 60
}

variable "picket_admin_domain" {
  description = "Public hostname for picket-admin. Must be on a Cloudflare zone attached to this account — terraform looks up the parent zone and attaches a Workers Custom Domain to the picket-admin Worker."
  type        = string
  default     = "picket.shart.cloud"
}

variable "picket_admin_zone_name" {
  description = "Cloudflare zone that owns `picket_admin_domain` (the registrable apex). The zone must already exist on this account."
  type        = string
  default     = "shart.cloud"
}

variable "picket_ingest_domain" {
  description = "Public hostname for picket-ingest. This endpoint is not behind Cloudflare Access; it authenticates machine forwarders with x-api-key."
  type        = string
  default     = "ingest.shart.cloud"
}

variable "picket_ingest_zone_name" {
  description = "Cloudflare zone that owns `picket_ingest_domain` (the registrable apex)."
  type        = string
  default     = "shart.cloud"
}

variable "picket_admin_allowed_emails" {
  description = "Emails allowed to access picket-admin. Each gets an Access policy `include.email` rule. Leave empty when using GitHub org access only."
  type        = list(string)
  default     = []
}

variable "picket_admin_github_identity_provider_id" {
  description = "Cloudflare Access GitHub identity provider ID used to allow GitHub org members into picket-admin. Create the GitHub login method in Zero Trust, then paste its ID here."
  type        = string

  validation {
    condition     = var.picket_admin_github_identity_provider_id != ""
    error_message = "Set picket_admin_github_identity_provider_id to the Cloudflare Access GitHub identity provider ID."
  }
}

variable "picket_admin_github_org" {
  description = "GitHub organization allowed to access picket-admin through Cloudflare Access."
  type        = string
  default     = "shart-cloud"
}

variable "picket_admin_github_teams" {
  description = "Optional GitHub team display names inside picket_admin_github_org allowed to access picket-admin. Empty allows any org member."
  type        = list(string)
  default     = []
}

variable "picket_admin_worker_deployed" {
  description = <<EOT
Flag for the picket-admin chicken-and-egg. Stage 1 (false, default): infra
only — the custom domain and Access app are skipped. Stage 2 (true): set
after `pnpm deploy:cloudflare` has put the picket-admin Worker in place, so
`cloudflare_workers_custom_domain` can attach to it and the Access app can
go live on `picket_admin_domain`.
EOT
  type        = bool
  default     = true
}

variable "picket_admin_session_duration" {
  description = "How long an Access session lasts before re-authentication. Format examples: `30m`, `12h`, `24h`."
  type        = string
  default     = "24h"
}
