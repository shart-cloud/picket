variable "project_id" {
  description = "GCP project ID whose Cloud Audit logs are forwarded."
  type        = string
}

variable "region" {
  description = "Region where the Cloud Function and source bucket are deployed."
  type        = string
  default     = "us-central1"
}

variable "ingest_url" {
  description = "Base URL of the picket-ingest Worker. The forwarder appends /events. Example: https://ingest.picket.example"
  type        = string
}

variable "ingest_token" {
  description = "Picket API key (sent in the x-api-key header) scoped to source=gcp_cloud_audit."
  type        = string
  sensitive   = true
}

variable "name_prefix" {
  description = "Prefix applied to all GCP resources created by this module."
  type        = string
  default     = "picket-gcp-audit"
}

variable "include_data_access_logs" {
  description = "Forward Data Access audit logs in addition to Admin Activity and System Event logs. Data Access logs can be high volume."
  type        = bool
  default     = false
}

variable "additional_sink_filter" {
  description = "Optional extra Cloud Logging filter expression AND-ed onto the module's filter."
  type        = string
  default     = ""
}

variable "function_memory_mb" {
  description = "Memory allocation for the forwarder Cloud Function."
  type        = number
  default     = 256
}

variable "function_timeout_seconds" {
  description = "Timeout for the forwarder Cloud Function."
  type        = number
  default     = 60
}

variable "function_max_instances" {
  description = "Upper bound on concurrent function instances. Cap protects the ingestion Worker from runaway fanout."
  type        = number
  default     = 20
}

variable "source_bucket_name" {
  description = "Existing GCS bucket to upload the function source into. If empty, the module creates a bucket named '<project_id>-<name_prefix>-src'."
  type        = string
  default     = ""
}

variable "labels" {
  description = "Extra labels applied to GCP resources that accept labels."
  type        = map(string)
  default     = {}
}
