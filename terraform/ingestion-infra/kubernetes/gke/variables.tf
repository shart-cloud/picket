variable "project_id" {
  description = "GCP project ID that owns the GKE cluster and where forwarder resources will be created."
  type        = string
}

variable "cluster_name" {
  description = "Name of an existing GKE cluster. Used to filter audit logs to a single cluster."
  type        = string
}

variable "cluster_location" {
  description = "Optional cluster location (region or zone) used to disambiguate when multiple clusters share a name across locations. Empty matches any location."
  type        = string
  default     = ""
}

variable "region" {
  description = "Region where the Cloud Function and source bucket are deployed."
  type        = string
  default     = "us-central1"
}

variable "ingest_url" {
  description = "Base URL of the picket-ingest Worker (no path). The forwarder appends /events. Example: https://ingest.picket.example"
  type        = string
}

variable "ingest_token" {
  description = "Picket API key (sent in the x-api-key header) used to authenticate the Cloud Function forwarder against picket-ingest. Issued via picket-admin and scoped to source=kubernetes_audit."
  type        = string
  sensitive   = true
}

variable "name_prefix" {
  description = "Prefix applied to all GCP resource names created by this module."
  type        = string
  default     = "picket-gke-audit"
}

variable "include_data_access_logs" {
  description = "Forward Data Access audit logs in addition to Admin Activity. Data Access logs are high volume and chargeable — enable per cluster only after sizing."
  type        = bool
  default     = false
}

variable "additional_sink_filter" {
  description = "Optional extra Cloud Logging filter expression AND-ed onto the module's filter. Use to narrow further (e.g. exclude specific namespaces)."
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
