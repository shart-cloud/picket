variable "cloudflare_account_id" {
  description = "Cloudflare account ID whose Audit Logs v2 dataset should be pushed to Picket."
  type        = string
}

variable "ingest_url" {
  description = "Base URL of the picket-ingest Worker, or the full /events URL."
  type        = string
  default     = "https://ingest.shart.cloud"
}

variable "ingest_token" {
  description = "Picket API key sent in the x-api-key header. Mint with metadata.source=cloudflare_audit."
  type        = string
  sensitive   = true
}

variable "job_name" {
  description = "Name for the Cloudflare Logpush job."
  type        = string
  default     = "picket-cloudflare-audit"
}

variable "enabled" {
  description = "Whether the Logpush job should be enabled."
  type        = bool
  default     = true
}
