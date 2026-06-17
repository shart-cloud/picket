variable "cluster_name" {
  description = "Name of an existing EKS cluster. The cluster must already have 'audit' in enabled_cluster_log_types."
  type        = string
}

variable "ingest_url" {
  description = "Base URL of the picket-ingest Worker (no path). The forwarder appends /events. Example: https://ingest.picket.example"
  type        = string
}

variable "ingest_token" {
  description = "Picket API key (sent in the x-api-key header) used to authenticate the Lambda forwarder against picket-ingest. Issued via picket-admin and scoped to source=kubernetes_audit."
  type        = string
  sensitive   = true
}

variable "name_prefix" {
  description = "Prefix applied to all AWS resource names created by this module."
  type        = string
  default     = "picket-eks-audit"
}

variable "forwarded_log_stream_prefixes" {
  description = "Log stream name prefixes to forward. Default forwards only kube-apiserver audit. Add 'kube-apiserver-' to also ship API server access logs, 'authenticator-' for IAM auth."
  type        = list(string)
  default     = ["kube-apiserver-audit-"]
}

variable "lambda_memory_mb" {
  description = "Memory allocation for the forwarder Lambda."
  type        = number
  default     = 256
}

variable "lambda_timeout_seconds" {
  description = "Timeout for the forwarder Lambda."
  type        = number
  default     = 30
}

variable "lambda_log_retention_days" {
  description = "CloudWatch Logs retention for the forwarder Lambda's own logs."
  type        = number
  default     = 14
}

variable "subscription_filter_pattern" {
  description = "CloudWatch Logs filter pattern. Empty string forwards every event in the EKS cluster log group (the Lambda filters by stream prefix)."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Extra tags applied to all AWS resources."
  type        = map(string)
  default     = {}
}
