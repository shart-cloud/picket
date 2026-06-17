variable "ingest_url" {
  description = "Base URL of the picket-ingest Worker, or the full /events URL. Example: https://ingest.picket.example"
  type        = string
}

variable "ingest_token" {
  description = "Picket API key (sent in the x-api-key header) scoped to source=aws_guardduty."
  type        = string
  sensitive   = true
}

variable "name_prefix" {
  description = "Prefix applied to all AWS resources created by this module."
  type        = string
  default     = "picket-guardduty"
}

variable "create_detector" {
  description = "Create and enable a GuardDuty detector in this region. Leave false if GuardDuty is already enabled."
  type        = bool
  default     = false
}

variable "event_pattern" {
  description = "EventBridge event pattern used to select GuardDuty findings. Override to narrow by severity/type/account."
  type        = string
  default     = null
  nullable    = true
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

variable "tags" {
  description = "Extra tags applied to all AWS resources."
  type        = map(string)
  default     = {}
}
