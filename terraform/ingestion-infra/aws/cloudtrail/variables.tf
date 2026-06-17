variable "cloudtrail_bucket_name" {
  description = "Name of the existing S3 bucket receiving CloudTrail log files."
  type        = string
}

variable "ingest_url" {
  description = "Base URL of the picket-ingest Worker, or the full /events URL. Example: https://ingest.picket.example"
  type        = string
}

variable "ingest_token" {
  description = "Picket API key (sent in the x-api-key header) used to authenticate the Lambda forwarder against picket-ingest. Issued via picket-admin and scoped to source=aws_cloudtrail."
  type        = string
  sensitive   = true
}

variable "name_prefix" {
  description = "Prefix applied to all AWS resource names created by this module."
  type        = string
  default     = "picket-cloudtrail"
}

variable "cloudtrail_object_key_prefixes" {
  description = "Optional S3 key prefixes to notify on. Use [] to receive all object-created events in the bucket."
  type        = list(string)
  default     = ["AWSLogs/"]
}

variable "cloudtrail_object_key_suffix" {
  description = "Optional S3 key suffix filter for CloudTrail objects. Use null to omit the suffix filter."
  type        = string
  default     = ".json.gz"
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
  default     = 60
}

variable "lambda_log_retention_days" {
  description = "CloudWatch Logs retention for the forwarder Lambda's own logs."
  type        = number
  default     = 14
}

variable "lambda_batch_size" {
  description = "Maximum number of SQS messages delivered to the Lambda per invocation."
  type        = number
  default     = 10
}

variable "tags" {
  description = "Extra tags applied to all AWS resources."
  type        = map(string)
  default     = {}
}
