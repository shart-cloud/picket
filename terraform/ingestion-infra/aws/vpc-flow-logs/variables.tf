variable "vpc_id" {
  description = "VPC ID to enable Flow Logs for. Exactly one of vpc_id, subnet_id, or network_interface_id should be set."
  type        = string
  default     = null
  nullable    = true
}

variable "subnet_id" {
  description = "Subnet ID to enable Flow Logs for. Exactly one of vpc_id, subnet_id, or network_interface_id should be set."
  type        = string
  default     = null
  nullable    = true
}

variable "network_interface_id" {
  description = "Network interface ID to enable Flow Logs for. Exactly one of vpc_id, subnet_id, or network_interface_id should be set."
  type        = string
  default     = null
  nullable    = true
}

variable "flow_logs_bucket_name" {
  description = "Name of the existing S3 bucket that receives VPC Flow Logs."
  type        = string
}

variable "flow_logs_object_key_prefix" {
  description = "S3 key prefix for VPC Flow Logs objects. Must match the aws_flow_log destination prefix."
  type        = string
  default     = "AWSLogs/"
}

variable "flow_logs_object_key_suffix" {
  description = "Optional S3 key suffix filter for VPC Flow Logs objects. Use null to omit the suffix filter."
  type        = string
  default     = ".log.gz"
  nullable    = true
}

variable "traffic_type" {
  description = "Traffic type captured by the Flow Log: ACCEPT, REJECT, or ALL."
  type        = string
  default     = "ALL"

  validation {
    condition     = contains(["ACCEPT", "REJECT", "ALL"], var.traffic_type)
    error_message = "traffic_type must be ACCEPT, REJECT, or ALL."
  }
}

variable "ingest_url" {
  description = "Base URL of the picket-ingest Worker, or the full /events URL. Example: https://ingest.picket.example"
  type        = string
}

variable "ingest_token" {
  description = "Picket API key (sent in the x-api-key header) scoped to source=aws_vpc_flow."
  type        = string
  sensitive   = true
}

variable "name_prefix" {
  description = "Prefix applied to all AWS resource names created by this module."
  type        = string
  default     = "picket-vpc-flow"
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
