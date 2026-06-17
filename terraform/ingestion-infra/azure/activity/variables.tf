variable "resource_group_name" {
  description = "Existing resource group where the Event Hub, storage account, and Function App are deployed."
  type        = string
}

variable "location" {
  description = "Azure region for the forwarder resources."
  type        = string
}

variable "subscription_id" {
  description = "Subscription whose Activity Log is forwarded. Defaults to the active AzureRM provider subscription."
  type        = string
  default     = null
  nullable    = true
}

variable "ingest_url" {
  description = "Base URL of the picket-ingest Worker. The forwarder appends /events. Example: https://ingest.picket.example"
  type        = string
}

variable "ingest_token" {
  description = "Picket API key (sent in the x-api-key header) scoped to source=azure_activity."
  type        = string
  sensitive   = true
}

variable "name_prefix" {
  description = "Prefix applied to all Azure resource names created by this module. Keep short — Azure has tight name limits."
  type        = string
  default     = "wsiemact"
}

variable "activity_log_categories" {
  description = "Subscription Activity Log categories to forward."
  type        = list(string)
  default = [
    "Administrative",
    "Security",
    "ServiceHealth",
    "Alert",
    "Recommendation",
    "Policy",
    "Autoscale",
    "ResourceHealth",
  ]
}

variable "event_hub_partition_count" {
  description = "Event Hub partition count."
  type        = number
  default     = 4
}

variable "event_hub_retention_days" {
  description = "Event Hub message retention in days."
  type        = number
  default     = 1
}

variable "event_hub_sku" {
  description = "Event Hub namespace SKU. Standard is the floor for managed-identity auth."
  type        = string
  default     = "Standard"
}

variable "function_plan_sku" {
  description = "App Service Plan SKU for the Function App. Y1 = Consumption (default, scale-to-zero)."
  type        = string
  default     = "Y1"
}

variable "tags" {
  description = "Extra tags applied to all Azure resources."
  type        = map(string)
  default     = {}
}
