variable "resource_group_name" {
  description = "Existing resource group where the Event Hub, storage account, and Function App are deployed."
  type        = string
}

variable "location" {
  description = "Azure region for the forwarder resources."
  type        = string
}

variable "ingest_url" {
  description = "Base URL of the picket-ingest Worker. The forwarder appends /events. Example: https://ingest.picket.example"
  type        = string
}

variable "ingest_token" {
  description = "Picket API key (sent in the x-api-key header) scoped to source=azure_ad_signin."
  type        = string
  sensitive   = true
}

variable "name_prefix" {
  description = "Prefix applied to all Azure resources created by this module. Keep short — Azure has tight name limits."
  type        = string
  default     = "wsiemaad"
}

variable "signin_log_categories" {
  description = "Entra ID sign-in diagnostic categories to forward."
  type        = list(string)
  default = [
    "SignInLogs",
    "NonInteractiveUserSignInLogs",
    "ServicePrincipalSignInLogs",
    "ManagedIdentitySignInLogs",
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
