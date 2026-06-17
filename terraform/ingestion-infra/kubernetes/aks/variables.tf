variable "resource_group_name" {
  description = "Resource group containing the existing AKS cluster."
  type        = string
}

variable "cluster_name" {
  description = "Name of an existing AKS cluster."
  type        = string
}

variable "ingest_url" {
  description = "Base URL of the picket-ingest Worker (no path). The forwarder appends /events. Example: https://ingest.picket.example"
  type        = string
}

variable "ingest_token" {
  description = "Picket API key (sent in the x-api-key header) used to authenticate the Azure Function forwarder against picket-ingest. Issued via picket-admin and scoped to source=kubernetes_audit."
  type        = string
  sensitive   = true
}

variable "forwarder_resource_group_name" {
  description = "Resource group where the Event Hub + Function App are deployed. Defaults to the cluster's resource group."
  type        = string
  default     = ""
}

variable "location" {
  description = "Azure region for the forwarder resources. Defaults to the cluster's region."
  type        = string
  default     = ""
}

variable "name_prefix" {
  description = "Prefix applied to all Azure resource names created by this module. Keep short — Azure has tight name limits."
  type        = string
  default     = "wsiem"
}

variable "include_kube_audit_admin" {
  description = "Forward kube-audit-admin (admin-only operations, lower volume). Strongly recommended."
  type        = bool
  default     = true
}

variable "include_kube_audit" {
  description = "Forward the full kube-audit category (high volume — includes every API server request). Enable only after sizing."
  type        = bool
  default     = false
}

variable "additional_log_categories" {
  description = "Extra AKS diagnostic categories to ship alongside the audit categories (e.g. 'cloud-controller-manager', 'kube-apiserver', 'kube-controller-manager')."
  type        = list(string)
  default     = []
}

variable "event_hub_partition_count" {
  description = "Event Hub partition count. Bump for clusters with sustained high audit volume."
  type        = number
  default     = 4
}

variable "event_hub_retention_days" {
  description = "Event Hub message retention in days. 1 is enough for forward-only pipelines; raise to buffer if the forwarder may be down."
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

variable "key_vault_id" {
  description = "Existing Key Vault resource ID to store the ingestion bearer token in. If empty, the module creates a per-cluster vault. BYO is recommended — vaults are typically shared per environment."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Extra tags applied to all Azure resources."
  type        = map(string)
  default     = {}
}
