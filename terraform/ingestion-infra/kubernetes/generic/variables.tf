variable "ingest_url" {
  description = "Base URL of the picket-ingest Worker (no path). The forwarder appends /events. Example: https://ingest.picket.example"
  type        = string
}

variable "ingest_token" {
  description = "Picket API key (sent in the X-Api-Key header) used to authenticate Fluent Bit batches against picket-ingest. Issued via picket-admin and scoped to source=kubernetes_audit."
  type        = string
  sensitive   = true
}

variable "cluster_name" {
  description = "Logical cluster name stamped onto every event as cloud.account.uid."
  type        = string
}

variable "cluster_region" {
  description = "Optional region label stamped onto events as cloud.region."
  type        = string
  default     = ""
}

variable "namespace" {
  description = "Namespace into which the Fluent Bit DaemonSet is installed."
  type        = string
  default     = "picket"
}

variable "create_namespace" {
  description = "Create the namespace if it does not exist."
  type        = bool
  default     = true
}

variable "audit_log_host_path" {
  description = "Path on each control-plane node where the API server writes the audit log."
  type        = string
  default     = "/var/log/kubernetes/audit/audit.log"
}

variable "fluent_bit_chart_version" {
  description = "Version of the official fluent/fluent-bit Helm chart."
  type        = string
  default     = "0.46.10"
}

variable "control_plane_node_selector" {
  description = "Node selector that targets control-plane nodes where the audit log file exists."
  type        = map(string)
  default = {
    "node-role.kubernetes.io/control-plane" = ""
  }
}

variable "control_plane_tolerations" {
  description = "Tolerations applied to the DaemonSet so it can schedule onto control-plane nodes."
  type = list(object({
    key      = string
    operator = string
    value    = optional(string)
    effect   = string
  }))
  default = [
    {
      key      = "node-role.kubernetes.io/control-plane"
      operator = "Exists"
      effect   = "NoSchedule"
    }
  ]
}

variable "extra_labels" {
  description = "Extra labels applied to all resources created by this module."
  type        = map(string)
  default     = {}
}
