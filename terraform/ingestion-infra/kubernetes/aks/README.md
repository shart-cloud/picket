# picket — AKS Audit Log Forwarder

Add-on Terraform module that ships AKS audit logs to the picket ingestion Worker. BYO cluster — the only AKS-side inputs are `resource_group_name` and `cluster_name`.

## What It Creates

- Event Hub namespace + Event Hub (`audit`) + dedicated consumer group
- Diagnostic Setting on the AKS cluster routing audit categories → Event Hub
- Storage account + container holding the function source zip (SAS-deployed via `WEBSITE_RUN_FROM_PACKAGE`)
- App Service Plan (default: Y1 Consumption) + Linux Function App (Node 20, Event Hub trigger)
- System-assigned managed identity on the Function App
- Role assignments: `Azure Event Hubs Data Receiver` on the Event Hub, `Key Vault Secrets User` scoped to the ingestion token secret only
- Key Vault secret holding the ingestion bearer token. Vault is BYO via `key_vault_id` (recommended) or created per-cluster if omitted.

The AKS cluster is read via `data "azurerm_kubernetes_cluster"` and is **not modified beyond the addition of a Diagnostic Setting**, which is a sibling resource — the cluster spec itself is untouched.

## Why AKS Differs From EKS/GKE

AKS audit logging is configured via Diagnostic Settings on the cluster (siblings of the cluster resource), not via a property on the cluster spec. That means there's no precondition like EKS's `enabled_cluster_log_types` to validate — this module simply creates its own Diagnostic Setting alongside any others you have. Multiple Diagnostic Settings on the same cluster can coexist (up to Azure's per-resource limit, currently 5).

Two audit categories matter:
- `kube-audit-admin` — admin operations only. Lower volume. **Default: on.**
- `kube-audit` — full API server audit log. High volume. **Default: off.** Enable only after sizing.

Other categories (`cloud-controller-manager`, `kube-apiserver`, `kube-controller-manager`, `kube-scheduler`, `guard`, `csi-azuredisk-controller`, `csi-azurefile-controller`, `cluster-autoscaler`) can be added via `additional_log_categories` if you want broader visibility.

## Integration Patterns

### Alongside `Azure/aks/azurerm`

```hcl
module "aks" {
  source  = "Azure/aks/azurerm"
  version = "~> 9.0"
  # ...
}

module "picket_audit_forwarder" {
  source = "github.com/picket-siem/picket//terraform/ingestion-infra/kubernetes/aks"

  resource_group_name = "rg-prod-eus"
  cluster_name        = module.aks.aks_name

  ingest_url   = "https://k8s-audit.picket.example"
  ingest_token = var.picket_ingest_token
}
```

See `examples/with-azurerm-modules/`.

### Against an existing cluster managed elsewhere

```hcl
module "picket_audit_forwarder" {
  source = "github.com/picket-siem/picket//terraform/ingestion-infra/kubernetes/aks"

  resource_group_name = "rg-prod-eus"
  cluster_name        = "aks-prod-eus"

  ingest_url   = "https://k8s-audit.picket.example"
  ingest_token = var.picket_ingest_token
}
```

The module reads cluster location from the data source, so it co-locates the Event Hub and Function App with the cluster by default. Override `location` and `forwarder_resource_group_name` if you want a dedicated forwarder region/RG. See `examples/existing-cluster/`.

### Multi-cluster

Instantiate once per cluster. The module derives a short hash suffix from `(resource_group_name, cluster_name)` so resource names stay unique without manual `name_prefix` juggling. See `examples/multi-cluster/`.

## Variables

| Name | Required | Default | Notes |
|---|---|---|---|
| `resource_group_name` | yes | — | RG containing the AKS cluster |
| `cluster_name` | yes | — | Existing AKS cluster name |
| `ingest_url` | yes | — | picket ingestion Worker URL |
| `ingest_token` | yes | — | Bearer token (sensitive) |
| `forwarder_resource_group_name` | no | `var.resource_group_name` | Where forwarder resources live |
| `location` | no | cluster's region | Forwarder region |
| `name_prefix` | no | `wsiem` | Keep short — Azure name limits are tight |
| `include_kube_audit_admin` | no | `true` | Admin operations only — recommended |
| `include_kube_audit` | no | `false` | Full API server audit — high volume |
| `additional_log_categories` | no | `[]` | e.g. `["kube-apiserver", "cloud-controller-manager"]` |
| `event_hub_partition_count` | no | `4` | |
| `event_hub_retention_days` | no | `1` | Raise to buffer if the forwarder may be down |
| `event_hub_sku` | no | `Standard` | `Standard` minimum for managed-identity auth |
| `function_plan_sku` | no | `Y1` | Consumption plan; switch to EP1+ for predictable latency |
| `key_vault_id` | no | `""` | Existing Key Vault to store the ingestion token; module creates one per-cluster if empty |
| `tags` | no | `{}` | Merged with module-managed tags |

## Auth Model

- **Event Hub read path:** Function App's system-assigned managed identity → `Azure Event Hubs Data Receiver` role on the specific Event Hub. No connection strings.
- **Diagnostic Setting → Event Hub:** scoped Send-only authorization rule on the namespace.
- **Ingestion bearer token:** stored in Key Vault. The Function App setting holds a `@Microsoft.KeyVault(SecretUri=...)` reference, which Azure resolves at runtime and injects as the `INGEST_TOKEN` env var. The function code never sees the vault directly.

### Bring-your-own Key Vault (recommended)

Pass `key_vault_id` pointing at an existing environment-scoped vault. The module writes one secret into it and grants the Function App identity `Key Vault Secrets User` on **that secret only** (not the whole vault), so blast radius stays minimal.

The deploying principal needs `Key Vault Secrets Officer` on the target vault to write the secret. If the vault uses access policies instead of RBAC, switch it to RBAC first or provision the secret out-of-band.

### Self-managed vault (fallback)

If `key_vault_id` is empty, the module creates a per-cluster RBAC vault (`<prefix><hash>kv`) and grants the deploying principal `Key Vault Secrets Officer` on it automatically. Soft-delete retention is 7 days; purge protection is off so test environments can be torn down cleanly. Turn purge protection on manually for production deployments.

## Cost Notes

- Event Hub Standard is ~$0.03/hour/throughput unit. One TU comfortably handles `kube-audit-admin` for typical clusters; bump capacity if you enable `kube-audit`.
- Function App on Y1 (Consumption) scales to zero between bursts. Switch to a Premium plan if you need cold-start-free dispatch.
- Storage account holds the function source zip (one blob, small) — negligible cost.

## Out of Scope

- OCSF normalization (handled in the ingestion Worker)
- DLQ — failures throw and Azure Functions retries per its default policy. For long-tail durability, configure poison message handling explicitly outside this module.
- Customer-managed key (CMK) encryption on the Key Vault — uses the default Microsoft-managed key
