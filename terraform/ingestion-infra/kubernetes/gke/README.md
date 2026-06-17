# picket — GKE Audit Log Forwarder

Add-on Terraform module that ships GKE Cloud Audit Logs to the picket ingestion Worker. BYO cluster — the only GKE-side inputs are `project_id` and `cluster_name`.

## What It Creates

- Pub/Sub topic
- Cloud Logging project sink (filtered to `resource.type="k8s_cluster"` for the named cluster) → Pub/Sub
- IAM binding granting the sink's writer identity `roles/pubsub.publisher`
- Service account for the Cloud Function
- Secret Manager secret holding the ingestion bearer token + accessor binding
- GCS source bucket for the function code (or reuses `source_bucket_name` if you provide one)
- Cloud Functions Gen2 (Node.js 20) triggered by Pub/Sub that decodes each LogEntry, stamps cluster/cloud metadata, and POSTs to the ingestion Worker

No GKE cluster resources are touched. The cluster keeps running whatever it was running.

## Why GKE Is Easier Than EKS

GKE Admin Activity audit logs are always-on at the project level and route to Cloud Logging automatically — there's no equivalent of EKS `enabled_cluster_log_types` to toggle. This module is therefore purely additive: a sink, a topic, a function, an IAM binding. No cluster precondition check is needed.

Data Access logs (`data_access`) are opt-in at the project level via IAM audit config and are high volume + chargeable. They're off by default in this module; set `include_data_access_logs = true` to forward them.

## Integration Patterns

### Alongside `terraform-google-modules/kubernetes-engine`

```hcl
module "gke" {
  source  = "terraform-google-modules/kubernetes-engine/google"
  version = "~> 31.0"
  # ...
}

module "picket_audit_forwarder" {
  source = "github.com/picket-siem/picket//terraform/ingestion-infra/kubernetes/gke"

  project_id       = "my-prod-project"
  cluster_name     = module.gke.name
  cluster_location = module.gke.location
  region           = "us-central1"

  ingest_url   = "https://k8s-audit.picket.example"
  ingest_token = var.picket_ingest_token
}
```

See `examples/with-google-modules/`.

### Against an existing cluster managed elsewhere

```hcl
module "picket_audit_forwarder" {
  source = "github.com/picket-siem/picket//terraform/ingestion-infra/kubernetes/gke"

  project_id       = "my-prod-project"
  cluster_name     = "prod-usc1"
  cluster_location = "us-central1"

  ingest_url   = "https://k8s-audit.picket.example"
  ingest_token = var.picket_ingest_token
}
```

See `examples/existing-cluster/`. The module never reads the cluster resource itself — `cluster_name` is purely a log filter input, so the cluster can live in any other workspace, gcloud, or ClickOps deployment.

### Multi-cluster / multi-region

Instantiate once per cluster, passing a regional `google` provider alias. See `examples/multi-cluster/`.

## Variables

| Name | Required | Default | Notes |
|---|---|---|---|
| `project_id` | yes | — | GCP project ID containing the cluster |
| `cluster_name` | yes | — | Existing GKE cluster name |
| `cluster_location` | no | `""` | Region or zone — set when cluster names repeat across locations |
| `region` | no | `us-central1` | Where the Cloud Function deploys |
| `ingest_url` | yes | — | picket ingestion Worker URL |
| `ingest_token` | yes | — | Bearer token (stored in Secret Manager, mounted as env at runtime) |
| `name_prefix` | no | `picket-gke-audit` | |
| `include_data_access_logs` | no | `false` | Ships Data Access logs — high volume, costs money |
| `additional_sink_filter` | no | `""` | Extra Cloud Logging filter expression AND-ed onto the module filter |
| `function_memory_mb` | no | `256` | |
| `function_timeout_seconds` | no | `60` | |
| `function_max_instances` | no | `20` | Backpressure cap on the ingestion Worker |
| `source_bucket_name` | no | `""` | Reuse an existing GCS bucket for function source; otherwise the module creates one |
| `labels` | no | `{}` | Merged with module-managed labels |

## Required APIs

The owning project must have these APIs enabled. The module does not enable them (one-time, per-project, and usually owned by platform Terraform):

- `cloudfunctions.googleapis.com`
- `cloudbuild.googleapis.com`
- `run.googleapis.com` (Cloud Functions Gen2 runs on Cloud Run)
- `eventarc.googleapis.com`
- `pubsub.googleapis.com`
- `secretmanager.googleapis.com`
- `logging.googleapis.com`
- `storage.googleapis.com`

## Cost Notes

- Cloud Logging ingestion is free for Admin Activity. Data Access logs cost from byte one — leave `include_data_access_logs = false` unless a specific detection requires them.
- Cloud Functions Gen2 charges per invocation + GB-second. One invocation per Pub/Sub message; tune `function_max_instances` to bound peak fanout.
- Pub/Sub egress to the function within the same region is free; cross-region egress is not. Keep `region` matched to the cluster's region when possible.

## Out of Scope

- Enabling project-level Data Access audit config (`google_project_iam_audit_config`) — that's project-wide policy, owned by the platform team, not a per-cluster forwarder concern. Module just consumes whatever is being logged.
- OCSF normalization (handled in the ingestion Worker)
- DLQ — failed function invocations rely on Pub/Sub's built-in retry (`RETRY_POLICY_RETRY`). For long-tail durability, attach a dead-letter subscription to the topic outside this module.
