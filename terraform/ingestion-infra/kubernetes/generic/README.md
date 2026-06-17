# picket — Generic Kubernetes Audit Log Forwarder

Installs a Fluent Bit DaemonSet onto control-plane nodes that tails the API server audit log file and POSTs batches (JSON Lines, gzip) to the picket ingestion Worker.

Use this module for self-hosted clusters (kubeadm, k3s, RKE2, kind), or any environment where you'd rather ship from inside the cluster than wire up a cloud provider's log export pipeline. For managed clusters with native audit log export, prefer the `eks/`, `gke/`, or `aks/` modules in this directory — they avoid running an in-cluster forwarder.

## Prerequisites

1. **API server audit logging enabled.** This module does not configure the API server. Apply `audit-policy.example.yaml` (or your own) and start `kube-apiserver` with:
   ```
   --audit-policy-file=/etc/kubernetes/audit-policy.yaml
   --audit-log-path=/var/log/kubernetes/audit/audit.log
   --audit-log-maxage=7
   --audit-log-maxbackup=3
   --audit-log-maxsize=100
   ```
   On kubeadm: edit `/etc/kubernetes/manifests/kube-apiserver.yaml` and mount both the policy and log directory as hostPaths. On k3s: pass `--kube-apiserver-arg` flags via the systemd unit.

2. **Ingestion Worker deployed** with a known URL and bearer token. The Worker is provisioned by the platform module + `workers/ingest-k8s-audit` (separate from this Terraform module).

3. **kubectl context** configured to point at the target cluster.

## Usage

```hcl
module "k8s_audit_generic" {
  source = "../../terraform/ingestion-infra/kubernetes/generic"

  ingest_url     = "https://k8s-audit.example.workers.dev"
  ingest_token   = var.picket_ingest_token
  cluster_name   = "prod-use1"
  cluster_region = "us-east-1"
}
```

Multiple clusters: instantiate the module once per cluster with a distinct provider alias.

## What It Creates

- Namespace `picket` (configurable; opt-out via `create_namespace = false`)
- Secret `picket-ingest` holding the bearer token
- Helm release of the official `fluent/fluent-bit` chart configured to:
  - Tail `/var/log/kubernetes/audit/audit.log` (configurable)
  - Tolerate and select control-plane nodes (configurable)
  - Stamp `cluster_name`, `cluster_region`, and `cloud_provider=generic` onto each record
  - POST `json_lines` batches with `Authorization: Bearer <token>` to the ingestion URL

## What It Doesn't Do (Yet)

- OCSF normalization happens in the ingestion Worker, not in Fluent Bit. Fluent Bit ships raw `AuditEvent` records plus the three stamped fields.
- No file rotation handling beyond what the API server's `--audit-log-max*` flags provide.
- No backpressure buffering to disk on the Fluent Bit side — relies on the chart default in-memory buffer. Tune via Helm values if your cluster bursts above ~1k events/sec.
