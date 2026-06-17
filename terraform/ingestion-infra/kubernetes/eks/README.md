# picket — EKS Audit Log Forwarder

Add-on Terraform module that ships EKS control-plane audit logs to the picket ingestion Worker. Designed to drop next to an existing EKS deployment — the only EKS-side input is the cluster name.

## What It Creates

- Secrets Manager secret holding the ingestion bearer token
- IAM role for the forwarder Lambda + scoped `secretsmanager:GetSecretValue` policy for the token secret only
- Node.js 20 (arm64) Lambda function (`<prefix>-<cluster>`) that decodes CloudWatch Logs subscription events, filters to audit streams, stamps cluster/cloud metadata, and POSTs NDJSON batches to the ingestion Worker
- CloudWatch Logs subscription filter on the cluster's `/aws/eks/<cluster>/cluster` log group
- CloudWatch Log Group for the Lambda's own logs (with configurable retention)

The Lambda fetches the bearer token from Secrets Manager on cold start and caches it in module scope for the life of the execution environment. The AWS SDK v3 is provided by the Node 20 Lambda runtime, so no bundling is required.

No EKS resources are created or modified. The cluster must already exist and must have `"audit"` in its `enabled_cluster_log_types` — the module fails with a clear error if not.

## Integration Patterns

### Alongside `terraform-aws-modules/eks`

```hcl
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"
  # ...
  cluster_enabled_log_types = ["audit", "authenticator", "api"]
}

module "picket_audit_forwarder" {
  source = "github.com/picket-siem/picket//terraform/ingestion-infra/kubernetes/eks"

  cluster_name = module.eks.cluster_name
  ingest_url   = "https://k8s-audit.picket.example"
  ingest_token = var.picket_ingest_token
}
```

See `examples/with-aws-eks-module/` for the full example.

### Against an existing cluster managed elsewhere

```hcl
module "picket_audit_forwarder" {
  source = "github.com/picket-siem/picket//terraform/ingestion-infra/kubernetes/eks"

  cluster_name = "prod-use1"
  ingest_url   = "https://k8s-audit.picket.example"
  ingest_token = var.picket_ingest_token
}
```

The module looks the cluster up via `data "aws_eks_cluster"`, so it works with clusters provisioned by ClickOps, eksctl, CDK, Pulumi, or another Terraform workspace. See `examples/existing-cluster/`.

### Multi-cluster / multi-region

Instantiate the module once per cluster, passing distinct provider aliases. See `examples/multi-cluster/`.

## Variables

| Name | Required | Default | Notes |
|---|---|---|---|
| `cluster_name` | yes | — | Existing EKS cluster name |
| `ingest_url` | yes | — | picket ingestion Worker URL |
| `ingest_token` | yes | — | Bearer token (sensitive) |
| `name_prefix` | no | `picket-eks-audit` | Resource name prefix |
| `forwarded_log_stream_prefixes` | no | `["kube-apiserver-audit-"]` | Add `"kube-apiserver-"` for API access logs, `"authenticator-"` for IAM auth |
| `lambda_memory_mb` | no | `256` | |
| `lambda_timeout_seconds` | no | `30` | |
| `lambda_log_retention_days` | no | `14` | |
| `subscription_filter_pattern` | no | `""` | CloudWatch Logs filter — empty forwards all events; Lambda filters by stream prefix |
| `tags` | no | `{}` | Merged with module-managed tags |

## Cost Notes

- The subscription filter forwards every event in the EKS cluster log group to Lambda; Lambda drops non-audit streams in <1ms before doing any work. If `cluster_enabled_log_types` includes high-volume types you don't want shipped, leave them disabled rather than relying on Lambda to filter — CloudWatch Logs charges for ingestion regardless.
- Lambda is arm64 to keep per-invocation cost low; bump memory if you see consistent throttling.

## Out of Scope

- Audit policy on the API server (managed by AWS for EKS — you get the AWS-managed policy)
- OCSF normalization (handled in the ingestion Worker, not the Lambda)
- Customer-managed KMS key for the secret — defaults to the AWS-managed `aws/secretsmanager` key. Add a `kms_key_id` to the secret if you need CMK control.
