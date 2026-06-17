# picket Terraform Platform Module

This module provisions the Cloudflare resources that are independent from Worker bundle deployment.

## Resources

- R2 bucket for the event lake
- R2 Data Catalog on the lake bucket (exposes Iceberg + R2 SQL)
- D1 databases: `picket-alert-state` and `picket-auth`
- Cloudflare Queue for alert fanout
- Workers KV namespace for configuration and enrichment data
- Cloudflare Pipelines (stream + sink + pipeline) per data flow:
  - `picket-aws-cloudtrail` → Iceberg table `aws_cloudtrail`
  - `picket-kubernetes-audit` → Iceberg table `kubernetes_audit`
  - `picket-cloudflare-audit` → Iceberg table `cloudflare_audit`
  - `picket-alerts` → Iceberg table `picket_alerts`

Each pipeline's stream is exposed as a Worker binding — the names match the `pipelines` blocks already in `workers/ingest/wrangler.jsonc` and `workers/detection/wrangler.jsonc`.

The alert-state table schema lives in `workers/alert-router/migrations` and is applied with Wrangler D1 migrations after the database is provisioned.

## R2 API Token

Pipelines sinks write to the R2 Data Catalog using an R2 API token (not S3-style access keys). Create it once via dashboard → R2 → Manage R2 API Tokens → "Admin Read & Write", then pass it via `TF_VAR_r2_catalog_token`. The same token (or a separate read-only one) is what CLI users export as `WRANGLER_R2_SQL_AUTH_TOKEN` to run `picket query`.

Pass the Cloudflare provider token with `TF_VAR_cloudflare_api_token` or provider-specific environment configuration. Do not put either token in `terraform.tfvars`.

## Usage

```hcl
module "picket_platform" {
  source = "./terraform/platform"

  cloudflare_account_id = var.cloudflare_account_id
}
```

## Apply Locally

```sh
cp terraform.tfvars.example terraform.tfvars
export TF_VAR_cloudflare_api_token=...
export TF_VAR_r2_catalog_token=...
terraform init
terraform apply
```

Authenticate the Cloudflare provider with `CLOUDFLARE_API_TOKEN` in your environment or your preferred Terraform provider configuration.

Worker code deployment is currently handled by Wrangler. That keeps the early MVP deploy path simple while Terraform owns durable platform resources.
