# picket — Cloudflare Audit Logs Forwarder

Add-on Terraform module that pushes Cloudflare account Audit Logs v2 to the `picket-ingest` Worker using Cloudflare Logpush over HTTP.

## What It Creates

- Account-scoped Cloudflare Logpush job for the `audit_logs` dataset
- HTTP destination targeting `picket-ingest` at `/events`
- Custom `x-api-key` header carrying the Picket ingest API key

Logpush sends raw audit records. OCSF normalization happens inside `picket-ingest` via `normalizeCloudflareAudit`.

## Example Usage

```hcl
variable "picket_cloudflare_audit_ingest_token" {
  type      = string
  sensitive = true
}

module "picket_cloudflare_audit" {
  source = "github.com/picket-siem/picket//terraform/ingestion-infra/cloudflare/audit-logs"

  cloudflare_account_id = var.cloudflare_account_id
  ingest_url            = "https://ingest.shart.cloud"
  ingest_token          = var.picket_cloudflare_audit_ingest_token
}
```

If `ingest_url` already ends with `/events`, the module uses it as-is. Otherwise it appends `/events`.

## Picket API Key

Mint an API key scoped to Cloudflare audit ingestion, with metadata set to:

```json
{
  "source": "cloudflare_audit",
  "tenant_id": "<tenant>"
}
```

Store the token outside Terraform files, for example with `TF_VAR_picket_cloudflare_audit_ingest_token` in your shell or CI secret store.

## Required Cloudflare Permissions

The Terraform API token needs permission to create and manage account Logpush jobs for the target account.

## Verification

After applying the module, make a small audited account change in Cloudflare, then verify from Picket:

```sh
picket status
picket query --sql "SELECT time, actor_user_email, api_operation FROM cloudflare_audit_<table_suffix> WHERE time > now() - interval '1' hour ORDER BY time DESC LIMIT 20"
```
