# picket

Serverless SIEM components built around Cloudflare Workers, R2, Pipelines, Queues, D1, and Durable Objects.

This repository is building an MVP backend slice: ingestion, normalization, real-time detection, alert routing, alert state, source health, query execution, and Cloudflare/Terraform deployment scaffolding.

## Development

```sh
pnpm install
pnpm test
pnpm typecheck
```

## Current Architecture Direction

R2 SQL now supports JOINs, subqueries, and CTEs over Iceberg tables. picket should therefore prefer per-source Iceberg tables for MVP ingestion, then use SQL JOINs for analytical cross-source correlation and query-time enrichment.

Durable Objects remain the right fit for real-time stateful detections that need sub-second decisions. R2 SQL is the right fit for scheduled detections, investigation timelines, cross-source correlation, and enrichment joins against tables like `threat_intel`, `assets`, and `users`.

## Deploy Options

picket's production deploy path is Terraform-first. Terraform owns durable Cloudflare resources; Wrangler currently deploys Worker bundles, applies D1 migrations, and writes Worker secrets.

See [Deployment](docs/deployment.md) for the full runbook.

### Deploy to Cloudflare

The Cloudflare Deploy Button is not the primary path for this repository right now. The app is a multi-Worker monorepo with Terraform-managed Pipelines, R2 Data Catalog, Access, D1, and Queue wiring. A button can be revisited later as a bootstrap/demo flow, but Terraform is the reliable production path.

For local Wrangler deployment:

```sh
pnpm install
pnpm deploy:cloudflare
```

Optional alert destination secrets:

```sh
pnpm wrangler secret put SLACK_WEBHOOK_URL --config workers/alert-router/wrangler.jsonc
pnpm wrangler secret put ALERT_WEBHOOK_URL --config workers/alert-router/wrangler.jsonc
pnpm wrangler secret put ALERT_WEBHOOK_AUTH_HEADER --config workers/alert-router/wrangler.jsonc
```

### Terraform

Terraform currently provisions durable Cloudflare resources while Wrangler deploys Worker bundles and secrets.

```sh
cd terraform/platform
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

Current Terraform resources:

- R2 bucket
- R2 Data Catalog
- D1 databases
- Cloudflare Queues
- Workers KV namespace
- Cloudflare Pipelines
- Cloudflare Access app and admin custom domain

After Terraform applies, return to the repo root and deploy Workers with:

```sh
pnpm gen:wrangler       # generate gitignored wrangler.jsonc from templates + terraform output
pnpm deploy:cloudflare  # also runs gen:wrangler first
```

Then apply D1 migrations and configure secrets as described in [Deployment](docs/deployment.md).

### AWS CloudTrail Ingestion

The CloudTrail forwarder module lives in `terraform/ingestion-infra/aws/cloudtrail`. It attaches S3 object notifications, SQS buffering, and a Lambda forwarder to an existing CloudTrail bucket.

For AWS Control Tower centralized logging, CloudTrail objects are commonly nested under an organization prefix:

```text
o-<org-id>/AWSLogs/o-<org-id>/<account-id>/CloudTrail/<region>/<yyyy>/<mm>/<dd>/<file>.json.gz
```

Configure the module with the organization-level prefix so the bucket notification matches the actual object keys:

```hcl
cloudtrail_object_key_prefixes = ["o-<org-id>/AWSLogs/o-<org-id>/"]
```
