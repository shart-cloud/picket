# Deployment

picket's production deploy path is Terraform-first. Terraform owns durable Cloudflare resources; Wrangler currently deploys Worker code and writes Worker secrets.

The Deploy to Cloudflare button is not the primary path for this repository. The app is a multi-Worker monorepo with Terraform-managed Pipelines, R2 Data Catalog, Access, D1, and Queue wiring. A button can be revisited later as a bootstrap/demo flow, but Terraform is the reliable production path.

## What Terraform Owns Today

- R2 lake bucket
- R2 Data Catalog
- D1 databases: `picket-alert-state`, `picket-auth`
- Queues: `picket-alerts`, `picket-query-jobs`
- Workers KV namespace
- Pipeline streams, sinks, and flows for source events, alerts, and enrichment dimensions
- Cloudflare Access app for `picket-admin`
- Workers custom domain for `picket-admin`

## What Wrangler Owns Today

- Worker bundle deployment
- Web console asset build and upload through the `picket-admin` Worker assets binding
- D1 migration execution
- Worker secrets
- One-time system-user seed command

Secrets stay outside Terraform for now. Manage them with `wrangler secret put` so secret values do not land in Terraform state.

## Prerequisites

- Node.js and pnpm matching `package.json`
- Terraform `>= 1.6`
- Wrangler authenticated to the target Cloudflare account
- Cloudflare API token available as `CLOUDFLARE_API_TOKEN` or in `terraform.tfvars`
- R2 API token for Pipelines/Data Catalog writes
- A Cloudflare zone for the admin hostname if using the custom domain and Access app

The Cloudflare token used by Terraform needs permissions for the resources in `terraform/platform`: Workers, D1, Queues, R2, R2 Data Catalog, Pipelines, KV, Access, and zone/custom-domain changes.

## 1. Install And Validate

```sh
pnpm install
pnpm test
pnpm typecheck
```

## 2. Configure Terraform

```sh
cd terraform/platform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your account and environment values.

Required values:

- `cloudflare_account_id`
- `cloudflare_api_token`, unless using `CLOUDFLARE_API_TOKEN`
- `r2_catalog_token`, preferably via `TF_VAR_r2_catalog_token`
- `picket_admin_allowed_emails`

Common optional values:

- `picket_admin_domain`
- `picket_admin_zone_name`
- `picket_admin_session_duration`
- resource names such as `r2_bucket_name`, `d1_database_name`, and queue names

## 3. Apply Platform Infrastructure

```sh
terraform init
terraform apply
```

Terraform outputs the IDs and names that Worker configs need, including:

- `d1_database_id`
- `auth_d1_database_id`
- `stream_ids`
- `r2_catalog_warehouse`
- `r2_catalog_table_suffix`
- `cf_access_team_domain`
- `cf_access_aud`
- `picket_admin_url`

## 4. Generate Wrangler Configs

Each worker's `workers/*/wrangler.jsonc` is **generated** from a committed,
account-neutral `workers/*/wrangler.template.jsonc` and is gitignored — it holds
IDs and domains unique to your Cloudflare account, so it must never be
committed. From the repo root:

```sh
pnpm gen:wrangler
```

This reads `terraform output -json` and substitutes every account-specific value
into the templates: the D1 IDs, Pipeline stream IDs, KV namespace ID, the admin
`THREAT_INTEL_PIPELINE` / `ASSETS_PIPELINE` / `USERS_PIPELINE` enrichment
bindings, and the admin vars `CF_ACCESS_TEAM_DOMAIN`, `CF_ACCESS_AUD`,
`PICKET_R2_WAREHOUSE`, and `PICKET_TABLE_SUFFIX`. `scheduled-detection` is
generated from the same outputs, so its alerts pipeline and alert-state DB stay
in lockstep with Terraform.

There is nothing to paste or confirm by hand. `gen:wrangler` fails loudly if a
required Terraform output is missing — most commonly `CF_ACCESS_AUD`, which is
`null` until the picket-admin Access app exists (see the two-phase admin
bootstrap below). `pnpm deploy:cloudflare` runs `gen:wrangler` first, so a normal
deploy regenerates from the current Terraform state automatically.

## 5. Deploy Worker Bundles

```sh
pnpm deploy:cloudflare
```

This builds the monorepo and deploys these Workers with Wrangler:

- `picket-detection`
- `picket-alert-router`
- `picket-ingest`
- `picket-admin`
- `picket-query-runner`
- `picket-scheduled-detection`

The build also emits `apps/web/dist`. `picket-admin` serves that directory via its Workers assets binding, with `/api/*`, `/health`, and `/device/*` still routed through the Worker.

## 6. Apply D1 Migrations

Apply alert-state migrations:

```sh
pnpm exec wrangler d1 migrations apply picket-alert-state --config workers/alert-router/wrangler.jsonc --remote
```

This applies the alert state, source health, source health history, query job, detection health, detection rule, query management, and scheduled detection state migrations in `workers/alert-router/migrations`. Source detail timelines begin collecting entries after `0008_source_health_history.sql` is applied; the migration does not backfill earlier batches or errors.

Apply auth migrations:

```sh
pnpm exec wrangler d1 execute picket-auth --config workers/admin/wrangler.jsonc --remote --file workers/admin/migrations/0001_better_auth.sql
pnpm exec wrangler d1 execute picket-auth --config workers/admin/wrangler.jsonc --remote --file workers/admin/migrations/0002_device_authorization.sql
```

## 7. Seed System User

```sh
node scripts/seed-system-user.mjs --remote
```

The seeded `system@picket.local` user owns MVP ingest API keys.

## 8. Configure Secrets

Set required secrets:

```sh
pnpm exec wrangler secret put BETTER_AUTH_SECRET --config workers/admin/wrangler.jsonc
pnpm exec wrangler secret put BETTER_AUTH_SECRET --config workers/ingest/wrangler.jsonc
pnpm exec wrangler secret put R2_SQL_TOKEN --config workers/query-runner/wrangler.jsonc
pnpm exec wrangler secret put R2_SQL_TOKEN --config workers/scheduled-detection/wrangler.jsonc
```

Set this secret if using natural-language query:

```sh
pnpm exec wrangler secret put ANTHROPIC_API_KEY --config workers/admin/wrangler.jsonc
```

Without `ANTHROPIC_API_KEY`, `POST /api/v1/query/natural` returns an error. Standard SQL query execution does not require it.

Set optional alert destination secrets:

```sh
pnpm exec wrangler secret put SLACK_WEBHOOK_URL --config workers/alert-router/wrangler.jsonc
pnpm exec wrangler secret put ALERT_WEBHOOK_URL --config workers/alert-router/wrangler.jsonc
pnpm exec wrangler secret put ALERT_WEBHOOK_AUTH_HEADER --config workers/alert-router/wrangler.jsonc
pnpm exec wrangler secret put ALERT_EMAIL_FROM --config workers/alert-router/wrangler.jsonc
pnpm exec wrangler secret put ALERT_EMAIL_TO --config workers/alert-router/wrangler.jsonc
```

Use the same `BETTER_AUTH_SECRET` value for `picket-admin` and `picket-ingest`.

## 9. Verify Bindings

Before sending production traffic, verify that the generated Wrangler configs no longer contain unresolved template placeholders:

```sh
grep -RE '__[A-Z0-9_]+__' workers/*/wrangler.jsonc
```

No output means every placeholder was filled from Terraform outputs. `pnpm gen:wrangler` already errors on any unknown or missing placeholder, so output here means the generated files are stale — rerun `pnpm gen:wrangler` from the repo root and inspect the Terraform outputs for missing streams.

Also verify the enrichment bindings if using IOC, asset, or user loaders:

- `workers/ingest/wrangler.jsonc` has `ENRICHMENT_KV`
- `workers/admin/wrangler.jsonc` has `ENRICHMENT_KV`
- `workers/admin/wrangler.jsonc` has `THREAT_INTEL_PIPELINE`, `ASSETS_PIPELINE`, and `USERS_PIPELINE`

## 10. Verify Runtime

Check unauthenticated health endpoints where routable:

```sh
curl https://<admin-hostname>/health
curl https://<admin-hostname>/api/v1/meta
```

For internal Workers without public routes, use Wrangler logs and queue/D1 state to confirm processing after an ingest request.

Useful local validation remains:

```sh
pnpm test
pnpm typecheck
```

Useful smoke checks after logging in through Cloudflare Access:

```sh
curl https://<admin-hostname>/api/v1/dashboard/overview
curl https://<admin-hostname>/api/v1/detections/scheduled
curl https://<admin-hostname>/api/v1/enrichment/iocs
```

The web console is served from the same admin hostname. Open `https://<admin-hostname>/` after `pnpm deploy:cloudflare` to verify the dashboard assets load.

## Undeploy

Delete Worker scripts first:

```sh
pnpm undeploy:cloudflare
```

Then destroy durable infrastructure:

```sh
cd terraform/platform
terraform destroy
```

If recreating Pipelines after a destroy, stale R2 Data Catalog tables can block sink creation. Use the helper if needed:

```sh
CF_ACCOUNT_ID=<account-id> R2_CATALOG_TOKEN=<token> node scripts/drop-catalog-tables.mjs
```

## Future: Terraform-Managed Worker Deployments

Terraform can also own Worker deployment. The missing piece is a build artifact step that emits self-contained Worker modules for Terraform to upload.

Target shape:

- Add a bundle script that writes deployable modules under `dist/workers/*/index.js`
- Add `cloudflare_worker`, `cloudflare_worker_version`, and `cloudflare_workers_deployment` resources
- Move D1, Queue, Service, Durable Object, Pipeline, cron, and send-email bindings from `wrangler.jsonc` into Terraform
- Keep secret values managed through Wrangler or another non-state secret workflow

Once that is in place, `scripts/gen-wrangler.mjs` and most environment-specific Wrangler IDs can go away.
