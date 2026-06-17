# Alert State Migrations

These D1 migrations define the mutable alert state described in `PRD.md`: alert status, analyst notes, lifecycle timeline entries, per-source ingestion health (`source_health`, used by `picket status` and written by `picket-ingest`), and the capped source batch/error timeline used by the web console (`source_health_history`).

The `source_health` table lives in this database — and these migrations live in the alert-router dir — because `picket-alert-state` is the existing shared D1 across ingest/detection/admin/alert-router (`migrations_dir` in each worker's `wrangler.jsonc` points here).

Terraform creates the database in `terraform/platform`. Apply these migrations to that database with Wrangler once the concrete D1 database ID is available in the Worker config.

```sh
wrangler d1 migrations apply picket-alert-state --config workers/detection/wrangler.jsonc --remote
```
