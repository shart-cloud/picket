# Picket Roadmap (post-MVP)

Status as of the MVP-conformance scan: MVP (Phase 0) is ~95% complete and green.
This roadmap drives Picket forward as a **CLI/API product** — the Phase 2 frontend
is deliberately parked. Sequencing decision: **MVP hardening first**, then Phase 1.

Recommended order: **M0 → M1 → (M2 ∥ M3) → M4**. M2 and M3 can run in parallel once
the API spine (M1) and real OCSF validation (M0.1) are solid.

---

## Milestone 0 — MVP Hardening — ✅ DONE

Close the scan gaps before adding surface area. These get cheaper now and far more
expensive once 6–8 more sources and a bigger API depend on them.

| #   | Task | Status | Notes |
|-----|------|--------|-------|
| 0.1 | **Real OCSF schema validation** — per-class field/type/enum checks. | ✅ | New `packages/core/src/ocsf-schema.ts`; `validateOcsfEvent` returns all issues, `assertOcsfEvent` throws `OcsfValidationError`. Surfaced + fixed a batch bug: CloudTrail/Cloudflare now drop bad records per-record like k8s. |
| 0.2 | **k8s normalizer tests** — all 4 flavors + `parseNdjson`/`flavorOfRecord`. | ✅ | +10 tests in `packages/normalize`, each asserting OCSF validity. |
| 0.3 | **Wire `assignee`** — `assignAlert()`, `PATCH /api/v1/alerts/:id`, CLI `picket alerts assign`. | ✅ | Assignee in `AlertDetail` + detail view; PATCH does status and/or assignee. |
| 0.4 | **Detection-engine health in `picket status`**. | ✅ | New `detection_health` singleton (migration 0004) + `@picket/core/detection-health`; detection worker heartbeat; `GET /api/v1/detections/health`; rendered in `picket status`. |
| 0.5 | **Polish** — GKE `Content-Type`; `sql`/`geo_velocity` execution kinds. | ✅ | GKE forwarder now emits true NDJSON. Decision: keep `sql` (M3 implements it) and the `geo_velocity` type (M3), but the realtime engine now **warns** on any enabled non-threshold stateful rule instead of silently skipping. |

**Exit:** all records pass real OCSF validation; k8s normalizers covered; no orphaned
schema/silent dead branches. `pnpm test && pnpm typecheck` green.

---

## Milestone 1 — Phase 1 REST API (the spine) — ✅ DONE

Finish the analyst API. ~40% existed at MVP (alerts CRUD, async query, sources list,
device auth). All route groups below now shipped (enrichment deferred to M4). Status by route group:

- **`/api/v1/detections`** — ✅ **DONE**. Rule registry in D1 (migration 0005 `detection_rules`) seeded idempotently from the bundle by the detection worker (preserves operator `enabled` override + match stats). `GET /`, `GET /:id`, `PATCH /:id` (enable/disable). Worker honors runtime disable (TTL-cached) and records per-rule match stats. CLI `picket detections list/show/enable/disable`. `@picket/core/detection-rules`.
- **`/api/v1/sources/:id`** — ✅ **DONE**. `/status` (single-source health via `getSourceHealth` + freshness classification), `/schema` (OCSF field list from `@picket/core/sources` — `OCSF_EVENT_FIELDS` mirrors the flattened event columns; Data Catalog introspection deferred), `/sample` (R2 SQL `SELECT * … ORDER BY time DESC LIMIT 10` through the async query-job flow — the POST `/query` submit+poll tail was extracted to a shared `submitQueryJob()` helper). Unknown sources 404. CLI `picket sources status|schema|sample <id>`. `@picket/core/sources`.
- **`/api/v1/alerts/stats`** — ✅ **DONE**. `alertStats()` in `@picket/core/alerts` runs GROUP BY aggregations over the `alerts` table (severity/status returned across the full canonical scale with zero buckets; rule/source ordered by count desc). `GET /api/v1/alerts/stats` (registered before `/:id`). CLI `picket alerts stats [--format table|json]`. (Unified `PATCH /:id` already shipped in M0.3.)
- **`/api/v1/query`** extensions — ✅ **DONE**. Migration `0006_query_management.sql` adds `saved_queries` (upsert by owner+name) and `query_history` (append-only). `POST /explain` (validate + structural plan via new `explainQuery`/`planR2Sql` in `@picket/query`, no execution), `POST /save`, `GET /saved`, `GET /history` (all registered before `/:id`). Submitting a query now logs to `query_history` best-effort from the shared `submitQueryJob()`. `@picket/core/saved-queries`. CLI `picket query explain|save|saved|history` (subcommands dispatched ahead of the bare-flags execution form). **⚠ Deploy: migration 0006 must be applied (`wrangler d1 migrations apply`).**
- **`/api/v1/dashboard/overview`** — ✅ **DONE**. `buildDashboardOverview()` in `@picket/core/dashboard` composes source_health (with per-source `healthy/stale/unknown` classification + summary counts), `alertStats()`, and detection health + rule counts (total/enabled/disabled) into one payload. Health classified server-side against an injectable `now`. `GET /api/v1/dashboard/overview[?tenant=]`. CLI `picket dashboard [--tenant <id>] [--format table|json]`.
- **`/api/v1/enrichment`** — deferred to M4 (depends on enrichment tables).

**Exit:** PRD §Phase 1 metric — `<500ms` for all non-query endpoints; every endpoint
covered by admin-worker tests ✅; CLI gains `picket detections list/show/toggle` ✅,
`alerts stats`, `dashboard`, `sources status/schema/sample`, `query explain/save/saved/history` ✅.
**Deploy note:** migration `0006_query_management.sql` must be applied on next deploy.

---

## Milestone 2 — Additional Log Sources (breadth) — ✅ DONE

One repeatable pattern per source: Terraform module + forwarder + `normalize<Source>()`
+ OCSF validation (M0.1) + 2–3 default Sigma rules + fixtures + tests. Sequence by
payoff/effort:

1. **AWS VPC Flow Logs** → OCSF Network Activity *(reuses CloudTrail S3→SQS→Lambda)*
2. **AWS GuardDuty** → Detection Finding *(EventBridge→Lambda)*
3. **GCP Cloud Audit** → API Activity *(reuses GKE Pub/Sub→Function)*
4. **Azure Activity + Azure AD Sign-in** → API Activity / Authentication *(reuses AKS Event Hub→Function)*
5. **GitHub Audit Log** → API Activity *(webhook→Worker, no cloud dep — cheap dogfood)*
6. **M365 Management Activity** → Email/Auth *(polling Worker)*

Current backend source status:

- **AWS VPC Flow Logs** — ✅ normalized ingest path, pipeline/table, fixtures/tests, and default rules exist.
- **AWS GuardDuty** — ✅ normalized ingest path, pipeline/table, fixture/test, high-severity default rule, and provider-side EventBridge/Lambda Terraform module exist.
- **GCP Cloud Audit** — ✅ normalized ingest path, pipeline/table, fixture/test, IAM policy-change default rule, and provider-side Pub/Sub/Function Terraform module exist.
- **Azure Activity** — ✅ normalized ingest path, pipeline/table, fixture/test, role-assignment default rule, and provider-side Event Hub/Function Terraform module exist.
- **Azure AD Sign-in** — ✅ normalized ingest path, pipeline/table, fixture/test, default rules, and provider-side Entra diagnostic setting/Event Hub/Function Terraform module exist.
- **GitHub Audit** — ✅ normalized ingest path, pipeline/table, fixture/test, default rules, and provider-side webhook/poller collection pattern documented. No first-party Terraform module: GitHub audit streaming/polling is not cleanly exposed by the existing provider surface.
- **Cloudflare Audit** — ✅ normalized ingest path, pipeline/table, fixture/test, default rules, and provider-side Logpush module exist.
- **Microsoft 365 Management Activity** — ✅ normalized ingest path, pipeline/table, fixture/test, default rules, and provider-side polling pattern documented. No first-party Terraform module: Management Activity polling needs app secrets plus durable API cursor state, which fits a future Worker/poller backend better than Terraform-only IaC.

Okta stays deferred (no test tenant). New sources need a Pipeline + Iceberg table
in `terraform/platform` (and the `PICKET_TABLE_SUFFIX` hand-sync gotcha), plus
provider-side collection modules where noted above.

**Exit:** PRD metric — 10+ sources with platform Pipeline/Iceberg tables and provider collection modules or documented patterns; each table queryable via `wrangler r2 sql query` after Terraform apply and `gen:wrangler`.

---

## Milestone 3 — Scheduled SQL Detections — ✅ DONE

Cron-triggered Worker for aggregation rules R2 SQL can express but the runtime engine can't.

- **Shared alert emission** — ✅ `upsertAlertState`/`persistAlerts`, `writeAlertsToPipeline`, `enqueueAlerts` extracted from `workers/detection` into `@picket/core/alert-emit`; the detection worker now delegates via thin env-aware wrappers. Both producers route alerts through one path.
- **Rule model + bundling** — ✅ `execution: sql` rules carry a `sql:` block (`query`/`interval`/`threshold`/`count_field`/`group_by`); `@picket/sigma-engine` `ScheduledSqlConfig`, `detection` now optional. `@picket/rules` loader parses it; `bundle-rules.mjs` emits `SQL_RULES` to the scheduled worker (atomic temp-file+rename write to avoid the concurrent-`build:rules` race). Example rule `rules/aws-iam-privilege-escalation-spike.yml`.
- **`workers/scheduled-detection`** — ✅ cron `*/5 * * * *`. Each tick: seed sql rules into `detection_rules` registry, honor operator disables, run each *due* rule (interval vs `last_run_at`) via the `@picket/query` executor (`applyTableSuffix` rewrites bare table names to the deployed suffix), synthesize **one alert per result row over threshold** (dedupe from rule + `group_by`, summary OCSF event), route via the shared emission path, and record per-rule run health.
- **Migration 0007** `scheduled_detection_state` (rule_id, last_run_at, last_status, last_row_count, last_alert_count, last_error). `@picket/core/scheduled-detection`.
- **Rule templates** — ✅ single-source (`aws-iam-privilege-escalation-spike`), threat-intel JOIN (`aws-cloudtrail-threat-intel-ip-match`), and cross-source JOIN (`aws-k8s-cross-source-identity`).
- **Run-health surface** — ✅ `listScheduledDetections()` joins the sql rules with `scheduled_detection_state` + a computed `due` flag. `GET /api/v1/detections/scheduled`; CLI `picket detections scheduled`. Also closed a pre-existing gap: the whole `/api/v1/detections` group is now Cloudflare-Access-gated (it wasn't before).

**Exit:** PRD metric — scheduled execution within 30s of schedule; alerts flow through
the same dedup/routing path. **Deploy:** apply migration 0007; set `PICKET_R2_WAREHOUSE`/`PICKET_TABLE_SUFFIX` vars + `R2_SQL_TOKEN` secret on `picket-scheduled-detection`.

---

## Milestone 4 — Enrichment + NL Query — ✅ DONE

- **NL Query** — ✅ **DONE**. `POST /api/v1/query/natural` (`{ question }`): builds a system prompt from the OCSF column schema (`OCSF_EVENT_FIELDS`) + the deployed source tables (suffix-applied) + R2 SQL constraints (`R2_SQL_CAPABILITIES`), calls Claude, validates with `validateR2Sql`, then runs the generated SQL through the existing `submitQueryJob` flow and returns `generated_sql` + `rationale` alongside the job/results (422 with the rejected SQL when validation fails). `@picket/query/natural`: injectable `NlSqlClient` + `createAnthropicNlSqlClient` (small fetch client to the Messages API — forced `emit_query` tool call, no prefill/temperature, default `claude-opus-4-8`, overridable via `PICKET_NL_QUERY_MODEL`). CLI `picket query natural "<question>"` (prints generated SQL to stderr, results to stdout). **Deploy:** set `ANTHROPIC_API_KEY` secret on `picket-admin` (route 500s without it). Net-new Anthropic integration uses a fetch client rather than `@anthropic-ai/sdk` to keep the Worker bundle light + tests fake-injectable.
- **Enrichment (ingest-time KV path)** — ✅ **DONE**. `@picket/core/enrichment`: IOC store over the `picket-config` KV namespace (`ioc:<type>:<indicator>` keys; descriptive fields mirrored into KV metadata so list avoids a GET per key) + `enrichEvents(events, kv)` which stamps a `threat_match` onto events whose src/dst IPs hit the store (batch-deduped lookups, best-effort). New `threat_match` field on `OcsfEvent` → 5 flattened columns (`threat_match_indicator`/`_indicator_type`/`_field`/`_feed_name`/`_threat_type`) → terraform `event_field_columns`. `workers/ingest` binds `ENRICHMENT_KV` and stamps after normalize, before the detection post + pipeline write, so both real-time detection and the Iceberg tables see the match. `/api/v1/enrichment/iocs` admin routes (GET list, POST add one/many, DELETE; Access-gated, 503 when KV unbound). CLI `picket enrichment list/add/remove/import-csv`. **Deploy:** apply the updated event-stream terraform schema (5 new columns) and bind the `picket-config` KV namespace (`kv_namespaces` already added to `picket-ingest` + `picket-admin` wrangler.jsonc, id `e70fbf31…`).
- **Enrichment (query-time Iceberg path)** — ✅ **DONE for MVP loaders**. Terraform provisions suffixed `threat_intel`/`assets`/`users` Iceberg dimension tables via Pipeline streams/sinks. `/api/v1/enrichment/iocs` writes IOCs to KV and appends `threat_intel` changelog rows (`active=true` on add/import, `active=false` tombstones on delete) through a `THREAT_INTEL_PIPELINE` binding; `/api/v1/enrichment/iocs/import` accepts CSV feeds; `/api/v1/enrichment/assets` and `/api/v1/enrichment/users` load JSON batches into their dimension tables through `ASSETS_PIPELINE`/`USERS_PIPELINE`. CLI: `picket enrichment import-csv`, `load-assets`, `load-users`. The shipped `aws-cloudtrail-threat-intel-ip-match` SQL rule filters out superseded/tombstoned indicators. Future: STIX/TAXII polling and source-specific directory sync connectors.

**Exit:** NL query, ingest-time IOC enrichment, and query-time dimension loaders are shipped. Deploy requires `ANTHROPIC_API_KEY` for NL query, synced KV/Pipeline bindings for enrichment, and the updated event-stream schema with the `threat_match_*` columns.

---

## Milestone 5 — Web Console Workflow Depth — 🚧 IN PROGRESS

The `apps/web` console exists and covers the top-level PRD nouns: dashboard, alerts, alert detail, detections, sources, and query. The next product work is turning those thin surfaces into analyst workflows.

Recommended sequence:

1. **Alert Triage v1** — ✅ **DONE**. URL-backed severity/status/source/rule/time filters, server-side sorting and pagination, bulk acknowledge/resolve, event context summaries, and IOC/threat-match display.
2. **Query Explorer v1** — ✅ **DONE**. SQL and natural-language modes, execute/explain, generated-SQL editing, saved query/history browser, sortable tabular results, and CSV/JSON export. Advanced editor autocomplete remains parked.
3. **Source Detail v1** — ✅ **DONE**. Tenant-safe source routes, current health/counters, OCSF schema browser, recent R2 SQL sample events with JSON expansion, recent errors, and a capped ingestion history timeline. Migration `0008_source_health_history.sql` records batch/error activity and retains the latest 500 entries per source/tenant.
4. **Detection Detail v1** — 🚧 **NEXT**. Rule detail, scheduled run health, recent matches, and enable/disable state in context.

**Exit:** the console supports the PRD Phase 2 core loop: open an alert, understand why it fired, inspect the triggering event/context, take an action, and pivot into a query.

---

## Parked

- **Advanced frontend features** — real-time WebSocket push, charting, Monaco/CodeMirror autocomplete, detection backtesting UI, and enrichment feed management beyond basic loaders.
- **Phase 3** — multi-tenancy (the better-auth `organization` plugin is the seam), SOAR-lite, case management, compliance reports. Roadmap-only.
