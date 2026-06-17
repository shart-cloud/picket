# Product Requirements Document: Picket

## Serverless SIEM on Cloudflare Workers

**Author:** Jared Gore
**Status:** Draft
**Last Updated:** May 2026

---

## Executive Summary

Picket is an open-source, serverless Security Information and Event Management (SIEM) platform built on Cloudflare's edge infrastructure. It uses R2 Data Catalog for Apache Iceberg storage, Cloudflare Pipelines for ingestion, R2 SQL for analytics, Workers for compute, and Durable Objects for stateful detection correlation.

The project is a spiritual successor to Matano (an open-source serverless security data lake on AWS, now abandoned). Picket differentiates itself by: targeting Cloudflare's platform instead of AWS, providing Terraform modules that automate log source provisioning across AWS/Azure/GCP/SaaS, evaluating Sigma YAML rules directly against normalized OCSF events, and shipping a frontend for alert triage and threat hunting — something Matano never delivered.

The primary audience is small-to-mid security teams (1–10 analysts) who want a cost-effective, self-hosted SIEM without the operational burden of Elastic/Splunk or the vendor lock-in of a commercial cloud SIEM.

---

## Problem Statement

Security teams face a painful set of trade-offs when choosing a SIEM:

- **Commercial SIEMs** (Splunk, Sentinel, Chronicle) are expensive at scale and create vendor lock-in. Pricing is often per-GB-ingested, which discourages comprehensive log collection.
- **Open-source SIEMs** (ELK/Elastic Security, Wazuh) require significant infrastructure management — Elasticsearch clusters, index lifecycle policies, capacity planning — and break under load without dedicated engineering effort.
- **Security data lakes** (Matano, Amazon Security Lake) solve cost and scale but lack the detection, alerting, and investigation workflows that make a tool a *SIEM* rather than just a *lake*.
- **Log source onboarding** is universally painful. Every SIEM requires manual configuration of IAM roles, log exports, API credentials, and format mappings per source. This is the #1 reason security teams have incomplete log coverage.

Picket addresses all four: serverless (zero infrastructure management), open table format (zero vendor lock-in), built-in detection and alerting (it's a SIEM, not just a lake), and Terraform-automated log source provisioning (onboarding a new source is `terraform apply`).

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        LOG SOURCES                                  │
│  AWS CloudTrail │ Kubernetes │ Azure AD │ GCP Audit │ O365 │ GitHub │ … │
└───────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────┘
        │          │          │          │          │          │
        ▼          ▼          ▼          ▼          ▼          ▼
┌─────────────────────────────────────────────────────────────────────┐
│               TERRAFORM PLATFORM MODULES                            │
│  Per-source modules that provision IAM roles, log sinks, and       │
│  forwarder functions (Lambda / Cloud Function / Azure Function /   │
│  Fluent Bit). Shared: R2, Data Catalog, Pipelines, Workers, D1.    │
└───────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────┘
        │          │          │          │          │          │
        ▼          ▼          ▼          ▼          ▼          ▼
┌─────────────────────────────────────────────────────────────────────┐
│           PICKET-INGEST (single Worker, POST /events)               │
│  Hono app. One public endpoint accepts every source.                │
│  • Authenticates each request via tenant API key (x-api-key)        │
│  • Per-key metadata.source identifies the log source                │
│  • Dispatches to @picket/normalize (CloudTrail, k8s, Cloudflare…)  │
│  • Per-source body-size caps + per-key rate limits                  │
│  • Forwards normalized OCSF events to the detection Worker          │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                    ┌───────────┼───────────┐
                    ▼                       ▼
┌──────────────────────────┐  ┌──────────────────────────────────────┐
│   DETECTION WORKER       │  │        CLOUDFLARE PIPELINE           │
│   (Runtime Sigma engine) │  │   Schema validation → batching →    │
│   Evaluates every event  │  │   Parquet serialization → R2 write  │
│   against Sigma YAML     │  │   → Iceberg table in Data Catalog   │
│   rules.                 │  │                                      │
│                          │  └──────────────────────────────────────┘
│   Durable Objects hold   │                    │
│   windowed state for     │                    ▼
│   correlation rules.     │  ┌──────────────────────────────────────┐
│                          │  │            R2 SQL                     │
│   Alert matches →        │  │   Serverless distributed query       │
│   Queues → fanout.       │  │   engine over Iceberg tables.        │
└──────────┬───────────────┘  │   Supports JOINs, subqueries, CTEs. │
           │                  │   Used by: scheduled detections,     │
           ▼                  │   API query endpoint, CLI, frontend. │
           ▼                  └──────────────────────────────────────┘
┌──────────────────────────┐
│     ALERT ROUTING        │
│  Slack │ Email │ Webhook │
│  PagerDuty │ SNS │ …     │
│                          │
│  Alerts also written to  │
│  Iceberg alerts table.   │
└──────────────────────────┘

      ┌──────────────────────────────────────────────────────────────┐
      │  PICKET-ADMIN (Hono, gated by Cloudflare Access)             │
      │  Mounts better-auth's api-key CRUD routes for operators.     │
      │  Shares the picket_auth D1 database with picket-ingest.      │
      └──────────────────────────────────────────────────────────────┘
```

**Two distinct auth boundaries** run in the platform:

- **Machine ingest** — forwarders authenticate to `picket-ingest` with a tenant API key (`x-api-key` header) issued by better-auth. Each key is scoped to a single source via metadata and rate-limited per key.
- **Human operators** — `picket-admin` (and the Phase 1 REST API) sit behind Cloudflare Access for SSO/IdP-backed login. Access-gated workers verify the Access JWT before invoking better-auth's admin endpoints.

---

## Phased Delivery

### Phase 0 — MVP: Prove the Data Plane

**Goal:** Demonstrate end-to-end log ingestion, detection, alerting, and querying on Cloudflare. CLI-only. No frontend. Deployable by a technical user in under 30 minutes.

**Target timeline:** 8–12 weeks from start.

---

#### MVP Feature 1: Core Platform Infrastructure

**Description:** A Terraform root module that provisions the durable Cloudflare resources needed for the SIEM to function. Worker bundle deployment is handled by Wrangler during the MVP; Terraform owns durable infrastructure while Wrangler owns code deployment.

**Resources provisioned:**
- R2 bucket with Data Catalog enabled
- Cloudflare Pipelines (one per log source table, plus one for the alerts table)
- `picket-ingest` Worker — single public ingest endpoint (`POST /events`), Hono app, dispatches by source from the verified API key's metadata
- `picket-admin` Worker — Hono app behind Cloudflare Access, mounts better-auth's API-key CRUD routes
- `picket-detection` Worker (runtime Sigma evaluation engine; service-bound, not publicly routed)
- `picket-alert-router` Worker (Queue consumer, fans out to Slack/webhook/email)
- Cloudflare Queue for alert fanout and a second Queue for asynchronous R2 SQL query jobs
- D1 database `picket-alert-state` for alert state (status, analyst notes, acknowledgment), source health, and asynchronous query job state
- D1 database `picket-auth` for the better-auth schema (users, API keys, organizations) — bound to both `picket-ingest` and `picket-admin`
- KV namespace for real-time enrichment data and configuration (threat intel IOCs also stored as an Iceberg table for query-time JOIN enrichment)
- Shared TypeScript packages: `@picket/api` (Hono middleware + better-auth factory), `@picket/normalize` (per-source OCSF mappers), `@picket/core` (OCSF types and D1 storage helpers), `@picket/sigma-engine`, `@picket/rules`, and `@picket/query`

**User experience:**
```hcl
module "picket_platform" {
  source = "github.com/picket/terraform-cloudflare-picket"

  cloudflare_account_id = var.cloudflare_account_id
  r2_bucket_name        = "picket-lake"
  alert_destinations    = {
    slack_webhook = var.slack_webhook_url
  }
}
```

`terraform apply` → platform is ready to receive logs.

**Acceptance criteria:**
- Platform durable infrastructure deploys successfully with `terraform apply`, followed by Worker deployment via Wrangler
- R2 bucket exists with Data Catalog enabled
- Pipeline endpoints are reachable and accept HTTP POST
- `picket-ingest` is deployed, healthy at `GET /health`, and rejects `POST /events` without a valid `x-api-key`
- `picket-admin` is deployed behind Cloudflare Access and exposes better-auth's API-key CRUD endpoints
- `picket-detection` is deployed and reachable via service binding from `picket-ingest`
- Alert Queue and `picket-alert-router` are functional
- Query Jobs Queue and `picket-query-runner` are functional for async R2 SQL execution
- Teardown via `terraform destroy` is clean

---

#### MVP Feature 2: Log Source Modules (3 Sources)

**Description:** Terraform modules that configure log export and deploy thin forwarder functions for three initial log sources. Every forwarder targets the same destination — `POST /events` on `picket-ingest` — and authenticates with a per-tenant API key sent in the `x-api-key` header. Source identification, normalization, and dispatch all happen inside `picket-ingest` based on the verified key's `metadata.source`. Forwarders do not normalize; they push raw provider payloads.

**Sources for MVP:**

**AWS CloudTrail:**
- Terraform module creates: IAM role (cross-account, least privilege), CloudTrail trail (if not existing) or references existing trail, S3 bucket notification → SQS → Lambda forwarder. The API key is stored in AWS Secrets Manager and fetched on cold start.
- Lambda forwarder: reads CloudTrail JSON from S3 and POSTs to `picket-ingest` with `x-api-key`. Normalization (CloudTrail JSON / `{Records:[]}` → OCSF `Authentication` / `API Activity` / `Account Change`) runs inside `picket-ingest` via `normalizeCloudTrail` from `@picket/normalize`.
- OCSF mapping covers: `actor`, `src_endpoint`, `dst_endpoint`, `api.operation`, `api.service.name`, `status`, `time`, `cloud.provider`, `cloud.region`, `cloud.account.uid`

**Kubernetes Audit Logs:**
- Terraform module is a parent with four flavor-specific submodules:
  - **EKS** — enables EKS control-plane audit log export to CloudWatch Logs, provisions a Lambda subscription filter that POSTs records to `picket-ingest` as NDJSON with `x-api-key`
  - **GKE** — configures Cloud Logging sink for `k8s_cluster` audit logs → Pub/Sub topic → Cloud Function forwarder; API key stored in GCP Secret Manager
  - **AKS** — enables Diagnostic Settings on the AKS cluster for `kube-audit` / `kube-audit-admin` categories → Event Hub → Azure Function forwarder; API key stored in Azure Key Vault and bound via Key Vault references
  - **Generic / self-hosted** — Helm-installable Fluent Bit DaemonSet that tails the API server audit log file and POSTs `json_lines` batches directly to `picket-ingest` with `X-Api-Key` (no cloud provider dependency)
- `picket-ingest` parses the NDJSON body, calls `normalizeK8sAudit(record, { flavor })` per record, and emits OCSF `API Activity` events. Flavor is inferred per record from `cloud_provider`.
- OCSF mapping covers: `actor.user` (from `user.username` + `user.groups`), `api.operation` (from `verb`), `api.service.name` (= `kubernetes`), `api.request`/`api.response` (from `requestObject`/`responseObject` when present), `src_endpoint` (from `sourceIPs`), `status` (from `responseStatus.code`), `time` (from `requestReceivedTimestamp`), `cloud.*` (provider/region/account per flavor), and k8s-specific fields preserved under an `unmapped.kubernetes` namespace (`objectRef`, `stage`, `auditID`)

**Cloudflare Audit Logs (dogfood source):**
- Terraform module creates: Cloudflare Logpush job → `picket-ingest` via Logpush HTTP destination (with `x-api-key` as a custom header) or R2 → polling Worker
- `picket-ingest` normalizes to OCSF `API Activity` via `normalizeCloudflareAudit`
- Minimal mapping since this is primarily for dogfooding and demonstrating the platform

**Shared normalization library:**
- TypeScript package (`@picket/normalize`) used by `picket-ingest`
- Exports per-source mapping functions: `normalizeCloudTrail(raw)`, `normalizeK8sAudit(raw, { flavor })`, `normalizeCloudflareAudit(raw)`, plus body-format helpers `parseNdjson` and `flavorOfRecord` for k8s
- All functions return OCSF-compliant JSON
- Includes OCSF schema validation (runtime type checking against OCSF category/class definitions)
- Pure functions with zero Cloudflare/Workers coupling — also usable from Node forwarders if a source ever needs to pre-normalize

**API key issuance:**
- Operators mint per-tenant, per-source API keys via `picket-admin` (gated by Cloudflare Access). Keys carry `metadata.source` (e.g., `aws_cloudtrail`, `kubernetes_audit`) and `metadata.tenant_id`. The plain-text key is shown once at creation and stored only as a SHA-256 hash in the `picket-auth` D1 database. Per-key rate limiting is enforced by better-auth's api-key plugin.

**Acceptance criteria:**
- Each Terraform module deploys with a single `terraform apply` given valid provider credentials
- CloudTrail events appear in the `aws_cloudtrail` Iceberg table within 5 minutes of the event occurring in AWS
- Kubernetes audit events appear in the `kubernetes_audit` Iceberg table within 60 seconds (cloud-managed flavors) or 30 seconds (generic Fluent Bit) of the event occurring on the API server
- Cloudflare audit events appear in the `cloudflare_audit` Iceberg table within 60 seconds
- All records pass OCSF schema validation
- Each table is queryable via `wrangler r2 sql query`

---

#### MVP Feature 3: Detection Engine (Real-time)

**Description:** A Cloudflare Worker that evaluates every ingested event against a set of Sigma detection rules and produces alert records.

**Architecture:**
- The detection Worker sits in the ingestion path: `picket-ingest` → detection Worker (service binding) → Pipeline. Events always reach the Pipeline (detections do not block ingestion); the Worker evaluates rules as a side effect. The detection Worker is not publicly routed — it is reachable only via Cloudflare service binding from `picket-ingest`.
- Detection rules are Sigma YAML files parsed at build time and embedded into the Worker bundle as typed rule objects.
- For stateless rules (simple field matching / pattern detection), the Worker evaluates the Sigma detection block directly at runtime and returns a list of matched rule IDs.
- For stateful rules (threshold / correlation over time windows), a Durable Object per correlation key (e.g., source IP, user ID) holds the event window. The Worker routes events to the appropriate Durable Object, which maintains the sliding window and evaluates threshold conditions.
- When a rule matches, the Worker writes an alert record to the alerts Pipeline (which lands in the `picket_alerts` Iceberg table) and enqueues an alert message to the Cloudflare Queue for fanout.

**MVP detection rules (shipped as defaults):**
1. AWS root account usage (CloudTrail)
2. Console login without MFA (CloudTrail)
3. IAM policy attached to user (CloudTrail — detects privilege escalation)
4. Anonymous or unauthenticated request to Kubernetes API server succeeded (k8s audit, stateless — `user.username` in (`system:anonymous`, `system:unauthenticated`) and `responseStatus.code` < 400)
5. Excessive failed Kubernetes API-server auth — 10+ `Forbidden`/`Unauthorized` responses from same `sourceIPs[0]` in 5 minutes (k8s audit, stateful/Durable Object)

Okta normalization and rules are useful future work but are not part of the MVP acceptance path because the project does not currently have a reliable Okta tenant for live ingestion testing.

**Sigma rule tooling (`picket rules`):**
- CLI tooling (TypeScript, runs via `npx`)
- Input: directory of Sigma YAML files
- Output: generated TypeScript module containing parsed stateless Sigma rule objects for the detection Worker bundle
- Handles Sigma `detection` block selections, filters, and boolean conditions directly in the runtime TypeScript engine
- Handles `logsource` → OCSF event class routing
- Stateful rules (those with `count`, `temporal`, or `near` conditions in Sigma) are flagged and generate Durable Object routing metadata
- Rules that are better expressed as SQL (heavy aggregation, long time windows) generate `.sql` files, tagged for the scheduled detection path

**Acceptance criteria:**
- Default Sigma rules parse and bundle without errors
- Detection Worker starts with embedded stateless Sigma rules
- Detection Worker evaluates a synthetic CloudTrail root-login event and produces an alert within 2 seconds
- Durable Object correctly tracks a 5-minute sliding window and fires the excessive-failed-auth alert on the 10th forbidden/unauthorized response from the same source IP
- Alert records appear in the `picket_alerts` Iceberg table
- Alert messages arrive in the configured Slack webhook
- Custom Sigma rules can be added to the rules directory and bundled/deployed via CLI

---

#### MVP Feature 4: CLI

**Description:** A CLI tool (`picket`) that wraps platform operations, query execution, and detection management.

**Commands:**

`picket init` — Post-MVP interactive setup wizard. Generates a Terraform variable file and a Picket project directory structure:
```
my-picket/
├── terraform/
│   ├── main.tf            # platform module + source modules
│   └── variables.tf
├── detections/
│   ├── aws_root_login/
│   │   └── rule.yml       # Sigma YAML
│   ├── brute_force/
│   │   └── rule.yml
│   └── ...
├── enrichment/
│   └── threat_intel.csv   # optional IOC lists
└── picket.config.yml    # project config
```

`picket deploy` — Post-MVP wrapper that bundles Sigma rules, deploys Workers, and coordinates any changed infrastructure via Terraform. For MVP, local deployment is handled by `pnpm deploy:cloudflare` after `terraform apply`.

`picket query <sql>` — Executes an R2 SQL query against the lake either through the admin API's async query job flow or directly with an R2 SQL token. Supports output formats: `--format table|json|csv`. Includes predefined query aliases:
- `picket query --preset iam-changes --hours 48`
- `picket query --preset threat-intel-ip-matches --hours 24`
- `picket query --preset failed-logins --hours 24` once Okta or another authentication source is enabled

`picket alerts list` — Lists recent alerts with filtering by severity, rule, source, time range, and status (open/acknowledged/resolved).

`picket alerts ack <alert-id>` — Acknowledge an alert.

`picket status` — Shows ingestion health per source (last event time, event rate, error count) and detection engine status.

`picket test <rule-path>` — Post-MVP dry-run of a detection rule against historical data in the lake. Runs the Sigma rule against a time range of events and reports what would have matched.

**Acceptance criteria:**
- MVP local deployment is documented and works through `terraform apply`, binding sync, and `pnpm deploy:cloudflare`
- `picket query` returns results from R2 SQL with correct formatting
- `picket alerts list` shows alerts written by the detection engine
- `picket status` accurately reflects ingestion health
- Post-MVP: `picket init`, `picket deploy`, and historical `picket test` provide the polished project workflow

---

#### MVP Feature 5: Alert Routing

**Description:** A fanout Worker that consumes alert messages from the Cloudflare Queue and delivers them to configured destinations.

**Destinations for MVP:**
- **Slack** — Formatted message with alert title, severity, matched rule, source event summary, and a link to the event in the query explorer (placeholder URL until frontend exists)
- **Webhook** — Generic HTTP POST with full alert JSON payload, configurable URL and headers
- **Email** — Via Cloudflare Email Workers, simple HTML-formatted alert summary

**Alert lifecycle:**
- Alert is created by the detection Worker with status `open`
- Alert record is written to the `picket_alerts` Iceberg table (for querying/history)
- Alert metadata (status, notes, assignee) is written to D1 (for mutable state)
- Alert message is enqueued to Cloudflare Queue
- Fanout Worker delivers to all configured destinations
- Analyst acknowledges/resolves via CLI (`picket alerts ack`)
- D1 record is updated; Iceberg record is immutable (append-only audit trail)

**Alert deduplication:**
- Each detection rule defines a `dedupe_key` (e.g., `source.ip` for brute force, `actor.user.uid` for impossible travel)
- Alerts with the same rule ID + dedupe key within a configurable window (default 15 minutes) are grouped into a single alert with an incrementing match count
- Deduplication state is managed in D1 by looking up open or acknowledged alerts with the same rule ID + dedupe key inside the dedupe window. Durable Objects are reserved for streaming correlation state, such as threshold windows.

**Acceptance criteria:**
- Slack messages arrive within 10 seconds of detection firing
- Webhook payloads contain complete alert data and are parseable
- Email alerts are delivered and readable
- Duplicate detections within the dedup window increment the existing alert rather than creating a new one
- Alert status changes via CLI are reflected in D1

---

### Phase 1 — API Layer & Additional Sources

**Goal:** Expose all platform functionality via a REST API. Expand log source coverage. Prepare the data contracts the frontend will consume.

**Target timeline:** 6–8 weeks after MVP.

---

#### Phase 1 Feature 1: REST API

A set of Cloudflare Workers behind Cloudflare Access (SSO/IdP authentication) that expose the full platform surface.

**Endpoints:**

`/api/v1/sources`
- `GET /` — List configured log sources with health metadata
- `GET /:id/status` — Ingestion health for a specific source (last event, rate, errors)
- `GET /:id/schema` — OCSF schema for the source's table
- `GET /:id/sample` — Recent sample events

`/api/v1/query`
- `POST /` — Submit an R2 SQL query or preset as an async query job. The handler validates SQL, enqueues `{ job_id }`, long-polls briefly for fast jobs, and otherwise returns a polling location.
- `GET /:id` — Fetch async query job status and result.
- `POST /execute` — Optional later compatibility endpoint for synchronous-style clients; may wrap the async job flow rather than executing inline.
- `POST /explain` — Returns the execution plan for a query without running it
- `GET /history` — Query history for the authenticated user
- `POST /save` — Save a named query
- `GET /saved` — List saved queries

`/api/v1/alerts`
- `GET /` — List alerts with filtering (severity, rule, source, time range, status)
- `GET /:id` — Alert detail including matched events and timeline
- `PATCH /:id` — Update alert status (acknowledge, resolve, escalate), add notes
- `GET /stats` — Alert summary statistics (counts by severity, rule, source)

`/api/v1/detections`
- `GET /` — List deployed detection rules with metadata (last triggered, match count)
- `GET /:id` — Rule detail (Sigma YAML, compiled Rego, performance stats)
- `PATCH /:id` — Enable/disable a rule
- `POST /test` — Dry-run a rule against historical data

`/api/v1/enrichment`
- `GET /feeds` — List configured threat intel feeds / IOC lists
- `POST /feeds` — Add a new feed (CSV upload, STIX/TAXII URL)
- `GET /iocs` — Search IOC database
- `POST /iocs/check` — Check a set of indicators against all feeds

`/api/v1/dashboard`
- `GET /overview` — Aggregated dashboard data (ingestion health, alert counts, detection stats)

**Authentication:** The analyst REST API and `picket-admin` are gated by Cloudflare Access (SSO/IdP-backed). Workers validate the `Cf-Access-Jwt-Assertion` JWT against Access's JWKS before invoking better-auth's admin endpoints. The Terraform platform module configures the Access application and policies.

This is distinct from the **ingest auth path** (`picket-ingest`), which uses tenant-scoped API keys (`x-api-key` header) verified by better-auth's api-key plugin. Two surfaces, two boundaries, one shared `picket-auth` D1.

---

#### Phase 1 Feature 2: Additional Log Sources (6–8 New Sources)

Expand source coverage with Terraform modules and normalization mappings for:

- **AWS VPC Flow Logs** — S3 → Lambda forwarder → Pipeline. OCSF `Network Activity`.
- **AWS GuardDuty** — EventBridge → Lambda forwarder → Pipeline. OCSF `Detection Finding`.
- **Okta System Log** — Okta API polling Worker or Event Hooks → `picket-ingest`. OCSF `Authentication` / `API Activity` / `Account Change`. Deferred until a test tenant is available for live ingestion validation.
- **Azure Activity Log** — Event Hub → Azure Function forwarder → Pipeline. OCSF `API Activity`.
- **Azure AD Sign-in Logs** — Event Hub → Azure Function forwarder → Pipeline. OCSF `Authentication`.
- **GCP Cloud Audit Logs** — Pub/Sub → Cloud Function forwarder → Pipeline. OCSF `API Activity`.
- **Microsoft 365 Management Activity** — Office 365 Management API (polling Worker) → Pipeline. OCSF `Email Activity` / `Authentication`.
- **GitHub Audit Log** — Webhook → Worker → Pipeline. OCSF `API Activity`.
- **CrowdStrike Falcon** — Falcon Data Replicator (S3) → Lambda forwarder → Pipeline. OCSF `Detection Finding` / `Process Activity`.

Each source ships with 2–3 default detection rules specific to that source.

---

#### Phase 1 Feature 3: Scheduled Detections (SQL-based)

A cron-triggered Worker that runs SQL-based detection queries on a configurable schedule.

- Sigma rules with aggregation conditions compile to parameterized SQL queries
- The scheduler Worker runs each query via R2 SQL, evaluates results against thresholds, and creates alerts
- **Single-source example:** "More than 100 denied API calls from a single principal in 1 hour" → `SELECT actor_user_uid, count(*) as cnt FROM aws_cloudtrail WHERE status = 'failure' AND time > now() - interval '1 hour' GROUP BY actor_user_uid HAVING count(*) > 100`
- **Cross-source correlation example:** "User authenticates in Okta and performs a sensitive CloudTrail action within 5 minutes" → `SELECT o.actor_user_uid, o.time as okta_time, ct.time as aws_time, ct.api_operation FROM okta_auth o JOIN aws_cloudtrail ct ON o.actor_user_uid = ct.actor_user_uid WHERE ct.time BETWEEN o.time AND o.time + interval '5' minute AND ct.api_operation IN ('AssumeRole', 'CreateAccessKey')`
- **Enrichment JOIN example:** "Match any source IP in the last hour against threat intel IOCs" → `SELECT e.*, ti.feed_name, ti.threat_type FROM aws_cloudtrail e JOIN threat_intel ti ON e.src_endpoint_ip = ti.indicator WHERE e.time > now() - interval '1' hour AND ti.indicator_type = 'ipv4'`
- Schedule is configurable per rule (every 5 minutes, every hour, daily)
- Results that exceed thresholds create alerts through the same alert routing pipeline
- Best practice: always include time-range WHERE filters and prefer JOINing fact tables through dimension tables (e.g., users, assets) rather than cross-joining two large fact tables directly

---

#### Phase 1 Feature 4: Natural Language Query Interface

An API endpoint that accepts plain English questions, generates R2 SQL constrained by the lake schema, and returns results.

- `POST /api/v1/query/natural` — `{ "question": "Show me failed logins from outside the US in the last 24 hours" }`
- Worker sends the question + table schemas + R2 SQL capabilities (JOINs, subqueries, CTEs, 173 scalar functions, 33 aggregate functions) and constraints (partitioned Iceberg tables only, Parquet format, read-only) to an LLM
- Generated SQL is validated against R2 SQL's supported syntax before execution
- Returns both the generated SQL (for transparency/learning) and the query results
- LLM context includes OCSF field descriptions so it maps natural language concepts to the correct fields
- Cross-source questions (e.g., "which users authenticated in Okta and then made IAM changes in AWS?") generate JOIN queries across tables automatically

---

### Phase 2 — Frontend

**Goal:** Ship a web-based UI for alert triage, threat hunting, detection management, and platform administration. Hosted on Cloudflare Pages, authenticated via Cloudflare Access.

**Target timeline:** 8–12 weeks after Phase 1.

---

#### Phase 2 Feature 1: Dashboard

The landing page. Shows at-a-glance operational health and security posture.

**Components:**
- **Ingestion health grid** — One card per configured log source. Shows source name, last event timestamp, events/minute rate, and a status indicator (healthy / degraded / stale). Stale = no events in >2× the expected interval for that source. Data from `GET /api/v1/sources`.
- **Alert summary** — Count of open alerts by severity (critical, high, medium, low, informational) as a horizontal bar or badge row. Click a severity to jump to the filtered alert list. Data from `GET /api/v1/alerts/stats`.
- **Recent alerts feed** — Last 10 alerts in a compact list: timestamp, rule name, severity badge, brief title. Click to open alert detail.
- **Detection activity sparkline** — A 24-hour histogram showing detection matches over time. Spikes are immediately visible.
- **Ingestion volume chart** — Stacked area chart showing events ingested per source over the last 24 hours or 7 days (toggle).

**Auto-refresh:** Dashboard data refreshes every 60 seconds. If WebSocket support is available (via Durable Object), push new alerts in real-time.

---

#### Phase 2 Feature 2: Alert Triage

The primary analyst workflow surface.

**Alert list view:**
- Filterable by: severity, status (open / acknowledged / resolved), rule name, log source, time range
- Sortable by: time, severity, match count
- Bulk actions: acknowledge selected, resolve selected
- Pagination with infinite scroll or page controls

**Alert detail view:**
- **Header** — Alert title, severity badge, status, rule name, first/last match timestamps, match count
- **Matched event** — The raw OCSF event that triggered the detection, rendered as formatted JSON with syntax highlighting. Key fields (source IP, user, action, outcome) pulled out into a summary strip above the raw JSON.
- **Context timeline** — Related events from the same entity (source IP, user, or asset) in a configurable time window around the alert, pulled from across all log source tables via JOIN queries through the API. For example, an Okta brute force alert automatically pulls CloudTrail, Azure AD, and O365 events for the same user in the surrounding time window. Displayed as a chronological, cross-source timeline with expandable event details and source badges.
- **Rule info** — The Sigma YAML and/or compiled Rego for the detection rule that fired. Read-only view.
- **Analyst actions** — Acknowledge, resolve, escalate (changes status and optionally notifies a different destination), add notes (free text, stored in D1). Full action history displayed as a timeline.
- **IOC check** — One-click check of the alert's indicators (IPs, domains, hashes) against configured threat intel feeds. Results displayed inline.

---

#### Phase 2 Feature 3: Query Explorer

Ad-hoc threat hunting and investigation surface.

**SQL editor:**
- CodeMirror or Monaco editor with syntax highlighting for R2 SQL
- Schema-aware autocomplete: table names from Data Catalog, column names per table, R2 SQL function names
- Inline syntax validation — highlight unsupported features (JOINs, subqueries, window functions) before execution
- Query execution via `POST /api/v1/query/execute`, results displayed in a table below the editor
- Result table supports sorting, column resizing, and cell-level copy
- Export results as CSV or JSON

**Natural language mode:**
- Toggle between SQL editor and a natural language input box
- Submits to `POST /api/v1/query/natural`
- Shows the generated SQL alongside results so the analyst can learn and refine
- "Edit as SQL" button copies the generated query into the SQL editor for modification

**Query management:**
- Query history (auto-saved, searchable)
- Save queries with a name and optional description
- Preset library: ship with 10–15 common hunting queries (failed logins, top source IPs, IAM changes, data exfiltration indicators, etc.)

**Visualization:**
- Basic chart support for query results: time-series line/bar chart (when results include a timestamp column and numeric column), horizontal bar chart for top-N aggregations, count display for single-value results
- Chart type is auto-suggested based on result shape but manually overridable

---

#### Phase 2 Feature 4: Detection Management

Operational visibility into the detection engine.

**Detection list view:**
- All deployed rules with: name, severity, status (enabled/disabled), last triggered timestamp, total match count (last 7/30 days), false positive rate (if analyst feedback is tracked)
- Filter by: status, severity, log source, tag
- Enable/disable toggle per rule

**Detection detail view:**
- Sigma YAML source (read-only, links to git repo if configured)
- Compiled Rego (read-only)
- Performance chart: matches over time (daily/weekly)
- Recent matches: last 10 alerts from this rule with links to alert detail
- **Dry-run / backtest**: select a time range, run the rule against historical data, see what would have matched. Uses `POST /api/v1/detections/test`. Results displayed as a list of hypothetical matches with the events that triggered them.

---

#### Phase 2 Feature 5: Log Source Management

Operational visibility into the ingestion pipeline.

**Source list view:**
- All configured sources with: name, type (AWS/Azure/GCP/SaaS), status (healthy/degraded/stale), last event timestamp, ingestion rate, event count (last 24h)
- Click into source detail

**Source detail view:**
- **Health chart** — Ingestion volume over time (line chart, 24h/7d/30d)
- **Schema browser** — Expandable tree of OCSF fields in the source's Iceberg table, with field type and description. Clicking a field copies a query snippet.
- **Sample events** — Last 10 events from the source, rendered as formatted JSON
- **Error log** — Recent ingestion errors (malformed events, normalization failures, Pipeline errors)

---

#### Phase 2 Feature 6: Enrichment & IOC Management

Manage threat intelligence feeds and enrichment data. With R2 SQL's JOIN support, enrichment operates in two modes: **query-time enrichment** (JOIN event tables against IOC/asset Iceberg tables during investigation — always uses freshest data) and **ingest-time enrichment** (stamp high-priority IOC matches onto events as they flow through `picket-ingest`, enabling real-time detection rules to reference enrichment fields without a query).

- **Feed list** — Configured feeds with: name, type (CSV upload, STIX/TAXII, manual), indicator count, last updated, storage location (Iceberg table for query-time, KV for ingest-time, or both)
- **Add feed** — Upload a CSV of IOCs or configure a STIX/TAXII polling URL. Feed data is written to a `threat_intel` Iceberg table (for query-time JOINs) and optionally synced to KV (for ingest-time lookups)
- **IOC browser** — Search across all feeds by indicator type (IP, domain, hash, email) and value
- **Asset inventory** — Upload or sync asset/user directory data (hostname → owner, department, criticality). Stored as an Iceberg table (`assets` or `users`) for JOIN enrichment during investigation. Example: `SELECT e.*, a.owner, a.criticality FROM aws_cloudtrail e JOIN assets a ON e.dst_endpoint_hostname = a.hostname WHERE a.criticality = 'high'`
- **Enrichment at ingestion** — Configuration UI for which high-priority IOC data gets stamped onto events at ingest time via KV lookup (e.g., "tag events where source.ip matches a known C2 IP")

---

### Phase 3 — Scale & Ecosystem (Future)

Features beyond the initial three phases. Listed for roadmap visibility, not fully specified.

- **Multi-tenancy** — Support for MSSPs managing multiple customer environments from a single Picket deployment
- **SOAR-lite** — Automated response actions triggered by detections (e.g., block IP in Cloudflare WAF, disable user in Okta, isolate host in CrowdStrike). Implemented as response Workers with explicit approval workflows.
- **Case management** — Group related alerts into investigation cases with notes, timelines, and evidence collection. D1-backed with Iceberg audit trail.
- **Compliance reporting** — Pre-built SQL queries and report templates for common frameworks (SOC 2, PCI DSS, HIPAA). Exportable as PDF.
- **Community detection rules** — Public repository of Sigma rules optimized for Picket, with community contributions and quality scoring
- **Terraform provider** — A native `picket` Terraform provider (in addition to the modules) for teams that want programmatic control over detections, alert routing, and enrichment
- **Mobile app** — Lightweight alert triage on mobile. Push notifications for critical alerts.
- **External Iceberg engine support** — Documentation and configuration examples for querying the Picket lake from Snowflake, Spark, Trino, DuckDB for teams that need capabilities beyond R2 SQL (e.g., window functions, UNION/INTERSECT, UNNEST) or want to integrate Picket data into existing analytics platforms

---

## Technical Decisions & Rationale

### Why OCSF over ECS?

OCSF (Open Cybersecurity Schema Framework) is the industry-converging standard as of 2025–2026. AWS Security Lake, Splunk, IBM, and CrowdStrike have adopted it. ECS (Elastic Common Schema) is Elastic-centric and carries unnecessary coupling to the Elastic ecosystem. OCSF also has richer event class taxonomy for security use cases (50+ event classes vs. ECS's flatter field hierarchy). Starting with OCSF avoids a future migration.

### Why Interpret Sigma Directly In TypeScript?

The MVP targets learners and small personal deployments, so clarity and debuggability matter more than compilation throughput. Sigma's stateless detection subset maps cleanly to a small TypeScript interpreter over normalized OCSF events: logsource pre-filtering, field resolution, value matching, and boolean condition evaluation. Keeping the engine in TypeScript avoids a separate policy toolchain while preserving auditable YAML rule files.

### Why Durable Objects for stateful correlation?

Real-time stateful detection rules (thresholds, sliding windows, temporal correlation) need per-key state with sub-second evaluation latency. Matano used DynamoDB for this, which adds latency, cost, and operational complexity. Durable Objects provide single-threaded, strongly consistent, co-located state per correlation key. A Durable Object per source-IP or per-user-ID holding a 15-minute sliding window is architecturally elegant and performs well for SIEM-scale cardinalities (typically thousands to low millions of active keys).

Note: with R2 SQL's JOIN support, *analytical* cross-source correlation (e.g., "which users appeared in both Okta and CloudTrail within a time window?") is handled by scheduled SQL detection queries with JOINs. Durable Objects are reserved for *real-time* stateful correlation where sub-second alerting latency matters (e.g., brute force detection, impossible travel). The two tiers are complementary: Durable Objects for streaming, SQL JOINs for batch.

### Why D1 for alert metadata?

Alert records in Iceberg are append-only (immutable audit trail), but analyst workflows need mutable state (acknowledge, resolve, add notes). D1 is a natural fit: lightweight relational data, low latency from Workers, SQL interface, and no infrastructure to manage. The alert ID is the join key between the immutable Iceberg record and the mutable D1 record.

### Why Cloudflare Access for the operator surface, better-auth for ingest?

Picket has two distinct auth boundaries, and conflating them is the wrong choice in both directions.

**Cloudflare Access** is used for human operators — the analyst REST API and `picket-admin`. SSO/IdP integration (Okta, Azure AD, Google Workspace, GitHub) comes for free, JWT validation in Workers is trivial, and the Terraform platform module configures the Access application and policies. Zero custom auth code for the human surface.

**better-auth** (with the `@better-auth/api-key` plugin) is used for machine ingestion — `picket-ingest` only. Cloudflare Access is a poor fit for log forwarders: it expects browser-mediated SSO flows, not headless services posting NDJSON from inside a customer's VPC. API keys with per-key rate limits, per-key metadata (source, tenant), and revocation are the right primitive for that boundary. better-auth was chosen over hand-rolling because it ships hashed-at-rest keys (SHA-256), built-in rate limiting, a CRUD admin surface we can mount in `picket-admin`, and a forward path to multi-tenant organizations via its `organization` plugin once the operator console lands.

Both surfaces share one D1 (`picket-auth`) through better-auth's Kysely adapter (kysely-d1). For MVP, all API keys are owned by a single seeded `system@picket.local` user with `metadata.tenant_id` for scoping; the organization plugin is deferred until Phase 2 when there is a UI to manage it.

### Why dual enrichment (query-time JOINs + ingest-time KV)?

R2 SQL's JOIN support enables query-time enrichment: analysts can JOIN any event table against a `threat_intel` or `assets` Iceberg table during investigation and always get the freshest enrichment data without reprocessing historical events. This is the primary enrichment path for investigation and hunting workflows.

However, real-time detection rules evaluated in the detection Worker need enrichment data available at event evaluation time — they can't issue an R2 SQL query per event. For this path, high-priority IOC data is synced to KV and looked up during ingest-time normalization, stamping a `threat_match` field onto the event. This enables real-time detection rules like "alert on any authentication from a known C2 IP" without query latency.

The two paths serve different latency requirements: KV for real-time (<100ms), Iceberg JOINs for analytical (seconds). Both draw from the same feed sources; the platform keeps them in sync.

### Why per-source Iceberg tables (not unified OCSF category tables)?

With R2 SQL JOINs available, per-source tables (`aws_cloudtrail`, `okta_auth`, `azure_ad_signin`) are preferred over unified category tables (`authentication`) for several reasons: each source retains its full native schema including source-specific fields that would be lost in unification, schema evolution per source is independent (adding a field to CloudTrail doesn't affect Okta), ingestion pipelines are simpler (no merge logic), and cross-source analysis is handled via JOINs when needed. Unified category views can be added later as a convenience layer if user feedback demands it.

---

## Success Metrics

**MVP:**
- End-to-end log ingestion latency: <5 minutes for CloudTrail (S3 polling), <60 seconds for webhook/streaming sources (Kubernetes, Cloudflare)
- Detection evaluation latency: <2 seconds from event ingestion to alert creation
- Query response time: <10 seconds for queries scanning <1GB of Parquet data
- Deployment time: <30 minutes from `git clone` to first query result for a user with existing AWS, Kubernetes, or Cloudflare log source access
- Default detection rules: 5 shipped, 0 false positives on synthetic test data

**Phase 1:**
- API response time: <500ms for all non-query endpoints
- Log source coverage: 10+ sources with Terraform modules
- Scheduled detection execution: within 30 seconds of configured schedule

**Phase 2:**
- Dashboard load time: <3 seconds
- Alert triage workflow: analyst can open, review context, and acknowledge an alert in <60 seconds
- Query explorer: autocomplete suggestions appear in <200ms
- Frontend Lighthouse score: >90 (performance, accessibility)

---

## Open Questions

1. **Domain & namespace availability** — Verify availability of `picket.dev` or `picket-siem.dev`, npm scope `@picket`, GitHub org `picket-siem`, and Terraform registry namespace.
2. **R2 SQL billing** — Currently free in open beta. Pricing model will affect the cost story significantly. Need to monitor Cloudflare's announcements and model costs once pricing is published.
3. **R2 SQL JOIN performance at scale** — JOINs, subqueries, and multi-table CTEs are now supported, but the docs advise using WHERE filters to manage join selectivity and avoiding direct cross-joins of two large fact tables. Need to benchmark cross-source correlation queries (e.g., CloudTrail JOIN Okta on user ID with time window) at realistic data volumes (100GB+ per table) to understand practical query latency and whether dimension-table patterns (users, assets) are needed as intermediaries.
4. **Table design: per-source vs. per-OCSF-category** — With JOINs available, per-source tables (one `aws_cloudtrail`, one `okta_auth`, etc.) are the simpler default. However, some use cases benefit from unified OCSF category tables (a single `authentication` table across all sources) for simpler single-table queries. Need to decide: per-source only, unified only, or both (unified as materialized views). Per-source is recommended for MVP; evaluate unified tables based on user feedback.
5. **Sigma rule coverage** — The Sigma-to-Rego compiler needs to handle a large subset of Sigma's specification. Need to define which Sigma features are in scope for MVP vs. later phases (e.g., `near` temporal proximity rules, `correlation` rules, `aggregation` conditions).
6. **License** — Apache 2.0 (like Matano) for maximum adoption, or something with more protection against cloud vendor co-option (e.g., BSL, SSPL, ELv2)?
7. **R2 SQL remaining limitations** — Window functions (`OVER`), `SELECT DISTINCT`, `UNION`/`INTERSECT`/`EXCEPT`, `OFFSET`, `ARRAY_AGG`, and `STRING_AGG` are still unsupported. Window functions are the most impactful gap for SIEM use cases (sessionization, running totals, lead/lag analysis). Monitor R2 SQL beta updates for additions.
