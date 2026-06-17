import { OCSF_SOURCES } from "./ocsf-schema.js";
import type { SourceHealthRow, SourceHealthStatus } from "./source-health.js";

// Per-source helpers for the Milestone 1 `/api/v1/sources/:id/*` endpoints:
// an OCSF field list derived from the normalized event shape (the flattened
// columns R2 SQL queries actually hit), the source → Iceberg table mapping, and
// the canned "recent events" sample query.

export type OcsfFieldType = "string" | "timestamp" | "json";

export interface OcsfFieldDescriptor {
  name: string;
  type: OcsfFieldType;
  group: string;
}

// Mirrors flattenOcsfEvent() exactly — these are the columns present in every
// source's Iceberg table, so the same schema applies across sources for the MVP.
// Data Catalog introspection (real per-table columns) can replace this later.
export const OCSF_EVENT_FIELDS: readonly OcsfFieldDescriptor[] = [
  { name: "time", type: "timestamp", group: "base" },
  { name: "source", type: "string", group: "base" },
  { name: "category", type: "string", group: "base" },
  { name: "class_name", type: "string", group: "base" },
  { name: "activity_name", type: "string", group: "base" },
  { name: "status", type: "string", group: "base" },
  { name: "message", type: "string", group: "base" },
  { name: "actor_user_uid", type: "string", group: "actor" },
  { name: "actor_user_name", type: "string", group: "actor" },
  { name: "actor_user_email", type: "string", group: "actor" },
  { name: "actor_user_type", type: "string", group: "actor" },
  { name: "actor_session_uid", type: "string", group: "actor" },
  { name: "user_uid", type: "string", group: "user" },
  { name: "user_name", type: "string", group: "user" },
  { name: "user_email", type: "string", group: "user" },
  { name: "user_type", type: "string", group: "user" },
  { name: "src_endpoint_ip", type: "string", group: "src_endpoint" },
  { name: "src_endpoint_name", type: "string", group: "src_endpoint" },
  { name: "src_endpoint_uid", type: "string", group: "src_endpoint" },
  { name: "src_endpoint_country", type: "string", group: "src_endpoint" },
  { name: "src_endpoint_region", type: "string", group: "src_endpoint" },
  { name: "src_endpoint_city", type: "string", group: "src_endpoint" },
  { name: "dst_endpoint_ip", type: "string", group: "dst_endpoint" },
  { name: "dst_endpoint_name", type: "string", group: "dst_endpoint" },
  { name: "dst_endpoint_uid", type: "string", group: "dst_endpoint" },
  { name: "dst_endpoint_country", type: "string", group: "dst_endpoint" },
  { name: "dst_endpoint_region", type: "string", group: "dst_endpoint" },
  { name: "dst_endpoint_city", type: "string", group: "dst_endpoint" },
  { name: "api_operation", type: "string", group: "api" },
  { name: "api_service_name", type: "string", group: "api" },
  { name: "cloud_provider", type: "string", group: "cloud" },
  { name: "cloud_region", type: "string", group: "cloud" },
  { name: "cloud_account_uid", type: "string", group: "cloud" },
  { name: "cloud_account_name", type: "string", group: "cloud" },
  { name: "http_request_user_agent", type: "string", group: "http_request" },
  { name: "http_request_url", type: "string", group: "http_request" },
  { name: "http_request_http_method", type: "string", group: "http_request" },
  { name: "metadata_product_name", type: "string", group: "metadata" },
  { name: "metadata_original_uid", type: "string", group: "metadata" },
  { name: "metadata_raw_event", type: "json", group: "metadata" }
];

// Recent-events sample size for /api/v1/sources/:id/sample.
export const SAMPLE_LIMIT = 10;

export function isKnownSource(source: string): source is (typeof OCSF_SOURCES)[number] {
  return (OCSF_SOURCES as readonly string[]).includes(source);
}

export interface OcsfSourceSchema {
  source: string;
  field_count: number;
  fields: readonly OcsfFieldDescriptor[];
}

export function ocsfSchemaForSource(source: string): OcsfSourceSchema {
  return {
    source,
    field_count: OCSF_EVENT_FIELDS.length,
    fields: OCSF_EVENT_FIELDS
  };
}

// The Iceberg table R2 SQL queries hit for a source. The terraform module mints
// a random suffix per table (Pipelines open-beta cache workaround); pass
// PICKET_TABLE_SUFFIX so the table name matches the deployed catalog.
export function sampleTableName(source: string, suffix?: string | null): string {
  return suffix ? `${source}_${suffix}` : source;
}

export function sampleQuery(source: string, suffix?: string | null, limit: number = SAMPLE_LIMIT): string {
  const table = sampleTableName(source, suffix);
  return `SELECT * FROM ${table} ORDER BY time DESC LIMIT ${limit}`;
}

// Base Iceberg table names that the terraform module suffixes with a random_pet
// (the Pipelines open-beta cache workaround). Scheduled SQL rules are authored
// against the bare names; the worker rewrites them to the deployed names.
export const SUFFIXABLE_TABLES: readonly string[] = [
  "aws_cloudtrail",
  "aws_vpc_flow",
  "aws_guardduty",
  "gcp_cloud_audit",
  "azure_activity",
  "azure_ad_signin",
  "github_audit",
  "m365_management",
  "kubernetes_audit",
  "cloudflare_audit",
  "okta_auth",
  "threat_intel",
  "assets",
  "users"
];

// Rewrite `FROM <base>` / `JOIN <base>` to the suffixed table name for every
// known base table. No-op when suffix is falsy. Word-boundary anchored so it
// won't touch an already-suffixed name or a column.
export function applyTableSuffix(sql: string, suffix?: string | null): string {
  if (!suffix) return sql;
  let out = sql;
  for (const table of SUFFIXABLE_TABLES) {
    out = out.replace(
      new RegExp(`\\b(from|join)\\s+${table}\\b`, "gi"),
      (_match, keyword: string) => `${keyword} ${table}_${suffix}`
    );
  }
  return out;
}

// A single source's health row plus its server-computed freshness classification,
// as returned by GET /api/v1/sources/:id/status.
export interface SourceStatus extends SourceHealthRow {
  health: SourceHealthStatus;
}

export function formatSourceStatus(status: SourceStatus): string {
  return [
    `Source ${status.source}`,
    `  health:        ${status.health}`,
    `  tenant:        ${status.tenant_id}`,
    `  last_event_at: ${status.last_event_at ?? "-"}`,
    `  total_events:  ${status.total_events}`,
    `  total_batches: ${status.total_batches}`,
    `  total_errors:  ${status.total_errors}`,
    `  last_error_at: ${status.last_error_at ?? "-"}`,
    `  last_error:    ${status.last_error_message ?? "-"}`,
    `  updated_at:    ${status.updated_at}`
  ].join("\n");
}

export function formatOcsfSchema(schema: OcsfSourceSchema): string {
  const lines: string[] = [];
  lines.push(`OCSF schema for ${schema.source} (${schema.field_count} fields)`);
  let lastGroup = "";
  const nameWidth = schema.fields.reduce((max, field) => Math.max(max, field.name.length), 0);
  for (const field of schema.fields) {
    if (field.group !== lastGroup) {
      lines.push("");
      lines.push(`[${field.group}]`);
      lastGroup = field.group;
    }
    lines.push(`  ${field.name.padEnd(nameWidth)}  ${field.type}`);
  }
  return lines.join("\n");
}
