import type { AlertStateDb } from "./alerts.js";

export interface SourceHealthRow {
  source: string;
  tenant_id: string;
  last_event_at: string | null;
  last_event_count: number;
  total_events: number;
  total_batches: number;
  total_errors: number;
  last_error_at: string | null;
  last_error_message: string | null;
  updated_at: string;
}

export type SourceHealthHistoryKind = "batch" | "error";

export interface SourceHealthHistoryRow {
  id: number;
  source: string;
  tenant_id: string;
  kind: SourceHealthHistoryKind;
  event_count: number;
  last_event_at: string | null;
  error_message: string | null;
  recorded_at: string;
}

export type SourceHealthStatus = "healthy" | "stale" | "unknown";

export interface RecordIngestBatchInput {
  source: string;
  tenant_id?: string;
  event_count: number;
  last_event_at: string | null;
}

export interface RecordIngestErrorInput {
  source: string;
  tenant_id?: string;
  message: string;
}

export interface ListSourceHealthFilters {
  tenant_id?: string;
}

export interface ListSourceHealthHistoryFilters {
  tenant_id?: string;
  kind?: SourceHealthHistoryKind;
  limit?: number;
}

const MAX_ERROR_LENGTH = 500;
const DEFAULT_HISTORY_LIMIT = 50;
const MAX_HISTORY_LIMIT = 200;

const SOURCE_HEALTH_COLUMNS =
  "source, tenant_id, last_event_at, last_event_count, total_events, total_batches, total_errors, last_error_at, last_error_message, updated_at";

const FRESHNESS_WINDOW_MS: Record<string, number> = {
  aws_cloudtrail: 10 * 60_000,
  kubernetes_audit: 5 * 60_000,
  cloudflare_audit: 10 * 60_000
};
const DEFAULT_FRESHNESS_WINDOW_MS = 15 * 60_000;

export function freshnessWindowMs(source: string): number {
  return FRESHNESS_WINDOW_MS[source] ?? DEFAULT_FRESHNESS_WINDOW_MS;
}

export async function recordIngestBatch(
  db: AlertStateDb,
  input: RecordIngestBatchInput
): Promise<void> {
  const tenant = input.tenant_id ?? "default";
  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO source_health (
         source, tenant_id, last_event_at, last_event_count,
         total_events, total_batches, total_errors, updated_at
       ) VALUES (?, ?, ?, ?, ?, 1, 0, ?)
       ON CONFLICT(source, tenant_id) DO UPDATE SET
         last_event_at = CASE
           WHEN excluded.last_event_at IS NULL THEN source_health.last_event_at
           WHEN source_health.last_event_at IS NULL THEN excluded.last_event_at
           WHEN excluded.last_event_at >= source_health.last_event_at THEN excluded.last_event_at
           ELSE source_health.last_event_at
         END,
         last_event_count = excluded.last_event_count,
         total_events = source_health.total_events + excluded.total_events,
         total_batches = source_health.total_batches + 1,
         updated_at = excluded.updated_at`
    )
    .bind(input.source, tenant, input.last_event_at, input.event_count, input.event_count, now)
    .run();
  await recordSourceHealthHistory(db, {
    source: input.source,
    tenant_id: tenant,
    kind: "batch",
    event_count: input.event_count,
    last_event_at: input.last_event_at,
    error_message: null,
    recorded_at: now
  });
}

export async function recordIngestError(
  db: AlertStateDb,
  input: RecordIngestErrorInput
): Promise<void> {
  const tenant = input.tenant_id ?? "default";
  const now = new Date().toISOString();
  const truncated = input.message.slice(0, MAX_ERROR_LENGTH);
  await db
    .prepare(
      `INSERT INTO source_health (
         source, tenant_id, total_errors, last_error_at, last_error_message, updated_at
       ) VALUES (?, ?, 1, ?, ?, ?)
       ON CONFLICT(source, tenant_id) DO UPDATE SET
         total_errors = source_health.total_errors + 1,
         last_error_at = excluded.last_error_at,
         last_error_message = excluded.last_error_message,
         updated_at = excluded.updated_at`
    )
    .bind(input.source, tenant, now, truncated, now)
    .run();
  await recordSourceHealthHistory(db, {
    source: input.source,
    tenant_id: tenant,
    kind: "error",
    event_count: 0,
    last_event_at: null,
    error_message: truncated,
    recorded_at: now
  });
}

export async function listSourceHealthHistory(
  db: AlertStateDb,
  source: string,
  filters: ListSourceHealthHistoryFilters = {}
): Promise<SourceHealthHistoryRow[]> {
  const conditions = ["source = ?"];
  const params: unknown[] = [source];
  if (filters.tenant_id) {
    conditions.push("tenant_id = ?");
    params.push(filters.tenant_id);
  }
  if (filters.kind) {
    conditions.push("kind = ?");
    params.push(filters.kind);
  }
  const requestedLimit = filters.limit ?? DEFAULT_HISTORY_LIMIT;
  const limit = Number.isInteger(requestedLimit) && requestedLimit > 0
    ? Math.min(requestedLimit, MAX_HISTORY_LIMIT)
    : DEFAULT_HISTORY_LIMIT;
  params.push(limit);
  const result = await db
    .prepare(
      `SELECT id, source, tenant_id, kind, event_count, last_event_at, error_message, recorded_at
       FROM source_health_history
       WHERE ${conditions.join(" AND ")}
       ORDER BY recorded_at DESC, id DESC
       LIMIT ?`
    )
    .bind(...params)
    .all<SourceHealthHistoryRow>();
  return result.results;
}

export async function listSourceHealth(
  db: AlertStateDb,
  filters: ListSourceHealthFilters = {}
): Promise<SourceHealthRow[]> {
  const conditions: string[] = [];
  const params: unknown[] = [];
  if (filters.tenant_id) {
    conditions.push("tenant_id = ?");
    params.push(filters.tenant_id);
  }
  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const sql = `SELECT ${SOURCE_HEALTH_COLUMNS} FROM source_health ${where} ORDER BY source ASC`;
  const result = await db.prepare(sql).bind(...params).all<SourceHealthRow>();
  return result.results;
}

export async function getSourceHealth(
  db: AlertStateDb,
  source: string,
  tenant_id?: string
): Promise<SourceHealthRow | null> {
  if (tenant_id !== undefined) {
    const row = await db
      .prepare(
        `SELECT ${SOURCE_HEALTH_COLUMNS} FROM source_health WHERE source = ? AND tenant_id = ?`
      )
      .bind(source, tenant_id)
      .first<SourceHealthRow>();
    return row ?? null;
  }
  const row = await db
    .prepare(`SELECT ${SOURCE_HEALTH_COLUMNS} FROM source_health WHERE source = ?`)
    .bind(source)
    .first<SourceHealthRow>();
  return row ?? null;
}

export function classifySourceHealth(
  row: Pick<SourceHealthRow, "source" | "last_event_at">,
  now: Date
): SourceHealthStatus {
  if (!row.last_event_at) return "unknown";
  const lastMs = Date.parse(row.last_event_at);
  if (!Number.isFinite(lastMs)) return "unknown";
  const elapsed = now.getTime() - lastMs;
  return elapsed <= freshnessWindowMs(row.source) ? "healthy" : "stale";
}

async function recordSourceHealthHistory(
  db: AlertStateDb,
  row: Omit<SourceHealthHistoryRow, "id">
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO source_health_history (
         source, tenant_id, kind, event_count, last_event_at, error_message, recorded_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      row.source,
      row.tenant_id,
      row.kind,
      row.event_count,
      row.last_event_at,
      row.error_message,
      row.recorded_at
    )
    .run();
}

export interface FormatSourceHealthOptions {
  now: Date;
}

export function formatSourceHealthTable(
  rows: readonly SourceHealthRow[],
  options: FormatSourceHealthOptions
): string {
  if (rows.length === 0) return "No sources reporting.";

  const headers = [
    "source",
    "tenant",
    "status",
    "last_event_at",
    "total_events",
    "total_batches",
    "total_errors",
    "last_error_at"
  ] as const;

  const body: string[][] = rows.map((row) => [
    row.source,
    row.tenant_id,
    classifySourceHealth(row, options.now),
    row.last_event_at ?? "-",
    String(row.total_events),
    String(row.total_batches),
    String(row.total_errors),
    row.last_error_at ?? "-"
  ]);

  const widths = headers.map((header, columnIndex) => {
    let width = header.length;
    for (const cells of body) {
      const cell = cells[columnIndex] ?? "";
      if (cell.length > width) width = cell.length;
    }
    return width;
  });

  const pad = (cells: readonly string[]): string =>
    cells.map((cell, columnIndex) => cell.padEnd(widths[columnIndex] ?? 0)).join("  ");

  const separator = widths.map((width) => "-".repeat(width));
  return [pad(headers), pad(separator), ...body.map(pad)].join("\n");
}
