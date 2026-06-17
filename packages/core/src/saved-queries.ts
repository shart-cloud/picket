import type { AlertStateDb } from "./alerts.js";

// Query management storage (Milestone 1): named saved queries + an append-only
// submission history. Shared by picket-admin routes and exercised via FakeAlertDb
// in core/admin/cli tests.

export interface SavedQueryRow {
  id: string;
  owner: string;
  name: string;
  description: string | null;
  sql: string;
  preset: string | null;
  created_at: string;
  updated_at: string;
}

export interface QueryHistoryRow {
  id: string;
  owner: string | null;
  sql: string;
  preset: string | null;
  job_id: string | null;
  created_at: string;
}

export interface SaveQueryInput {
  id: string;
  owner: string;
  name: string;
  description?: string | null;
  sql: string;
  preset?: string | null;
}

export interface ListSavedQueriesFilters {
  owner?: string;
  limit?: number;
}

export interface RecordQueryHistoryInput {
  id: string;
  owner: string | null;
  sql: string;
  preset?: string | null;
  job_id?: string | null;
}

export interface ListQueryHistoryFilters {
  owner?: string;
  limit?: number;
}

export class SavedQueryNameRequiredError extends Error {
  constructor() {
    super("Saved query name must be a non-empty string.");
    this.name = "SavedQueryNameRequiredError";
  }
}

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

const SAVED_QUERY_COLUMNS = "id, owner, name, description, sql, preset, created_at, updated_at";
const QUERY_HISTORY_COLUMNS = "id, owner, sql, preset, job_id, created_at";

function clampLimit(limit: number | undefined): number {
  if (limit === undefined || !Number.isInteger(limit) || limit <= 0) return DEFAULT_LIMIT;
  return Math.min(limit, MAX_LIMIT);
}

// Upsert by (owner, name): saving with an existing name overwrites the stored
// SQL/description and bumps updated_at, preserving the original id + created_at.
export async function saveQuery(db: AlertStateDb, input: SaveQueryInput): Promise<SavedQueryRow> {
  const name = input.name.trim();
  if (name.length === 0) throw new SavedQueryNameRequiredError();

  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO saved_queries (id, owner, name, description, sql, preset, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(owner, name) DO UPDATE SET
         description = excluded.description,
         sql = excluded.sql,
         preset = excluded.preset,
         updated_at = excluded.updated_at`
    )
    .bind(input.id, input.owner, name, input.description ?? null, input.sql, input.preset ?? null, now, now)
    .run();

  const row = await db
    .prepare(`SELECT ${SAVED_QUERY_COLUMNS} FROM saved_queries WHERE owner = ? AND name = ?`)
    .bind(input.owner, name)
    .first<SavedQueryRow>();
  if (!row) throw new Error("saveQuery: row not found after upsert");
  return row;
}

export async function listSavedQueries(
  db: AlertStateDb,
  filters: ListSavedQueriesFilters = {}
): Promise<SavedQueryRow[]> {
  const conditions: string[] = [];
  const params: unknown[] = [];
  if (filters.owner) {
    conditions.push("owner = ?");
    params.push(filters.owner);
  }
  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const sql = `SELECT ${SAVED_QUERY_COLUMNS} FROM saved_queries ${where} ORDER BY updated_at DESC LIMIT ?`;
  params.push(clampLimit(filters.limit));
  const result = await db.prepare(sql).bind(...params).all<SavedQueryRow>();
  return result.results;
}

// Best-effort: callers should wrap in try/catch so a history-write failure never
// blocks the query path.
export async function recordQueryHistory(db: AlertStateDb, input: RecordQueryHistoryInput): Promise<void> {
  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO query_history (id, owner, sql, preset, job_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .bind(input.id, input.owner, input.sql, input.preset ?? null, input.job_id ?? null, now)
    .run();
}

export async function listQueryHistory(
  db: AlertStateDb,
  filters: ListQueryHistoryFilters = {}
): Promise<QueryHistoryRow[]> {
  const conditions: string[] = [];
  const params: unknown[] = [];
  if (filters.owner) {
    conditions.push("owner = ?");
    params.push(filters.owner);
  }
  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const sql = `SELECT ${QUERY_HISTORY_COLUMNS} FROM query_history ${where} ORDER BY created_at DESC LIMIT ?`;
  params.push(clampLimit(filters.limit));
  const result = await db.prepare(sql).bind(...params).all<QueryHistoryRow>();
  return result.results;
}

export function formatSavedQueriesTable(rows: readonly SavedQueryRow[]): string {
  if (rows.length === 0) return "No saved queries.";
  const headers = ["name", "owner", "preset", "updated_at", "sql"] as const;
  const body: string[][] = rows.map((row) => [
    row.name,
    row.owner,
    row.preset ?? "-",
    row.updated_at,
    truncate(row.sql, 60)
  ]);
  return renderTable(headers, body);
}

export function formatQueryHistoryTable(rows: readonly QueryHistoryRow[]): string {
  if (rows.length === 0) return "No query history.";
  const headers = ["created_at", "owner", "preset", "job_id", "sql"] as const;
  const body: string[][] = rows.map((row) => [
    row.created_at,
    row.owner ?? "-",
    row.preset ?? "-",
    row.job_id ?? "-",
    truncate(row.sql, 60)
  ]);
  return renderTable(headers, body);
}

function truncate(value: string, max: number): string {
  const oneLine = value.replace(/\s+/g, " ").trim();
  return oneLine.length > max ? `${oneLine.slice(0, max - 1)}…` : oneLine;
}

function renderTable(headers: readonly string[], rows: readonly string[][]): string {
  const widths = headers.map((header, columnIndex) => {
    let width = header.length;
    for (const row of rows) {
      const cell = row[columnIndex] ?? "";
      if (cell.length > width) width = cell.length;
    }
    return width;
  });
  const pad = (cells: readonly string[]): string =>
    cells.map((cell, columnIndex) => cell.padEnd(widths[columnIndex] ?? 0)).join("  ");
  const separator = widths.map((width) => "-".repeat(width));
  return [pad(headers), pad(separator), ...rows.map(pad)].join("\n");
}
