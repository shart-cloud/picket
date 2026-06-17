import { randomUUID } from "node:crypto";

export type AlertStatus = "open" | "acknowledged" | "resolved";
export type AlertSeverity = "critical" | "high" | "medium" | "low" | "informational";

export const ALERT_STATUSES: readonly AlertStatus[] = ["open", "acknowledged", "resolved"];
export const ALERT_SEVERITIES: readonly AlertSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational"
];

export interface AlertRow {
  id: string;
  rule_id: string;
  title: string;
  severity: AlertSeverity;
  source: string;
  status: AlertStatus;
  match_count: number;
  first_seen: string;
  last_seen: string;
  updated_at: string;
}

export interface AlertDetail extends AlertRow {
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  assignee: string | null;
  event_json: string;
}

export interface AlertTimelineEntry {
  id: string;
  action: string;
  actor: string | null;
  body: string | null;
  metadata_json: string | null;
  created_at: string;
}

export interface AlertNoteEntry {
  id: string;
  body: string;
  author: string | null;
  created_at: string;
}

export interface AlertWithHistory {
  alert: AlertDetail;
  timeline: AlertTimelineEntry[];
  notes: AlertNoteEntry[];
}

export interface ListAlertsFilters {
  status?: AlertStatus;
  severity?: AlertSeverity;
  rule_id?: string;
  source?: string;
  start_time?: string;
  end_time?: string;
  limit: number;
  offset?: number;
  sort?: AlertSortField;
  direction?: AlertSortDirection;
}

export type AlertSortField = "updated_at" | "last_seen" | "severity" | "match_count";
export type AlertSortDirection = "asc" | "desc";

export interface AlertCountEntry {
  key: string;
  count: number;
}

export interface AlertStats {
  total: number;
  by_severity: AlertCountEntry[];
  by_status: AlertCountEntry[];
  by_rule: AlertCountEntry[];
  by_source: AlertCountEntry[];
}

export interface AlertStateStatement {
  bind(...params: unknown[]): AlertStateStatement;
  first<T = unknown>(): Promise<T | null>;
  all<T = unknown>(): Promise<{ results: T[] }>;
  run(): Promise<unknown>;
}

export interface AlertStateDb {
  prepare(sql: string): AlertStateStatement;
}

export class AlertNotFoundError extends Error {
  constructor(public readonly alertId: string) {
    super(`Alert not found: ${alertId}`);
    this.name = "AlertNotFoundError";
  }
}

export class AlertAlreadyOpenError extends Error {
  constructor(public readonly alertId: string) {
    super(`Alert is already open: ${alertId}`);
    this.name = "AlertAlreadyOpenError";
  }
}

export class AlertNoteBodyRequiredError extends Error {
  constructor() {
    super("Alert note body must be a non-empty string.");
    this.name = "AlertNoteBodyRequiredError";
  }
}

const ALERT_COLUMNS =
  "id, rule_id, title, severity, source, status, match_count, first_seen, last_seen, updated_at";

const ALERT_DETAIL_COLUMNS = `${ALERT_COLUMNS}, acknowledged_at, acknowledged_by, resolved_at, resolved_by, assignee, event_json`;

export async function listAlerts(db: AlertStateDb, filters: ListAlertsFilters): Promise<AlertRow[]> {
  const { where, params } = buildAlertFilterQuery(filters);
  const orderBy = alertOrderBy(filters.sort ?? "updated_at", filters.direction ?? "desc");
  const sql = `SELECT ${ALERT_COLUMNS} FROM alerts ${where} ORDER BY ${orderBy}, id ASC LIMIT ? OFFSET ?`;
  params.push(filters.limit, filters.offset ?? 0);

  const result = await db.prepare(sql).bind(...params).all<AlertRow>();
  return result.results;
}

export async function countAlerts(db: AlertStateDb, filters: Omit<ListAlertsFilters, "limit" | "offset" | "sort" | "direction">): Promise<number> {
  const { where, params } = buildAlertFilterQuery(filters);
  const row = await db.prepare(`SELECT COUNT(*) AS count FROM alerts ${where}`).bind(...params).first<{ count: number }>();
  return row?.count ?? 0;
}

function buildAlertFilterQuery(filters: Omit<ListAlertsFilters, "limit" | "offset" | "sort" | "direction">): {
  where: string;
  params: unknown[];
} {
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (filters.status) {
    conditions.push("status = ?");
    params.push(filters.status);
  }
  if (filters.severity) {
    conditions.push("severity = ?");
    params.push(filters.severity);
  }
  if (filters.rule_id) {
    conditions.push("rule_id = ?");
    params.push(filters.rule_id);
  }
  if (filters.source) {
    conditions.push("source = ?");
    params.push(filters.source);
  }
  if (filters.start_time) {
    conditions.push("last_seen >= ?");
    params.push(filters.start_time);
  }
  if (filters.end_time) {
    conditions.push("first_seen <= ?");
    params.push(filters.end_time);
  }

  return {
    where: conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "",
    params
  };
}

function alertOrderBy(sort: AlertSortField, direction: AlertSortDirection): string {
  const sqlDirection = direction === "asc" ? "ASC" : "DESC";
  if (sort === "severity") {
    return `CASE severity
      WHEN 'critical' THEN 5
      WHEN 'high' THEN 4
      WHEN 'medium' THEN 3
      WHEN 'low' THEN 2
      ELSE 1
    END ${sqlDirection}, last_seen DESC`;
  }
  return `${sort} ${sqlDirection}`;
}

// Aggregate counts across the alerts table for the stats endpoint. Severity and
// status are ordered by their canonical scales (and include zero-count buckets so
// the shape is stable); rule and source are dynamic, ordered by count desc then
// key asc.
export async function alertStats(db: AlertStateDb): Promise<AlertStats> {
  const bySeverity = await groupCount(db, "severity");
  const byStatus = await groupCount(db, "status");
  const byRule = await groupCount(db, "rule_id");
  const bySource = await groupCount(db, "source");

  const total = bySeverity.reduce((sum, entry) => sum + entry.count, 0);

  return {
    total,
    by_severity: orderByScale(bySeverity, ALERT_SEVERITIES),
    by_status: orderByScale(byStatus, ALERT_STATUSES),
    by_rule: orderByCount(byRule),
    by_source: orderByCount(bySource)
  };
}

async function groupCount(db: AlertStateDb, column: string): Promise<AlertCountEntry[]> {
  // `column` is a fixed internal identifier (never user input), so interpolation
  // is safe here.
  const result = await db
    .prepare(`SELECT ${column} AS key, COUNT(*) AS count FROM alerts GROUP BY ${column}`)
    .all<{ key: string; count: number }>();
  return result.results.map((row) => ({ key: row.key, count: row.count }));
}

function orderByScale(entries: AlertCountEntry[], scale: readonly string[]): AlertCountEntry[] {
  const counts = new Map(entries.map((entry) => [entry.key, entry.count]));
  return scale.map((key) => ({ key, count: counts.get(key) ?? 0 }));
}

function orderByCount(entries: AlertCountEntry[]): AlertCountEntry[] {
  return [...entries].sort((left, right) => right.count - left.count || left.key.localeCompare(right.key));
}

export function formatAlertStats(stats: AlertStats): string {
  const lines: string[] = [];
  lines.push(`Total alerts: ${stats.total}`);
  appendStatsSection(lines, "By severity", stats.by_severity);
  appendStatsSection(lines, "By status", stats.by_status);
  appendStatsSection(lines, "By rule", stats.by_rule);
  appendStatsSection(lines, "By source", stats.by_source);
  return lines.join("\n");
}

function appendStatsSection(lines: string[], title: string, entries: readonly AlertCountEntry[]): void {
  lines.push("");
  lines.push(`${title}:`);
  if (entries.length === 0) {
    lines.push("  (none)");
    return;
  }
  const width = entries.reduce((max, entry) => Math.max(max, entry.key.length), 0);
  for (const entry of entries) {
    lines.push(`  ${entry.key.padEnd(width)}  ${entry.count}`);
  }
}

export async function acknowledgeAlert(
  db: AlertStateDb,
  alertId: string,
  acknowledgedBy: string
): Promise<AlertRow> {
  const existing = await db
    .prepare("SELECT id FROM alerts WHERE id = ?")
    .bind(alertId)
    .first<{ id: string }>();
  if (!existing) throw new AlertNotFoundError(alertId);

  const now = new Date().toISOString();
  await db
    .prepare(
      `UPDATE alerts
       SET status = 'acknowledged', acknowledged_at = ?, acknowledged_by = ?, updated_at = ?
       WHERE id = ?`
    )
    .bind(now, acknowledgedBy, now, alertId)
    .run();

  await db
    .prepare(
      `INSERT INTO alert_timeline (id, alert_id, action, actor, metadata_json)
       VALUES (?, ?, 'acknowledged', ?, ?)`
    )
    .bind(randomUUID(), alertId, acknowledgedBy, JSON.stringify({ alert_id: alertId }))
    .run();

  const updated = await db
    .prepare(`SELECT ${ALERT_COLUMNS} FROM alerts WHERE id = ?`)
    .bind(alertId)
    .first<AlertRow>();
  if (!updated) throw new AlertNotFoundError(alertId);
  return updated;
}

export async function resolveAlert(
  db: AlertStateDb,
  alertId: string,
  resolvedBy: string
): Promise<AlertRow> {
  const existing = await db
    .prepare("SELECT id FROM alerts WHERE id = ?")
    .bind(alertId)
    .first<{ id: string }>();
  if (!existing) throw new AlertNotFoundError(alertId);

  const now = new Date().toISOString();
  await db
    .prepare(
      `UPDATE alerts
       SET status = 'resolved', resolved_at = ?, resolved_by = ?, updated_at = ?
       WHERE id = ?`
    )
    .bind(now, resolvedBy, now, alertId)
    .run();

  await db
    .prepare(
      `INSERT INTO alert_timeline (id, alert_id, action, actor, metadata_json)
       VALUES (?, ?, 'resolved', ?, ?)`
    )
    .bind(randomUUID(), alertId, resolvedBy, JSON.stringify({ alert_id: alertId }))
    .run();

  const updated = await db
    .prepare(`SELECT ${ALERT_COLUMNS} FROM alerts WHERE id = ?`)
    .bind(alertId)
    .first<AlertRow>();
  if (!updated) throw new AlertNotFoundError(alertId);
  return updated;
}

export async function addAlertNote(
  db: AlertStateDb,
  alertId: string,
  body: string,
  author: string
): Promise<AlertNoteEntry> {
  const trimmedBody = body.trim();
  if (trimmedBody.length === 0) throw new AlertNoteBodyRequiredError();

  const existing = await db
    .prepare("SELECT id FROM alerts WHERE id = ?")
    .bind(alertId)
    .first<{ id: string }>();
  if (!existing) throw new AlertNotFoundError(alertId);

  const noteId = randomUUID();
  await db
    .prepare(
      `INSERT INTO alert_notes (id, alert_id, body, author)
       VALUES (?, ?, ?, ?)`
    )
    .bind(noteId, alertId, trimmedBody, author)
    .run();

  await db
    .prepare(
      `INSERT INTO alert_timeline (id, alert_id, action, actor, body, metadata_json)
       VALUES (?, ?, 'note_added', ?, ?, ?)`
    )
    .bind(randomUUID(), alertId, author, trimmedBody, JSON.stringify({ alert_id: alertId, note_id: noteId }))
    .run();

  const note = await db
    .prepare(`SELECT id, body, author, created_at FROM alert_notes WHERE id = ?`)
    .bind(noteId)
    .first<AlertNoteEntry>();
  if (!note) throw new AlertNotFoundError(alertId);
  return note;
}

export async function reopenAlert(
  db: AlertStateDb,
  alertId: string,
  actor: string
): Promise<AlertRow> {
  const existing = await db
    .prepare("SELECT status FROM alerts WHERE id = ?")
    .bind(alertId)
    .first<{ status: AlertStatus }>();
  if (!existing) throw new AlertNotFoundError(alertId);
  if (existing.status === "open") throw new AlertAlreadyOpenError(alertId);

  const now = new Date().toISOString();
  await db
    .prepare(
      `UPDATE alerts
       SET status = 'open', resolved_at = NULL, resolved_by = NULL, updated_at = ?
       WHERE id = ?`
    )
    .bind(now, alertId)
    .run();

  await db
    .prepare(
      `INSERT INTO alert_timeline (id, alert_id, action, actor, metadata_json)
       VALUES (?, ?, 'reopened', ?, ?)`
    )
    .bind(randomUUID(), alertId, actor, JSON.stringify({ alert_id: alertId, previous_status: existing.status }))
    .run();

  const updated = await db
    .prepare(`SELECT ${ALERT_COLUMNS} FROM alerts WHERE id = ?`)
    .bind(alertId)
    .first<AlertRow>();
  if (!updated) throw new AlertNotFoundError(alertId);
  return updated;
}

export async function assignAlert(
  db: AlertStateDb,
  alertId: string,
  assignee: string | null,
  actor: string
): Promise<AlertDetail> {
  const existing = await db
    .prepare("SELECT id FROM alerts WHERE id = ?")
    .bind(alertId)
    .first<{ id: string }>();
  if (!existing) throw new AlertNotFoundError(alertId);

  // Empty/whitespace assignee clears the assignment (unassign).
  const normalized = typeof assignee === "string" && assignee.trim().length > 0 ? assignee.trim() : null;
  const now = new Date().toISOString();
  await db
    .prepare(`UPDATE alerts SET assignee = ?, updated_at = ? WHERE id = ?`)
    .bind(normalized, now, alertId)
    .run();

  await db
    .prepare(
      `INSERT INTO alert_timeline (id, alert_id, action, actor, metadata_json)
       VALUES (?, ?, 'assigned', ?, ?)`
    )
    .bind(randomUUID(), alertId, actor, JSON.stringify({ alert_id: alertId, assignee: normalized }))
    .run();

  const updated = await db
    .prepare(`SELECT ${ALERT_DETAIL_COLUMNS} FROM alerts WHERE id = ?`)
    .bind(alertId)
    .first<AlertDetail>();
  if (!updated) throw new AlertNotFoundError(alertId);
  return updated;
}

export async function recordDeliveryAttempt(
  db: AlertStateDb,
  alertId: string,
  destination: string,
  extra?: Record<string, unknown>
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO alert_timeline (id, alert_id, action, actor, metadata_json)
       VALUES (?, ?, 'delivery_attempted', ?, ?)`
    )
    .bind(
      randomUUID(),
      alertId,
      "router",
      JSON.stringify({ alert_id: alertId, destination, ...(extra ?? {}) })
    )
    .run();
}

export async function recordDeliverySucceeded(
  db: AlertStateDb,
  alertId: string,
  destination: string,
  status: number,
  extra?: Record<string, unknown>
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO alert_timeline (id, alert_id, action, actor, metadata_json)
       VALUES (?, ?, 'delivery_succeeded', ?, ?)`
    )
    .bind(
      randomUUID(),
      alertId,
      "router",
      JSON.stringify({ alert_id: alertId, destination, status, ...(extra ?? {}) })
    )
    .run();
}

export async function recordDeliveryFailed(
  db: AlertStateDb,
  alertId: string,
  destination: string,
  error: string,
  extra?: Record<string, unknown>
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO alert_timeline (id, alert_id, action, actor, metadata_json)
       VALUES (?, ?, 'delivery_failed', ?, ?)`
    )
    .bind(
      randomUUID(),
      alertId,
      "router",
      JSON.stringify({ alert_id: alertId, destination, error, ...(extra ?? {}) })
    )
    .run();
}

export async function getAlertWithHistory(db: AlertStateDb, alertId: string): Promise<AlertWithHistory> {
  const alert = await db
    .prepare(`SELECT ${ALERT_DETAIL_COLUMNS} FROM alerts WHERE id = ?`)
    .bind(alertId)
    .first<AlertDetail>();
  if (!alert) throw new AlertNotFoundError(alertId);

  const timeline = await db
    .prepare(
      `SELECT id, action, actor, body, metadata_json, created_at
       FROM alert_timeline WHERE alert_id = ? ORDER BY created_at ASC`
    )
    .bind(alertId)
    .all<AlertTimelineEntry>();

  const notes = await db
    .prepare(
      `SELECT id, body, author, created_at
       FROM alert_notes WHERE alert_id = ? ORDER BY created_at ASC`
    )
    .bind(alertId)
    .all<AlertNoteEntry>();

  return { alert, timeline: timeline.results, notes: notes.results };
}

export function formatAlertDetail(detail: AlertWithHistory): string {
  const { alert, timeline, notes } = detail;
  const lines: string[] = [];
  lines.push(`Alert ${alert.id}`);
  lines.push(`  title:       ${alert.title}`);
  lines.push(`  rule:        ${alert.rule_id}`);
  lines.push(`  severity:    ${alert.severity}`);
  lines.push(`  status:      ${alert.status}`);
  lines.push(`  assignee:    ${alert.assignee ?? "(unassigned)"}`);
  lines.push(`  source:      ${alert.source}`);
  lines.push(`  matches:     ${alert.match_count}`);
  lines.push(`  first_seen:  ${alert.first_seen}`);
  lines.push(`  last_seen:   ${alert.last_seen}`);
  lines.push(`  updated_at:  ${alert.updated_at}`);
  if (alert.acknowledged_at) lines.push(`  acknowledged ${alert.acknowledged_at} by ${alert.acknowledged_by ?? "?"}`);
  if (alert.resolved_at) lines.push(`  resolved     ${alert.resolved_at} by ${alert.resolved_by ?? "?"}`);

  lines.push("");
  lines.push("Timeline:");
  if (timeline.length === 0) {
    lines.push("  (none)");
  } else {
    for (const entry of timeline) {
      const actor = entry.actor ? ` by ${entry.actor}` : "";
      lines.push(`  ${entry.created_at}  ${entry.action}${actor}`);
    }
  }

  lines.push("");
  lines.push("Notes:");
  if (notes.length === 0) {
    lines.push("  (none)");
  } else {
    for (const note of notes) {
      const author = note.author ? ` (${note.author})` : "";
      lines.push(`  ${note.created_at}${author}: ${note.body}`);
    }
  }

  return lines.join("\n");
}

export function formatAlertsTable(alerts: readonly AlertRow[]): string {
  if (alerts.length === 0) return "No alerts found.";

  const headers = ["id", "severity", "status", "rule_id", "source", "match_count", "last_seen", "title"] as const;
  const rows: string[][] = alerts.map((alert) => [
    alert.id,
    alert.severity,
    alert.status,
    alert.rule_id,
    alert.source,
    String(alert.match_count),
    alert.last_seen,
    alert.title
  ]);

  const widths = headers.map((header, columnIndex) => {
    let width = header.length;
    for (const row of rows) {
      const cell = row[columnIndex] ?? "";
      if (cell.length > width) width = cell.length;
    }
    return width;
  });

  const padRow = (cells: readonly string[]): string =>
    cells.map((cell, columnIndex) => cell.padEnd(widths[columnIndex] ?? 0)).join("  ");

  const separator = widths.map((width) => "-".repeat(width));

  return [padRow(headers), padRow(separator), ...rows.map(padRow)].join("\n");
}
