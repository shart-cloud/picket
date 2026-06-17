import type { AlertStateDb } from "./alerts.js";
import { listDetectionRules } from "./detection-rules.js";

// Run-state for scheduled SQL detections (Milestone 3). The scheduled-detection
// worker upserts a row per rule after each run; the cron tick reads last_run_at
// to decide which rules are due, and the API/CLI surface per-rule run health.

export type ScheduledRunStatus = "ok" | "error" | "skipped";

export interface ScheduledDetectionStateRow {
  rule_id: string;
  last_run_at: string | null;
  last_status: ScheduledRunStatus | null;
  last_row_count: number | null;
  last_alert_count: number | null;
  last_error: string | null;
  updated_at: string;
}

export interface RecordScheduledRunInput {
  rule_id: string;
  status: ScheduledRunStatus;
  row_count?: number | null;
  alert_count?: number | null;
  error?: string | null;
  now: string;
}

const STATE_COLUMNS =
  "rule_id, last_run_at, last_status, last_row_count, last_alert_count, last_error, updated_at";

export async function getScheduledState(
  db: AlertStateDb,
  ruleId: string
): Promise<ScheduledDetectionStateRow | null> {
  const row = await db
    .prepare(`SELECT ${STATE_COLUMNS} FROM scheduled_detection_state WHERE rule_id = ?`)
    .bind(ruleId)
    .first<ScheduledDetectionStateRow>();
  return row ?? null;
}

export async function listScheduledState(db: AlertStateDb): Promise<ScheduledDetectionStateRow[]> {
  const result = await db
    .prepare(`SELECT ${STATE_COLUMNS} FROM scheduled_detection_state ORDER BY rule_id ASC`)
    .all<ScheduledDetectionStateRow>();
  return result.results;
}

export async function recordScheduledRun(db: AlertStateDb, input: RecordScheduledRunInput): Promise<void> {
  await db
    .prepare(
      `INSERT INTO scheduled_detection_state (
         rule_id, last_run_at, last_status, last_row_count, last_alert_count, last_error, updated_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(rule_id) DO UPDATE SET
         last_run_at = excluded.last_run_at,
         last_status = excluded.last_status,
         last_row_count = excluded.last_row_count,
         last_alert_count = excluded.last_alert_count,
         last_error = excluded.last_error,
         updated_at = excluded.updated_at`
    )
    .bind(
      input.rule_id,
      input.now,
      input.status,
      input.row_count ?? null,
      input.alert_count ?? null,
      input.error ?? null,
      input.now
    )
    .run();
}

// A rule is due when it has never run, or its interval has elapsed since the
// last run. Parsing failures are treated as "due" so a malformed interval can't
// silently wedge a rule.
export function isScheduledRuleDue(
  state: Pick<ScheduledDetectionStateRow, "last_run_at"> | null,
  intervalMs: number,
  now: Date
): boolean {
  if (!state || !state.last_run_at) return true;
  const lastMs = Date.parse(state.last_run_at);
  if (!Number.isFinite(lastMs)) return true;
  return now.getTime() - lastMs >= intervalMs;
}

// A scheduled (`execution: sql`) rule joined with its run state, for the
// run-health surface (GET /api/v1/detections/scheduled, `picket detections
// scheduled`). The `due` flag reflects whether the next cron tick would run it.
export interface ScheduledDetectionView {
  id: string;
  title: string;
  severity: string;
  source: string;
  enabled: boolean;
  interval: string | null;
  last_run_at: string | null;
  last_status: ScheduledRunStatus | null;
  last_row_count: number | null;
  last_alert_count: number | null;
  last_error: string | null;
  due: boolean;
}

export async function listScheduledDetections(
  db: AlertStateDb,
  now: Date
): Promise<ScheduledDetectionView[]> {
  const rules = (await listDetectionRules(db)).filter((rule) => rule.execution === "sql");
  const states = await listScheduledState(db);
  const stateById = new Map(states.map((state) => [state.rule_id, state]));

  return rules.map((rule) => {
    const interval = extractInterval(rule.definition);
    const state = stateById.get(rule.id) ?? null;
    let due = true;
    if (interval) {
      try {
        due = isScheduledRuleDue(state, parseDurationMs(interval), now);
      } catch {
        due = true;
      }
    }
    return {
      id: rule.id,
      title: rule.title,
      severity: rule.severity,
      source: rule.source,
      enabled: rule.enabled,
      interval,
      last_run_at: state?.last_run_at ?? null,
      last_status: (state?.last_status as ScheduledRunStatus | null) ?? null,
      last_row_count: state?.last_row_count ?? null,
      last_alert_count: state?.last_alert_count ?? null,
      last_error: state?.last_error ?? null,
      due
    };
  });
}

function extractInterval(definition: unknown): string | null {
  if (definition && typeof definition === "object") {
    const sql = (definition as { sql?: unknown }).sql;
    if (sql && typeof sql === "object") {
      const interval = (sql as { interval?: unknown }).interval;
      if (typeof interval === "string") return interval;
    }
  }
  return null;
}

export function formatScheduledDetectionsTable(rows: readonly ScheduledDetectionView[]): string {
  if (rows.length === 0) return "No scheduled detections.";
  const headers = ["id", "enabled", "interval", "due", "last_run_at", "status", "rows", "alerts", "last_error"] as const;
  const body: string[][] = rows.map((row) => [
    row.id,
    row.enabled ? "yes" : "no",
    row.interval ?? "-",
    row.due ? "yes" : "no",
    row.last_run_at ?? "-",
    row.last_status ?? "-",
    row.last_row_count === null ? "-" : String(row.last_row_count),
    row.last_alert_count === null ? "-" : String(row.last_alert_count),
    row.last_error ?? "-"
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

// Parse a duration like "15m" / "1h" / "30s" / "2d" into milliseconds.
export function parseDurationMs(value: string): number {
  const match = /^(\d+)([smhd])$/.exec(value);
  if (!match) throw new Error(`Invalid duration: ${value}`);
  const amount = Number(match[1]);
  switch (match[2]) {
    case "s":
      return amount * 1_000;
    case "m":
      return amount * 60_000;
    case "h":
      return amount * 3_600_000;
    default:
      return amount * 86_400_000;
  }
}
