import type { AlertStateDb } from "./alerts.js";

// Detection-engine heartbeat (Milestone 0.4). The detection worker records an
// eval on every event; `picket status` and the API read the singleton row to
// report liveness and rule coverage.

export interface DetectionHealthRow {
  last_eval_at: string | null;
  total_events_evaluated: number;
  total_alerts_created: number;
  stateless_rule_count: number;
  stateful_rule_count: number;
  updated_at: string | null;
}

export type DetectionHealthStatus = "healthy" | "stale" | "unknown";

export interface RecordDetectionEvalInput {
  events_evaluated: number;
  alerts_created: number;
  stateless_rule_count: number;
  stateful_rule_count: number;
}

// Detection runs inline on ingest; if it hasn't evaluated anything in this long
// the engine (or the ingest path feeding it) is likely wedged.
const DEFAULT_DETECTION_FRESHNESS_WINDOW_MS = 15 * 60_000;

const DETECTION_HEALTH_COLUMNS =
  "last_eval_at, total_events_evaluated, total_alerts_created, stateless_rule_count, stateful_rule_count, updated_at";

export function detectionFreshnessWindowMs(): number {
  return DEFAULT_DETECTION_FRESHNESS_WINDOW_MS;
}

export async function recordDetectionEval(
  db: AlertStateDb,
  input: RecordDetectionEvalInput
): Promise<void> {
  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO detection_health (
         id, last_eval_at, total_events_evaluated, total_alerts_created,
         stateless_rule_count, stateful_rule_count, updated_at
       ) VALUES (1, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         last_eval_at = excluded.last_eval_at,
         total_events_evaluated = detection_health.total_events_evaluated + excluded.total_events_evaluated,
         total_alerts_created = detection_health.total_alerts_created + excluded.total_alerts_created,
         stateless_rule_count = excluded.stateless_rule_count,
         stateful_rule_count = excluded.stateful_rule_count,
         updated_at = excluded.updated_at`
    )
    .bind(
      now,
      input.events_evaluated,
      input.alerts_created,
      input.stateless_rule_count,
      input.stateful_rule_count,
      now
    )
    .run();
}

export async function getDetectionHealth(db: AlertStateDb): Promise<DetectionHealthRow | null> {
  const row = await db
    .prepare(`SELECT ${DETECTION_HEALTH_COLUMNS} FROM detection_health WHERE id = 1`)
    .first<DetectionHealthRow>();
  return row ?? null;
}

export function classifyDetectionHealth(
  row: Pick<DetectionHealthRow, "last_eval_at"> | null,
  now: Date
): DetectionHealthStatus {
  if (!row || !row.last_eval_at) return "unknown";
  const lastMs = Date.parse(row.last_eval_at);
  if (!Number.isFinite(lastMs)) return "unknown";
  return now.getTime() - lastMs <= detectionFreshnessWindowMs() ? "healthy" : "stale";
}

export interface FormatDetectionHealthOptions {
  now: Date;
}

export function formatDetectionHealth(
  row: DetectionHealthRow | null,
  options: FormatDetectionHealthOptions
): string {
  const status = classifyDetectionHealth(row, options.now);
  if (!row) {
    return `Detection engine: ${status} (no evaluations recorded yet)`;
  }
  const rules = row.stateless_rule_count + row.stateful_rule_count;
  return [
    `Detection engine: ${status}`,
    `  last_eval_at:     ${row.last_eval_at ?? "-"}`,
    `  rules:            ${rules} (${row.stateless_rule_count} stateless, ${row.stateful_rule_count} stateful)`,
    `  events_evaluated: ${row.total_events_evaluated}`,
    `  alerts_created:   ${row.total_alerts_created}`
  ].join("\n");
}
