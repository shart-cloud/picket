import { flattenAlert, type Alert } from "./index.js";

// Shared alert-emission path (Milestone 3). Both the realtime detection worker
// and the scheduled-detection worker create Alert objects and must route them
// through the same dedup/persist/pipeline/queue path. That logic lives here so
// there is exactly one implementation.

export interface PicketPipeline {
  send(records: Record<string, unknown>[]): Promise<void>;
}

export interface PersistedAlert {
  alert: Alert;
  isNew: boolean;
}

export const DEFAULT_DEDUPE_WINDOW_MS = 15 * 60_000;

// Upsert each alert into D1, deduping against an open/acknowledged alert with the
// same rule + dedupe_key inside the window. Returns whether each alert was newly
// created (vs. folded into an existing one).
export async function persistAlerts(
  db: D1Database,
  alerts: readonly Alert[],
  dedupeWindowMs: number = DEFAULT_DEDUPE_WINDOW_MS
): Promise<PersistedAlert[]> {
  const results: PersistedAlert[] = [];
  for (const alert of alerts) {
    results.push(await upsertAlertState(alert, db, dedupeWindowMs));
  }
  return results;
}

export async function writeAlertsToPipeline(pipeline: PicketPipeline, alerts: readonly Alert[]): Promise<void> {
  if (alerts.length === 0) return;
  await pipeline.send(alerts.map((alert) => flattenAlert(alert)));
}

export async function enqueueAlerts(queue: Queue<Alert>, alerts: readonly Alert[]): Promise<void> {
  if (alerts.length === 0) return;
  await Promise.all(alerts.map((alert) => queue.send(alert)));
}

async function upsertAlertState(alert: Alert, db: D1Database, dedupeWindowMs: number): Promise<PersistedAlert> {
  const lastSeenMs = Date.parse(alert.last_seen);
  const cutoff = new Date((Number.isFinite(lastSeenMs) ? lastSeenMs : Date.now()) - dedupeWindowMs).toISOString();
  const existing = alert.dedupe_key
    ? await db
        .prepare(
          `SELECT id, match_count, first_seen
           FROM alerts
           WHERE rule_id = ?
             AND dedupe_key = ?
             AND status IN ('open', 'acknowledged')
             AND last_seen >= ?
           ORDER BY last_seen DESC
           LIMIT 1`
        )
        .bind(alert.rule_id, alert.dedupe_key, cutoff)
        .first<{ id: string; match_count: number; first_seen: string }>()
    : null;

  if (existing) {
    const now = new Date().toISOString();
    const updatedAlert: Alert = {
      ...alert,
      id: existing.id,
      first_seen: existing.first_seen,
      match_count: existing.match_count + 1
    };
    await db
      .prepare(
        `UPDATE alerts
         SET match_count = ?, last_seen = ?, updated_at = ?, event_json = ?
         WHERE id = ?`
      )
      .bind(updatedAlert.match_count, updatedAlert.last_seen, now, JSON.stringify(updatedAlert.event), updatedAlert.id)
      .run();
    await insertTimeline(db, updatedAlert.id, "matched", { rule_id: updatedAlert.rule_id, dedupe_key: updatedAlert.dedupe_key });
    return { alert: updatedAlert, isNew: false };
  }

  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO alerts (
        id, rule_id, title, severity, source, status, dedupe_key, match_count,
        first_seen, last_seen, created_at, updated_at, event_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      alert.id,
      alert.rule_id,
      alert.title,
      alert.severity,
      alert.source,
      alert.status,
      alert.dedupe_key ?? null,
      alert.match_count,
      alert.first_seen,
      alert.last_seen,
      now,
      now,
      JSON.stringify(alert.event)
    )
    .run();
  await insertTimeline(db, alert.id, "created", { rule_id: alert.rule_id, dedupe_key: alert.dedupe_key });
  return { alert, isNew: true };
}

async function insertTimeline(
  db: D1Database,
  alertId: string,
  action: "created" | "matched",
  metadata: Record<string, unknown>
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO alert_timeline (id, alert_id, action, metadata_json)
       VALUES (?, ?, ?, ?)`
    )
    .bind(crypto.randomUUID(), alertId, action, JSON.stringify(metadata))
    .run();
}
