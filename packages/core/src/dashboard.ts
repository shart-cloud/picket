import { alertStats, type AlertStateDb, type AlertStats } from "./alerts.js";
import {
  classifyDetectionHealth,
  getDetectionHealth,
  type DetectionHealthRow,
  type DetectionHealthStatus
} from "./detection-health.js";
import { listDetectionRules } from "./detection-rules.js";
import {
  classifySourceHealth,
  listSourceHealth,
  type SourceHealthRow,
  type SourceHealthStatus
} from "./source-health.js";

// Dashboard overview (Milestone 1): one aggregation endpoint stitching together
// ingestion health (source_health), alert stats, and detection-engine health +
// rule counts. Useful for CLI/automation today and UI-ready for the parked
// frontend. Health classifications are computed server-side against `now` so the
// payload is render-only for clients.

export interface DashboardSourceSummary {
  total: number;
  healthy: number;
  stale: number;
  unknown: number;
  items: Array<SourceHealthRow & { health: SourceHealthStatus }>;
}

export interface DashboardDetectionSummary {
  health: DetectionHealthRow | null;
  status: DetectionHealthStatus;
  rules: {
    total: number;
    enabled: number;
    disabled: number;
  };
}

export interface DashboardOverview {
  generated_at: string;
  sources: DashboardSourceSummary;
  alerts: AlertStats;
  detection: DashboardDetectionSummary;
}

export interface BuildDashboardOverviewOptions {
  now: Date;
  tenant_id?: string;
}

export async function buildDashboardOverview(
  db: AlertStateDb,
  options: BuildDashboardOverviewOptions
): Promise<DashboardOverview> {
  const { now } = options;

  const sourceRows = await listSourceHealth(db, options.tenant_id ? { tenant_id: options.tenant_id } : {});
  const items = sourceRows.map((row) => ({ ...row, health: classifySourceHealth(row, now) }));
  const sources: DashboardSourceSummary = {
    total: items.length,
    healthy: items.filter((item) => item.health === "healthy").length,
    stale: items.filter((item) => item.health === "stale").length,
    unknown: items.filter((item) => item.health === "unknown").length,
    items
  };

  const alerts = await alertStats(db);

  const detectionHealth = await getDetectionHealth(db);
  const rules = await listDetectionRules(db);
  const enabled = rules.filter((rule) => rule.enabled).length;
  const detection: DashboardDetectionSummary = {
    health: detectionHealth,
    status: classifyDetectionHealth(detectionHealth, now),
    rules: {
      total: rules.length,
      enabled,
      disabled: rules.length - enabled
    }
  };

  return {
    generated_at: now.toISOString(),
    sources,
    alerts,
    detection
  };
}

export function formatDashboardOverview(overview: DashboardOverview): string {
  const lines: string[] = [];
  lines.push(`Picket dashboard — ${overview.generated_at}`);

  lines.push("");
  lines.push(
    `Sources: ${overview.sources.total} ` +
      `(${overview.sources.healthy} healthy, ${overview.sources.stale} stale, ${overview.sources.unknown} unknown)`
  );
  for (const item of overview.sources.items) {
    lines.push(`  ${item.source.padEnd(20)} ${item.health.padEnd(8)} last_event=${item.last_event_at ?? "-"}`);
  }

  lines.push("");
  lines.push(`Alerts: ${overview.alerts.total} total`);
  for (const entry of overview.alerts.by_severity) {
    if (entry.count > 0) lines.push(`  ${entry.key.padEnd(14)} ${entry.count}`);
  }

  lines.push("");
  const { detection } = overview;
  lines.push(`Detection engine: ${detection.status}`);
  lines.push(
    `  rules: ${detection.rules.total} (${detection.rules.enabled} enabled, ${detection.rules.disabled} disabled)`
  );
  if (detection.health) {
    lines.push(`  last_eval_at:     ${detection.health.last_eval_at ?? "-"}`);
    lines.push(`  events_evaluated: ${detection.health.total_events_evaluated}`);
    lines.push(`  alerts_created:   ${detection.health.total_alerts_created}`);
  }

  return lines.join("\n");
}
