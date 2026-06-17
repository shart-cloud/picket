import { describe, expect, it } from "vitest";

import { buildDashboardOverview, formatDashboardOverview } from "./dashboard.js";
import { seedDetectionRules } from "./detection-rules.js";
import { FakeAlertDb, type FakeAlertRow } from "./alerts-fake-db.js";

const NOW = new Date("2026-05-27T12:10:00.000Z");

function alert(overrides: Partial<FakeAlertRow> & { id: string }): FakeAlertRow {
  return {
    rule_id: "aws-root-account-usage",
    title: "Root account usage",
    severity: "high",
    source: "aws_cloudtrail",
    status: "open",
    match_count: 1,
    first_seen: "2026-05-26T10:00:00.000Z",
    last_seen: "2026-05-26T10:00:00.000Z",
    updated_at: "2026-05-26T10:00:00.000Z",
    ...overrides
  };
}

function seedSourceHealth(db: FakeAlertDb): void {
  db.sourceHealth.push({
    source: "aws_cloudtrail",
    tenant_id: "default",
    last_event_at: "2026-05-27T12:05:00.000Z", // 5min ago → healthy (10min window)
    last_event_count: 1,
    total_events: 10,
    total_batches: 3,
    total_errors: 0,
    last_error_at: null,
    last_error_message: null,
    updated_at: "2026-05-27T12:05:00.000Z"
  });
  db.sourceHealth.push({
    source: "kubernetes_audit",
    tenant_id: "default",
    last_event_at: "2026-05-27T12:00:00.000Z", // 10min ago → stale (5min window)
    last_event_count: 1,
    total_events: 4,
    total_batches: 2,
    total_errors: 1,
    last_error_at: "2026-05-27T12:01:00.000Z",
    last_error_message: "bad ndjson",
    updated_at: "2026-05-27T12:01:00.000Z"
  });
}

describe("buildDashboardOverview", () => {
  it("stitches source health, alert stats, and detection summary", async () => {
    const db = new FakeAlertDb([
      alert({ id: "a", severity: "high" }),
      alert({ id: "b", severity: "low", status: "resolved" })
    ]);
    seedSourceHealth(db);
    await seedDetectionRules(db, [
      { id: "r1", title: "R1", severity: "high", source: "aws_cloudtrail", execution: "sigma", tags: [], enabled: true, definition: {} },
      { id: "r2", title: "R2", severity: "medium", source: "kubernetes_audit", execution: "sigma", tags: [], enabled: false, definition: {} }
    ]);
    db.detectionHealth = {
      last_eval_at: "2026-05-27T12:08:00.000Z",
      total_events_evaluated: 42,
      total_alerts_created: 3,
      stateless_rule_count: 2,
      stateful_rule_count: 0,
      updated_at: "2026-05-27T12:08:00.000Z"
    };

    const overview = await buildDashboardOverview(db, { now: NOW });

    expect(overview.generated_at).toBe(NOW.toISOString());
    expect(overview.sources.total).toBe(2);
    expect(overview.sources.healthy).toBe(1);
    expect(overview.sources.stale).toBe(1);
    expect(overview.sources.items.find((item) => item.source === "aws_cloudtrail")?.health).toBe("healthy");

    expect(overview.alerts.total).toBe(2);

    expect(overview.detection.status).toBe("healthy");
    expect(overview.detection.rules).toEqual({ total: 2, enabled: 1, disabled: 1 });
    expect(overview.detection.health?.total_events_evaluated).toBe(42);
  });

  it("reports an empty deployment cleanly", async () => {
    const overview = await buildDashboardOverview(new FakeAlertDb(), { now: NOW });
    expect(overview.sources.total).toBe(0);
    expect(overview.alerts.total).toBe(0);
    expect(overview.detection.status).toBe("unknown");
    expect(overview.detection.rules).toEqual({ total: 0, enabled: 0, disabled: 0 });
  });

  it("filters sources by tenant", async () => {
    const db = new FakeAlertDb();
    seedSourceHealth(db);
    db.sourceHealth.push({
      source: "cloudflare_audit",
      tenant_id: "other",
      last_event_at: "2026-05-27T12:05:00.000Z",
      last_event_count: 1,
      total_events: 1,
      total_batches: 1,
      total_errors: 0,
      last_error_at: null,
      last_error_message: null,
      updated_at: "2026-05-27T12:05:00.000Z"
    });

    const overview = await buildDashboardOverview(db, { now: NOW, tenant_id: "other" });
    expect(overview.sources.total).toBe(1);
    expect(overview.sources.items[0]?.source).toBe("cloudflare_audit");
  });

  it("renders a readable overview", async () => {
    const db = new FakeAlertDb([alert({ id: "a" })]);
    seedSourceHealth(db);
    const out = formatDashboardOverview(await buildDashboardOverview(db, { now: NOW }));
    expect(out).toContain("Picket dashboard");
    expect(out).toContain("Sources: 2");
    expect(out).toContain("Detection engine:");
  });
});
