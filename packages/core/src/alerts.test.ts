import { describe, expect, it } from "vitest";

import { alertStats, countAlerts, formatAlertStats, listAlerts } from "./alerts.js";
import { FakeAlertDb, type FakeAlertRow } from "./alerts-fake-db.js";

function row(overrides: Partial<FakeAlertRow> & { id: string }): FakeAlertRow {
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

describe("alertStats", () => {
  it("aggregates counts across severity, status, rule, and source", async () => {
    const db = new FakeAlertDb([
      row({ id: "a", severity: "high", status: "open", rule_id: "r1", source: "aws_cloudtrail" }),
      row({ id: "b", severity: "high", status: "resolved", rule_id: "r1", source: "aws_cloudtrail" }),
      row({ id: "c", severity: "low", status: "open", rule_id: "r2", source: "kubernetes_audit" })
    ]);

    const stats = await alertStats(db);

    expect(stats.total).toBe(3);
    // Severity is returned across the full canonical scale with zero buckets.
    expect(stats.by_severity).toEqual([
      { key: "critical", count: 0 },
      { key: "high", count: 2 },
      { key: "medium", count: 0 },
      { key: "low", count: 1 },
      { key: "informational", count: 0 }
    ]);
    expect(stats.by_status).toEqual([
      { key: "open", count: 2 },
      { key: "acknowledged", count: 0 },
      { key: "resolved", count: 1 }
    ]);
    // Rule/source are dynamic, ordered by count desc then key asc.
    expect(stats.by_rule).toEqual([
      { key: "r1", count: 2 },
      { key: "r2", count: 1 }
    ]);
    expect(stats.by_source).toEqual([
      { key: "aws_cloudtrail", count: 2 },
      { key: "kubernetes_audit", count: 1 }
    ]);
  });

  it("returns zero buckets and total 0 for an empty table", async () => {
    const stats = await alertStats(new FakeAlertDb());
    expect(stats.total).toBe(0);
    expect(stats.by_severity.every((entry) => entry.count === 0)).toBe(true);
    expect(stats.by_rule).toEqual([]);
    expect(stats.by_source).toEqual([]);
  });

  it("renders a readable table", async () => {
    const db = new FakeAlertDb([row({ id: "a", severity: "critical" })]);
    const out = formatAlertStats(await alertStats(db));
    expect(out).toContain("Total alerts: 1");
    expect(out).toContain("By severity:");
    expect(out).toContain("critical");
    expect(out).toContain("By source:");
  });
});

describe("listAlerts", () => {
  it("sorts by severity and paginates with a matching total", async () => {
    const db = new FakeAlertDb([
      row({ id: "medium", severity: "medium" }),
      row({ id: "critical", severity: "critical" }),
      row({ id: "low", severity: "low" })
    ]);

    const alerts = await listAlerts(db, { limit: 1, offset: 1, sort: "severity", direction: "desc" });
    const total = await countAlerts(db, {});

    expect(alerts.map((alert) => alert.id)).toEqual(["medium"]);
    expect(total).toBe(3);
  });
});
