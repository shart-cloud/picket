import { describe, expect, it } from "vitest";

import {
  formatScheduledDetectionsTable,
  getScheduledState,
  isScheduledRuleDue,
  listScheduledDetections,
  listScheduledState,
  parseDurationMs,
  recordScheduledRun
} from "./scheduled-detection.js";
import { FakeAlertDb, type FakeDetectionRuleRow } from "./alerts-fake-db.js";

function sqlRuleRow(id: string, interval: string, overrides: Partial<FakeDetectionRuleRow> = {}): FakeDetectionRuleRow {
  return {
    id,
    title: `Rule ${id}`,
    description: null,
    severity: "high",
    source: "aws_cloudtrail",
    class_name: "api_activity",
    execution: "sql",
    tags_json: "[]",
    enabled: 1,
    definition_json: JSON.stringify({ id, sql: { interval } }),
    match_count: 0,
    last_triggered_at: null,
    created_at: "2026-05-27T12:00:00.000Z",
    updated_at: "2026-05-27T12:00:00.000Z",
    ...overrides
  };
}

describe("scheduled detection state", () => {
  it("records and reads back a run", async () => {
    const db = new FakeAlertDb();
    await recordScheduledRun(db, {
      rule_id: "r1",
      status: "ok",
      row_count: 3,
      alert_count: 2,
      now: "2026-05-27T12:00:00.000Z"
    });

    const row = await getScheduledState(db, "r1");
    expect(row).toMatchObject({
      rule_id: "r1",
      last_run_at: "2026-05-27T12:00:00.000Z",
      last_status: "ok",
      last_row_count: 3,
      last_alert_count: 2,
      last_error: null
    });
  });

  it("upserts on a second run for the same rule", async () => {
    const db = new FakeAlertDb();
    await recordScheduledRun(db, { rule_id: "r1", status: "ok", now: "2026-05-27T12:00:00.000Z" });
    await recordScheduledRun(db, { rule_id: "r1", status: "error", error: "boom", now: "2026-05-27T12:15:00.000Z" });

    const rows = await listScheduledState(db);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ last_status: "error", last_error: "boom", last_run_at: "2026-05-27T12:15:00.000Z" });
  });
});

describe("isScheduledRuleDue", () => {
  const now = new Date("2026-05-27T12:30:00.000Z");

  it("is due when never run", () => {
    expect(isScheduledRuleDue(null, 15 * 60_000, now)).toBe(true);
    expect(isScheduledRuleDue({ last_run_at: null }, 15 * 60_000, now)).toBe(true);
  });

  it("is due only after the interval elapses", () => {
    // now = 12:30, interval = 15m
    expect(isScheduledRuleDue({ last_run_at: "2026-05-27T12:20:00.000Z" }, 15 * 60_000, now)).toBe(false); // 10m ago
    expect(isScheduledRuleDue({ last_run_at: "2026-05-27T12:16:00.000Z" }, 15 * 60_000, now)).toBe(false); // 14m ago
    expect(isScheduledRuleDue({ last_run_at: "2026-05-27T12:14:00.000Z" }, 15 * 60_000, now)).toBe(true); // 16m ago
    expect(isScheduledRuleDue({ last_run_at: "2026-05-27T12:10:00.000Z" }, 15 * 60_000, now)).toBe(true); // 20m ago
  });

  it("treats an unparseable timestamp as due", () => {
    expect(isScheduledRuleDue({ last_run_at: "not-a-date" }, 15 * 60_000, now)).toBe(true);
  });
});

describe("listScheduledDetections", () => {
  const now = new Date("2026-05-27T12:30:00.000Z");

  it("joins sql rules with run state and computes the due flag", async () => {
    const db = new FakeAlertDb();
    db.detectionRules.push(sqlRuleRow("sql-a", "15m"));
    db.detectionRules.push(sqlRuleRow("sql-b", "15m"));
    // A non-sql rule must be excluded.
    db.detectionRules.push(sqlRuleRow("sigma-x", "15m", { execution: "sigma" }));
    // sql-a ran 20m ago → due; sql-b ran 5m ago → not due.
    await recordScheduledRun(db, { rule_id: "sql-a", status: "ok", row_count: 4, alert_count: 1, now: "2026-05-27T12:10:00.000Z" });
    await recordScheduledRun(db, { rule_id: "sql-b", status: "ok", row_count: 0, alert_count: 0, now: "2026-05-27T12:25:00.000Z" });

    const views = await listScheduledDetections(db, now);
    expect(views.map((v) => v.id)).toEqual(["sql-a", "sql-b"]);

    const a = views.find((v) => v.id === "sql-a");
    expect(a).toMatchObject({ interval: "15m", due: true, last_status: "ok", last_row_count: 4, last_alert_count: 1 });

    const b = views.find((v) => v.id === "sql-b");
    expect(b?.due).toBe(false);
  });

  it("marks a never-run rule as due with null state", async () => {
    const db = new FakeAlertDb();
    db.detectionRules.push(sqlRuleRow("sql-a", "1h"));
    const [view] = await listScheduledDetections(db, now);
    expect(view).toMatchObject({ id: "sql-a", due: true, last_run_at: null, last_status: null });
  });

  it("renders a table and an empty placeholder", async () => {
    const db = new FakeAlertDb();
    db.detectionRules.push(sqlRuleRow("sql-a", "15m"));
    const out = formatScheduledDetectionsTable(await listScheduledDetections(db, now));
    expect(out).toContain("sql-a");
    expect(out).toContain("interval");
    expect(formatScheduledDetectionsTable([])).toBe("No scheduled detections.");
  });
});

describe("parseDurationMs", () => {
  it("parses s/m/h/d units", () => {
    expect(parseDurationMs("30s")).toBe(30_000);
    expect(parseDurationMs("15m")).toBe(900_000);
    expect(parseDurationMs("1h")).toBe(3_600_000);
    expect(parseDurationMs("2d")).toBe(172_800_000);
  });

  it("throws on a malformed duration", () => {
    expect(() => parseDurationMs("15")).toThrow(/Invalid duration/);
  });
});
