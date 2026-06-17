import { describe, expect, it } from "vitest";

import { FakeAlertDb } from "./alerts-fake-db.js";
import {
  classifySourceHealth,
  formatSourceHealthTable,
  freshnessWindowMs,
  getSourceHealth,
  listSourceHealthHistory,
  listSourceHealth,
  recordIngestBatch,
  recordIngestError
} from "./source-health.js";

describe("recordIngestBatch", () => {
  it("inserts a new row on first call", async () => {
    const db = new FakeAlertDb();

    await recordIngestBatch(db, {
      source: "aws_cloudtrail",
      tenant_id: "tenant-a",
      event_count: 3,
      last_event_at: "2026-05-27T12:00:00.000Z"
    });

    expect(db.sourceHealth).toHaveLength(1);
    const [row] = db.sourceHealth;
    expect(row).toMatchObject({
      source: "aws_cloudtrail",
      tenant_id: "tenant-a",
      last_event_at: "2026-05-27T12:00:00.000Z",
      last_event_count: 3,
      total_events: 3,
      total_batches: 1,
      total_errors: 0
    });
    expect(db.sourceHealthHistory[0]).toMatchObject({ kind: "batch", event_count: 3 });
  });

  it("accumulates counters and advances last_event_at monotonically", async () => {
    const db = new FakeAlertDb();
    const base = { source: "aws_cloudtrail", tenant_id: "tenant-a" } as const;

    await recordIngestBatch(db, { ...base, event_count: 2, last_event_at: "2026-05-27T12:00:00.000Z" });
    await recordIngestBatch(db, { ...base, event_count: 4, last_event_at: "2026-05-27T12:05:00.000Z" });
    // Out-of-order older batch should NOT regress last_event_at:
    await recordIngestBatch(db, { ...base, event_count: 1, last_event_at: "2026-05-27T11:00:00.000Z" });

    expect(db.sourceHealth).toHaveLength(1);
    expect(db.sourceHealth[0]).toMatchObject({
      total_events: 7,
      total_batches: 3,
      last_event_at: "2026-05-27T12:05:00.000Z",
      last_event_count: 1
    });
  });

  it("defaults missing tenant_id to 'default'", async () => {
    const db = new FakeAlertDb();
    await recordIngestBatch(db, {
      source: "cloudflare_audit",
      event_count: 1,
      last_event_at: "2026-05-27T12:00:00.000Z"
    });
    expect(db.sourceHealth[0]?.tenant_id).toBe("default");
  });
});

describe("recordIngestError", () => {
  it("increments errors and truncates long messages", async () => {
    const db = new FakeAlertDb();
    const long = "x".repeat(800);

    await recordIngestError(db, { source: "aws_cloudtrail", tenant_id: "t1", message: long });
    await recordIngestError(db, { source: "aws_cloudtrail", tenant_id: "t1", message: "shorter" });

    expect(db.sourceHealth).toHaveLength(1);
    const [row] = db.sourceHealth;
    expect(row?.total_errors).toBe(2);
    expect(row?.last_error_message).toBe("shorter");
    expect(db.sourceHealthHistory.map((entry) => entry.kind)).toEqual(["error", "error"]);
  });

  it("creates a row if the source has not reported any batches yet", async () => {
    const db = new FakeAlertDb();
    await recordIngestError(db, { source: "kubernetes_audit", message: "parse failure" });

    expect(db.sourceHealth).toHaveLength(1);
    expect(db.sourceHealth[0]).toMatchObject({
      source: "kubernetes_audit",
      tenant_id: "default",
      total_errors: 1,
      total_events: 0,
      total_batches: 0,
      last_error_message: "parse failure"
    });
  });

  it("truncation cap matches the documented MAX_ERROR_LENGTH", async () => {
    const db = new FakeAlertDb();
    await recordIngestError(db, {
      source: "aws_cloudtrail",
      message: "y".repeat(600)
    });
    expect(db.sourceHealth[0]?.last_error_message?.length).toBe(500);
  });
});

describe("listSourceHealthHistory", () => {
  it("returns recent activity and supports error-only filtering", async () => {
    const db = new FakeAlertDb();
    await recordIngestBatch(db, {
      source: "aws_cloudtrail",
      tenant_id: "t1",
      event_count: 2,
      last_event_at: "2026-05-27T12:00:00.000Z"
    });
    await recordIngestError(db, { source: "aws_cloudtrail", tenant_id: "t1", message: "bad record" });

    const history = await listSourceHealthHistory(db, "aws_cloudtrail", { tenant_id: "t1" });
    expect(history).toHaveLength(2);
    expect(history[0]?.kind).toBe("error");

    const errors = await listSourceHealthHistory(db, "aws_cloudtrail", { kind: "error" });
    expect(errors).toHaveLength(1);
    expect(errors[0]?.error_message).toBe("bad record");
  });
});

describe("listSourceHealth / getSourceHealth", () => {
  it("lists all rows ordered by source", async () => {
    const db = new FakeAlertDb();
    await recordIngestBatch(db, {
      source: "kubernetes_audit",
      event_count: 1,
      last_event_at: "2026-05-27T12:00:00.000Z"
    });
    await recordIngestBatch(db, {
      source: "aws_cloudtrail",
      event_count: 2,
      last_event_at: "2026-05-27T12:00:00.000Z"
    });

    const rows = await listSourceHealth(db);
    expect(rows.map((row) => row.source)).toEqual(["aws_cloudtrail", "kubernetes_audit"]);
  });

  it("filters by tenant_id", async () => {
    const db = new FakeAlertDb();
    await recordIngestBatch(db, {
      source: "aws_cloudtrail",
      tenant_id: "t1",
      event_count: 1,
      last_event_at: "2026-05-27T12:00:00.000Z"
    });
    await recordIngestBatch(db, {
      source: "aws_cloudtrail",
      tenant_id: "t2",
      event_count: 1,
      last_event_at: "2026-05-27T12:00:00.000Z"
    });

    const t1 = await listSourceHealth(db, { tenant_id: "t1" });
    expect(t1).toHaveLength(1);
    expect(t1[0]?.tenant_id).toBe("t1");
  });

  it("returns null for an unknown source", async () => {
    const db = new FakeAlertDb();
    const row = await getSourceHealth(db, "missing");
    expect(row).toBeNull();
  });
});

describe("classifySourceHealth / formatSourceHealthTable", () => {
  const now = new Date("2026-05-27T12:10:00.000Z");

  it("marks unknown when last_event_at is null", () => {
    expect(classifySourceHealth({ source: "aws_cloudtrail", last_event_at: null }, now)).toBe(
      "unknown"
    );
  });

  it("marks healthy when within the source freshness window", () => {
    expect(
      classifySourceHealth(
        { source: "aws_cloudtrail", last_event_at: "2026-05-27T12:05:00.000Z" }, // 5min ago, 10min window
        now
      )
    ).toBe("healthy");
  });

  it("marks stale when past the source freshness window", () => {
    expect(
      classifySourceHealth(
        { source: "kubernetes_audit", last_event_at: "2026-05-27T12:00:00.000Z" }, // 10min ago, 5min window
        now
      )
    ).toBe("stale");
  });

  it("uses a 15 minute default window for unknown sources", () => {
    expect(freshnessWindowMs("unknown-source")).toBe(15 * 60_000);
  });

  it("renders a table containing each source and status column", () => {
    const out = formatSourceHealthTable(
      [
        {
          source: "aws_cloudtrail",
          tenant_id: "tenant-a",
          last_event_at: "2026-05-27T12:05:00.000Z",
          last_event_count: 1,
          total_events: 5,
          total_batches: 3,
          total_errors: 0,
          last_error_at: null,
          last_error_message: null,
          updated_at: "2026-05-27T12:05:00.000Z"
        }
      ],
      { now }
    );
    expect(out).toContain("source");
    expect(out).toContain("aws_cloudtrail");
    expect(out).toContain("healthy");
    expect(out).toContain("tenant-a");
    expect(out).toContain("2026-05-27T12:05:00.000Z");
  });

  it("returns 'No sources reporting.' on an empty list", () => {
    expect(formatSourceHealthTable([], { now })).toBe("No sources reporting.");
  });
});
