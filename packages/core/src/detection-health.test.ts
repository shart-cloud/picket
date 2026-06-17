import { describe, expect, it } from "vitest";

import { FakeAlertDb } from "./alerts-fake-db.js";
import {
  classifyDetectionHealth,
  formatDetectionHealth,
  getDetectionHealth,
  recordDetectionEval
} from "./detection-health.js";

describe("recordDetectionEval", () => {
  it("creates the singleton row on first eval", async () => {
    const db = new FakeAlertDb();
    await recordDetectionEval(db, {
      events_evaluated: 1,
      alerts_created: 2,
      stateless_rule_count: 4,
      stateful_rule_count: 1
    });

    const health = await getDetectionHealth(db);
    expect(health?.total_events_evaluated).toBe(1);
    expect(health?.total_alerts_created).toBe(2);
    expect(health?.stateless_rule_count).toBe(4);
    expect(health?.stateful_rule_count).toBe(1);
    expect(health?.last_eval_at).toBeTruthy();
  });

  it("accumulates counters across evals and refreshes rule counts", async () => {
    const db = new FakeAlertDb();
    await recordDetectionEval(db, { events_evaluated: 1, alerts_created: 0, stateless_rule_count: 4, stateful_rule_count: 1 });
    await recordDetectionEval(db, { events_evaluated: 1, alerts_created: 1, stateless_rule_count: 5, stateful_rule_count: 2 });

    const health = await getDetectionHealth(db);
    expect(health?.total_events_evaluated).toBe(2);
    expect(health?.total_alerts_created).toBe(1);
    // rule counts reflect the latest bundle, not a sum
    expect(health?.stateless_rule_count).toBe(5);
    expect(health?.stateful_rule_count).toBe(2);
  });
});

describe("getDetectionHealth", () => {
  it("returns null when the engine has never evaluated", async () => {
    expect(await getDetectionHealth(new FakeAlertDb())).toBeNull();
  });
});

describe("classifyDetectionHealth", () => {
  const now = new Date("2026-05-27T12:10:00.000Z");

  it("is unknown with no row or no timestamp", () => {
    expect(classifyDetectionHealth(null, now)).toBe("unknown");
    expect(classifyDetectionHealth({ last_eval_at: null }, now)).toBe("unknown");
  });

  it("is healthy within the freshness window and stale beyond it", () => {
    expect(classifyDetectionHealth({ last_eval_at: "2026-05-27T12:08:00.000Z" }, now)).toBe("healthy");
    expect(classifyDetectionHealth({ last_eval_at: "2026-05-27T11:50:00.000Z" }, now)).toBe("stale");
  });
});

describe("formatDetectionHealth", () => {
  const now = new Date("2026-05-27T12:10:00.000Z");

  it("notes when nothing has been evaluated", () => {
    expect(formatDetectionHealth(null, { now })).toContain("no evaluations recorded yet");
  });

  it("summarizes rules and counters", () => {
    const out = formatDetectionHealth(
      {
        last_eval_at: "2026-05-27T12:09:00.000Z",
        total_events_evaluated: 10,
        total_alerts_created: 3,
        stateless_rule_count: 4,
        stateful_rule_count: 1,
        updated_at: "2026-05-27T12:09:00.000Z"
      },
      { now }
    );
    expect(out).toContain("Detection engine: healthy");
    expect(out).toContain("rules:            5 (4 stateless, 1 stateful)");
    expect(out).toContain("events_evaluated: 10");
    expect(out).toContain("alerts_created:   3");
  });
});
