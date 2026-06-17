import { describe, expect, it } from "vitest";

import type { Alert } from "@picket/core";
import type { R2SqlExecutor, R2SqlResult, R2SqlRow } from "@picket/query";
import type { SigmaRule } from "@picket/sigma-engine";

import { createScheduledRunner, type ScheduledDetectionEnv } from "./index";

// --- A minimal in-memory D1 covering exactly the statements the worker issues:
// detection_rules (seed + disabled list + match bump), scheduled_detection_state
// (read + upsert), alerts (dedup read + insert + update), alert_timeline insert.
interface AlertRow {
  id: string;
  rule_id: string;
  dedupe_key: string | null;
  match_count: number;
  first_seen: string;
  last_seen: string;
  status: string;
}
interface StateRow {
  rule_id: string;
  last_run_at: string | null;
  last_status: string | null;
  last_row_count: number | null;
  last_alert_count: number | null;
  last_error: string | null;
}
interface RegRule {
  id: string;
  enabled: number;
  match_count: number;
}

class FakeD1 {
  alerts: AlertRow[] = [];
  timeline: { alert_id: string; action: string }[] = [];
  state: StateRow[] = [];
  rules: RegRule[] = [];
  disabledIds = new Set<string>();
  database = { prepare: (q: string) => new Stmt(this, q) } as unknown as D1Database;
}

class Stmt {
  private params: unknown[] = [];
  constructor(private readonly db: FakeD1, private readonly q: string) {}
  bind(...p: unknown[]) {
    this.params = p;
    return this;
  }
  private n() {
    return this.q.trim().replace(/\s+/g, " ");
  }
  async all<T = unknown>(): Promise<{ results: T[] }> {
    const q = this.n();
    if (q.startsWith("SELECT id FROM detection_rules WHERE enabled = 0")) {
      return { results: [...this.db.disabledIds].map((id) => ({ id })) as unknown as T[] };
    }
    return { results: [] };
  }
  async first<T = unknown>(): Promise<T | null> {
    const q = this.n();
    if (q.startsWith("SELECT id, match_count, first_seen FROM alerts")) {
      const [ruleId, dedupeKey, cutoff] = this.params as [string, string, string];
      const row = this.db.alerts
        .filter(
          (a) =>
            a.rule_id === ruleId &&
            a.dedupe_key === dedupeKey &&
            (a.status === "open" || a.status === "acknowledged") &&
            a.last_seen >= cutoff
        )
        .sort((l, r) => r.last_seen.localeCompare(l.last_seen))[0];
      return row ? ({ id: row.id, match_count: row.match_count, first_seen: row.first_seen } as T) : null;
    }
    if (q.startsWith("SELECT rule_id, last_run_at, last_status, last_row_count, last_alert_count, last_error, updated_at FROM scheduled_detection_state WHERE rule_id = ?")) {
      const [ruleId] = this.params as [string];
      const row = this.db.state.find((s) => s.rule_id === ruleId);
      return (row ? { ...row, updated_at: row.last_run_at } : null) as T | null;
    }
    return null;
  }
  async run(): Promise<D1Result> {
    const q = this.n();
    if (q.startsWith("INSERT INTO alerts")) {
      const [id, rule_id, , , , status, dedupe_key, match_count, first_seen, last_seen] = this.params as [
        string, string, string, string, string, string, string | null, number, string, string
      ];
      this.db.alerts.push({ id, rule_id, dedupe_key, match_count, first_seen, last_seen, status });
    } else if (q.startsWith("UPDATE alerts SET")) {
      const [matchCount, lastSeen, , , id] = this.params as [number, string, string, string, string];
      const row = this.db.alerts.find((a) => a.id === id);
      if (row) {
        row.match_count = matchCount;
        row.last_seen = lastSeen;
      }
    } else if (q.startsWith("INSERT INTO alert_timeline")) {
      const [, alert_id, action] = this.params as [string, string, string];
      this.db.timeline.push({ alert_id, action });
    } else if (q.startsWith("INSERT INTO detection_rules")) {
      const id = this.params[0] as string;
      const enabled = this.params[8] as number;
      if (!this.db.rules.find((r) => r.id === id)) this.db.rules.push({ id, enabled, match_count: 0 });
    } else if (q.startsWith("UPDATE detection_rules SET match_count = match_count + 1")) {
      const id = this.params[2] as string;
      const row = this.db.rules.find((r) => r.id === id);
      if (row) row.match_count += 1;
    } else if (q.startsWith("INSERT INTO scheduled_detection_state")) {
      const [rule_id, last_run_at, last_status, last_row_count, last_alert_count, last_error] = this.params as [
        string, string, string, number | null, number | null, string | null
      ];
      const existing = this.db.state.find((s) => s.rule_id === rule_id);
      const next = { rule_id, last_run_at, last_status, last_row_count, last_alert_count, last_error };
      if (existing) Object.assign(existing, next);
      else this.db.state.push(next);
    }
    return { success: true, meta: {} } as D1Result;
  }
}

function fakeExecutor(rows: R2SqlRow[]): R2SqlExecutor {
  const result: R2SqlResult = { columns: rows[0] ? Object.keys(rows[0]) : [], rows };
  return { execute: async () => result };
}

const SPIKE_RULE: SigmaRule = {
  id: "sql-spike",
  title: "Privilege spike",
  description: "d",
  severity: "high",
  tags: [],
  enabled: true,
  execution: "sql",
  logsource: { source: "aws_cloudtrail", class_name: "api_activity" },
  dedupe_prefix: "spike",
  sql: {
    query: "SELECT actor_user_uid, COUNT(*) AS n FROM aws_cloudtrail GROUP BY actor_user_uid",
    interval: "15m",
    threshold: 5,
    count_field: "n",
    group_by: "actor_user_uid"
  }
};

function baseEnv(db: FakeD1, overrides: Partial<ScheduledDetectionEnv> = {}): ScheduledDetectionEnv {
  const sent: Alert[] = [];
  const piped: Record<string, unknown>[][] = [];
  return {
    ALERT_STATE_DB: db.database,
    R2_SQL_TOKEN: "tok",
    PICKET_R2_WAREHOUSE: "acct_picket-lake",
    PICKET_TABLE_SUFFIX: "pure_alien",
    ALERT_QUEUE: { send: async (a: Alert) => void sent.push(a), sentRef: sent } as unknown as Queue<Alert>,
    ALERTS_PIPELINE: { send: async (r: Record<string, unknown>[]) => void piped.push(r) },
    ...overrides
  };
}

const NOW = new Date("2026-05-27T12:30:00.000Z");

function runner(rows: R2SqlRow[], rules: SigmaRule[] = [SPIKE_RULE]) {
  let n = 0;
  return createScheduledRunner({
    now: () => NOW,
    uuid: () => `alert-${++n}`,
    executorFactory: () => fakeExecutor(rows),
    rules
  });
}

describe("scheduled-detection worker", () => {
  it("fires one alert per row over threshold and records an ok run", async () => {
    const db = new FakeD1();
    const results = await runner([
      { actor_user_uid: "u1", n: 8 },
      { actor_user_uid: "u2", n: 6 },
      { actor_user_uid: "u3", n: 2 } // below threshold 5 → filtered
    ]).runDueRules(baseEnv(db));

    expect(results).toEqual([
      { rule_id: "sql-spike", status: "ok", row_count: 3, alert_count: 2 }
    ]);
    expect(db.alerts.map((a) => a.dedupe_key)).toEqual(["spike:u1", "spike:u2"]);
    expect(db.alerts.every((a) => a.rule_id === "sql-spike" && a.status === "open")).toBe(true);
    expect(db.timeline.map((t) => t.action)).toEqual(["created", "created"]);
    expect(db.state[0]).toMatchObject({ rule_id: "sql-spike", last_status: "ok", last_row_count: 3, last_alert_count: 2 });
    expect(db.rules.find((r) => r.id === "sql-spike")?.match_count).toBe(1);
  });

  it("dedupes a repeat firing for the same group within the window", async () => {
    const db = new FakeD1();
    const r = runner([{ actor_user_uid: "u1", n: 8 }]);
    await r.runDueRules(baseEnv(db));
    // Second run, same group, inside the dedupe window → folds into existing alert.
    db.state = []; // force "due" again
    await r.runDueRules(baseEnv(db));

    expect(db.alerts).toHaveLength(1);
    expect(db.alerts[0]?.match_count).toBe(2);
    expect(db.timeline.map((t) => t.action)).toEqual(["created", "matched"]);
  });

  it("skips a rule that is not yet due", async () => {
    const db = new FakeD1();
    db.state.push({
      rule_id: "sql-spike",
      last_run_at: "2026-05-27T12:20:00.000Z", // 10m before NOW, interval 15m → not due
      last_status: "ok",
      last_row_count: 0,
      last_alert_count: 0,
      last_error: null
    });
    const results = await runner([{ actor_user_uid: "u1", n: 8 }]).runDueRules(baseEnv(db));
    expect(results).toEqual([]);
    expect(db.alerts).toHaveLength(0);
  });

  it("skips a disabled rule", async () => {
    const db = new FakeD1();
    db.disabledIds.add("sql-spike");
    const results = await runner([{ actor_user_uid: "u1", n: 8 }]).runDueRules(baseEnv(db));
    expect(results).toEqual([]);
    expect(db.alerts).toHaveLength(0);
  });

  it("records an error run when the warehouse is missing", async () => {
    const db = new FakeD1();
    const env = baseEnv(db, { PICKET_R2_WAREHOUSE: undefined });
    const results = await runner([{ actor_user_uid: "u1", n: 8 }]).runDueRules(env);
    expect(results[0]?.status).toBe("error");
    expect(db.state[0]?.last_status).toBe("error");
    expect(db.alerts).toHaveLength(0);
  });

  it("seeds SQL rules into the detection_rules registry", async () => {
    const db = new FakeD1();
    await runner([]).runDueRules(baseEnv(db));
    expect(db.rules.map((r) => r.id)).toContain("sql-spike");
  });

  it("keeps every returned row when no count_field is set", async () => {
    const db = new FakeD1();
    const noThreshold: SigmaRule = {
      ...SPIKE_RULE,
      id: "sql-all",
      sql: { query: "SELECT actor_user_uid FROM aws_cloudtrail", interval: "15m", group_by: "actor_user_uid" }
    };
    const results = await runner(
      [{ actor_user_uid: "a" }, { actor_user_uid: "b" }],
      [noThreshold]
    ).runDueRules(baseEnv(db));
    expect(results[0]).toMatchObject({ status: "ok", row_count: 2, alert_count: 2 });
  });
});
