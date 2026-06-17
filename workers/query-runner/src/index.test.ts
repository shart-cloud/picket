import { describe, expect, it } from "vitest";

import type { R2SqlExecutor, R2SqlResult } from "@picket/query";

import { createRunner, type QueryRunnerEnv } from "./index";

// Minimal D1-shape stub for the few operations the runner uses against
// query_jobs. Backed by an in-memory row map.
class FakeQueryJobsDb {
  rows = new Map<string, Record<string, unknown>>();

  prepare(sql: string): FakeStatement {
    return new FakeStatement(this, sql, []);
  }

  asDb(): D1Database {
    return this as unknown as D1Database;
  }
}

class FakeStatement {
  constructor(
    private db: FakeQueryJobsDb,
    private sql: string,
    private params: unknown[]
  ) {}

  bind(...params: unknown[]): FakeStatement {
    return new FakeStatement(this.db, this.sql, params);
  }

  async first<T>(): Promise<T | null> {
    const s = this.sql.toUpperCase();
    if (s.includes("SELECT * FROM QUERY_JOBS WHERE ID")) {
      return (this.db.rows.get(this.params[0] as string) ?? null) as T | null;
    }
    throw new Error(`unhandled first() sql: ${this.sql}`);
  }

  async run() {
    const s = this.sql.toUpperCase();
    if (s.includes("UPDATE QUERY_JOBS")) {
      const id = this.params[this.params.length - 1] as string;
      const row = this.db.rows.get(id);
      if (!row) return { meta: { changes: 0 } };
      const setMatch = this.sql.match(/SET\s+([\s\S]*?)\s+WHERE/i);
      if (setMatch && setMatch[1]) {
        const assignments = setMatch[1].split(",").map((a) => a.trim());
        let paramIdx = 0;
        for (const assignment of assignments) {
          const eq = assignment.indexOf("=");
          const col = assignment.slice(0, eq).trim();
          const rhs = assignment.slice(eq + 1).trim();
          if (rhs === "?") {
            row[col] = this.params[paramIdx++];
          } else {
            // Strip surrounding quotes if a string literal like 'succeeded'.
            row[col] = rhs.replace(/^'(.*)'$/, "$1");
          }
        }
      }
      return { meta: { changes: 1 } };
    }
    throw new Error(`unhandled run() sql: ${this.sql}`);
  }
}

class FakeExecutor implements R2SqlExecutor {
  public calls: string[] = [];
  constructor(private result: R2SqlResult | (() => Promise<R2SqlResult>)) {}
  async execute(sql: string): Promise<R2SqlResult> {
    this.calls.push(sql);
    return typeof this.result === "function" ? this.result() : this.result;
  }
}

function seed(db: FakeQueryJobsDb, id: string): void {
  db.rows.set(id, {
    id,
    idempotency_key: null,
    status: "pending",
    sql: "SELECT 1",
    warehouse: "acct_picket-lake",
    requested_by: "tester@example.com",
    tenant_id: null,
    preset: null,
    table_suffix: null,
    created_at: "2026-05-27T11:00:00.000Z",
    started_at: null,
    finished_at: null,
    result_json: null,
    error_message: null,
    bytes_scanned: null,
    files_scanned: null,
    row_count: null
  });
}

function buildEnv(db: FakeQueryJobsDb): QueryRunnerEnv {
  return {
    ALERT_STATE_DB: db.asDb(),
    R2_SQL_TOKEN: "test-token"
  };
}

describe("picket-query-runner", () => {
  it("runs a pending job and marks it succeeded", async () => {
    const db = new FakeQueryJobsDb();
    seed(db, "job-1");
    const executor = new FakeExecutor({
      columns: ["x"],
      rows: [{ x: 1 }, { x: 2 }]
    });
    const runner = createRunner({ executorFactory: () => executor });

    await runner.processOne(buildEnv(db), "job-1");

    const row = db.rows.get("job-1")!;
    expect(row.status).toBe("succeeded");
    expect(row.row_count).toBe(2);
    expect(typeof row.result_json).toBe("string");
    expect(JSON.parse(row.result_json as string).rows).toEqual([{ x: 1 }, { x: 2 }]);
    expect(executor.calls).toEqual(["SELECT 1"]);
  });

  it("marks job failed when the executor throws", async () => {
    const db = new FakeQueryJobsDb();
    seed(db, "job-2");
    const executor: R2SqlExecutor = {
      async execute() {
        throw new Error("R2 SQL boom");
      }
    };
    const runner = createRunner({ executorFactory: () => executor });

    await runner.processOne(buildEnv(db), "job-2");

    const row = db.rows.get("job-2")!;
    expect(row.status).toBe("failed");
    expect(row.error_message).toContain("R2 SQL boom");
  });

  it("skips a job that's no longer pending (queue redelivery)", async () => {
    const db = new FakeQueryJobsDb();
    seed(db, "job-3");
    db.rows.get("job-3")!.status = "succeeded";
    const executor = new FakeExecutor({ columns: [], rows: [] });
    const runner = createRunner({ executorFactory: () => executor });

    await runner.processOne(buildEnv(db), "job-3");
    expect(executor.calls).toHaveLength(0);
  });
});
