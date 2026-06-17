import { describe, expect, it } from "vitest";

import {
  formatQueryHistoryTable,
  formatSavedQueriesTable,
  listQueryHistory,
  listSavedQueries,
  recordQueryHistory,
  saveQuery,
  SavedQueryNameRequiredError
} from "./saved-queries.js";
import { FakeAlertDb } from "./alerts-fake-db.js";

describe("saved queries", () => {
  it("saves and lists a query", async () => {
    const db = new FakeAlertDb();
    const saved = await saveQuery(db, {
      id: "sq-1",
      owner: "alice@example.com",
      name: "failed logins",
      description: "recent failures",
      sql: "SELECT * FROM aws_cloudtrail WHERE time > now() - interval '1' hour",
      preset: null
    });
    expect(saved.id).toBe("sq-1");
    expect(saved.name).toBe("failed logins");

    const rows = await listSavedQueries(db, {});
    expect(rows.map((row) => row.name)).toEqual(["failed logins"]);
  });

  it("upserts by owner+name, preserving the original id and created_at", async () => {
    const db = new FakeAlertDb();
    const first = await saveQuery(db, { id: "sq-1", owner: "alice", name: "q", sql: "SELECT 1" });
    const second = await saveQuery(db, { id: "sq-2", owner: "alice", name: "q", sql: "SELECT 2" });

    expect(second.id).toBe("sq-1"); // original id preserved
    expect(second.created_at).toBe(first.created_at);
    expect(second.sql).toBe("SELECT 2");
    expect(await listSavedQueries(db, {})).toHaveLength(1);
  });

  it("scopes a different owner's same-named query separately", async () => {
    const db = new FakeAlertDb();
    await saveQuery(db, { id: "sq-1", owner: "alice", name: "q", sql: "SELECT 1" });
    await saveQuery(db, { id: "sq-2", owner: "bob", name: "q", sql: "SELECT 2" });

    expect(await listSavedQueries(db, { owner: "alice" })).toHaveLength(1);
    expect((await listSavedQueries(db, { owner: "bob" }))[0]?.sql).toBe("SELECT 2");
    expect(await listSavedQueries(db, {})).toHaveLength(2);
  });

  it("rejects an empty name", async () => {
    const db = new FakeAlertDb();
    await expect(saveQuery(db, { id: "x", owner: "a", name: "  ", sql: "SELECT 1" })).rejects.toBeInstanceOf(
      SavedQueryNameRequiredError
    );
  });

  it("records a history row", async () => {
    const db = new FakeAlertDb();
    await recordQueryHistory(db, { id: "h1", owner: "alice", sql: "SELECT 1", preset: "iam-changes", job_id: "j1" });

    const rows = await listQueryHistory(db, {});
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ id: "h1", owner: "alice", preset: "iam-changes", job_id: "j1" });
  });

  it("lists history newest-first by created_at", async () => {
    const db = new FakeAlertDb();
    // Explicit timestamps: recordQueryHistory stamps real time, which can tie
    // within a millisecond, so seed the rows directly to assert ordering.
    db.queryHistory.push(
      { id: "h1", owner: "alice", sql: "SELECT 1", preset: null, job_id: "j1", created_at: "2026-05-27T10:00:00.000Z" },
      { id: "h2", owner: "alice", sql: "SELECT 2", preset: null, job_id: "j2", created_at: "2026-05-27T11:00:00.000Z" }
    );

    const rows = await listQueryHistory(db, {});
    expect(rows.map((row) => row.id)).toEqual(["h2", "h1"]);
  });

  it("renders saved + history tables", async () => {
    const db = new FakeAlertDb();
    await saveQuery(db, { id: "sq-1", owner: "alice", name: "q", sql: "SELECT 1" });
    await recordQueryHistory(db, { id: "h1", owner: "alice", sql: "SELECT 1", job_id: "j1" });

    expect(formatSavedQueriesTable(await listSavedQueries(db, {}))).toContain("q");
    expect(formatQueryHistoryTable(await listQueryHistory(db, {}))).toContain("j1");
    expect(formatSavedQueriesTable([])).toBe("No saved queries.");
    expect(formatQueryHistoryTable([])).toBe("No query history.");
  });
});
