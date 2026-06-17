import { describe, expect, it } from "vitest";
import { Hono } from "hono";
import type { MiddlewareHandler } from "hono";
import { apiKeyAuth, type PicketAuth } from "@picket/api";

import { FakeAlertDb, type FakeAlertRow, type FakeDetectionRuleRow } from "@picket/core/alerts-fake-db";

import { createAdminApp, type AdminEnv } from "./index";

function stubAccess(user: { email?: string; sub?: string } = { email: "access@example.com" }): MiddlewareHandler {
  return async (c, next) => {
    c.set("accessUser", user);
    await next();
  };
}

interface StubSession {
  id: string;
  email?: string;
  name?: string;
}

function stubSession(user: StubSession | null = { id: "user-1", email: "analyst@example.com" }): MiddlewareHandler<{ Bindings: AdminEnv }> {
  return async (c, next) => {
    if (!user) return c.json({ error: "Not authenticated" }, 401);
    c.set("sessionUser", user);
    await next();
  };
}

function withAuth(opts: { session?: StubSession | null } = {}): {
  accessMiddleware: () => MiddlewareHandler;
  sessionMiddleware: MiddlewareHandler<{ Bindings: AdminEnv }>;
} {
  return {
    accessMiddleware: () => stubAccess(),
    sessionMiddleware: stubSession(opts.session === undefined ? { id: "user-1", email: "analyst@example.com" } : opts.session)
  };
}

function seed(overrides: Partial<FakeAlertRow> & { id: string }): FakeAlertRow {
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

function buildEnv(db: FakeAlertDb): AdminEnv {
  return {
    AUTH_DB: {} as D1Database,
    ALERT_STATE_DB: db as unknown as D1Database,
    BETTER_AUTH_SECRET: "test-secret",
    CF_ACCESS_TEAM_DOMAIN: "test.cloudflareaccess.com",
    CF_ACCESS_AUD: "test-aud"
  };
}

interface ApiKeyRow {
  id: string;
  configId: string;
  name: string;
  start: string | null;
  referenceId: string;
  prefix: string | null;
  key: string;
  refillInterval: number | null;
  refillAmount: number | null;
  lastRefillAt: string | null;
  enabled: number;
  rateLimitEnabled: number;
  rateLimitTimeWindow: number;
  rateLimitMax: number;
  requestCount: number;
  remaining: number | null;
  lastRequest: string | null;
  expiresAt: string | null;
  createdAt: string;
  updatedAt: string;
  permissions: string | null;
  metadata: string;
}

function apiKeyDb(): { db: D1Database; rows: ApiKeyRow[] } {
  const rows: ApiKeyRow[] = [];
  const db = {
    prepare: () => ({
      bind: (...values: unknown[]) => ({
        run: async () => {
          rows.push({
            id: valueAt<string>(values, 0),
            configId: valueAt<string>(values, 1),
            name: valueAt<string>(values, 2),
            start: nullableValueAt<string>(values, 3),
            referenceId: valueAt<string>(values, 4),
            prefix: nullableValueAt<string>(values, 5),
            key: valueAt<string>(values, 6),
            refillInterval: nullableValueAt<number>(values, 7),
            refillAmount: nullableValueAt<number>(values, 8),
            lastRefillAt: nullableValueAt<string>(values, 9),
            enabled: valueAt<number>(values, 10),
            rateLimitEnabled: valueAt<number>(values, 11),
            rateLimitTimeWindow: valueAt<number>(values, 12),
            rateLimitMax: valueAt<number>(values, 13),
            requestCount: valueAt<number>(values, 14),
            remaining: nullableValueAt<number>(values, 15),
            lastRequest: nullableValueAt<string>(values, 16),
            expiresAt: nullableValueAt<string>(values, 17),
            createdAt: valueAt<string>(values, 18),
            updatedAt: valueAt<string>(values, 19),
            permissions: nullableValueAt<string>(values, 20),
            metadata: valueAt<string>(values, 21)
          });
          return { success: true };
        }
      })
    })
  } as unknown as D1Database;
  return { db, rows };
}

function valueAt<T>(values: unknown[], index: number): T {
  const value = values[index];
  if (value === null || value === undefined) throw new Error(`missing bind value ${index}`);
  return value as T;
}

function nullableValueAt<T>(values: unknown[], index: number): T | null {
  const value = values[index];
  return value === null || value === undefined ? null : (value as T);
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function authBackedByRows(rows: ApiKeyRow[]): PicketAuth {
  return {
    api: {
      verifyApiKey: async ({ body }: { body: { key: string } }) => {
        const hashed = await sha256Base64Url(body.key);
        const row = rows.find((candidate) => candidate.key === hashed && candidate.enabled === 1);
        if (!row) return { valid: false, key: null };
        return {
          valid: true,
          key: {
            id: row.id,
            referenceId: row.referenceId,
            metadata: JSON.parse(row.metadata) as Record<string, unknown>
          }
        };
      },
      getSession: async () => null,
      createApiKey: async () => {
        throw new Error("not used");
      }
    },
    handler: async () => new Response(null, { status: 404 }),
    findOrCreateUserByEmail: async () => {
      throw new Error("not used");
    },
    decideDeviceCode: async () => {
      throw new Error("not used");
    }
  };
}

describe("admin worker alerts API", () => {
  it("rejects requests with no Cloudflare Access token", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp();

    const response = await app.request("/api/v1/alerts", {}, buildEnv(db));

    expect(response.status).toBe(401);
  });

  it("rejects requests that pass Access but have no better-auth session", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp({
      accessMiddleware: () => stubAccess(),
      sessionMiddleware: stubSession(null)
    });

    const response = await app.request("/api/v1/alerts", {}, buildEnv(db));

    expect(response.status).toBe(401);
  });

  it("lists alerts behind the auth middleware", async () => {
    const db = new FakeAlertDb([
      seed({ id: "alert-a", updated_at: "2026-05-26T11:00:00.000Z" }),
      seed({ id: "alert-b", severity: "low", updated_at: "2026-05-26T12:00:00.000Z" })
    ]);
    const app = createAdminApp(withAuth());

    const response = await app.request("/api/v1/alerts", {}, buildEnv(db));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { alerts: { id: string }[] };
    expect(body.alerts.map((alert) => alert.id)).toEqual(["alert-b", "alert-a"]);
  });

  it("aggregates alert stats behind the auth middleware", async () => {
    const db = new FakeAlertDb([
      seed({ id: "a", severity: "high", status: "open", rule_id: "r1", source: "aws_cloudtrail" }),
      seed({ id: "b", severity: "low", status: "resolved", rule_id: "r2", source: "kubernetes_audit" })
    ]);
    const app = createAdminApp(withAuth());

    const response = await app.request("/api/v1/alerts/stats", {}, buildEnv(db));
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      stats: {
        total: number;
        by_severity: { key: string; count: number }[];
        by_source: { key: string; count: number }[];
      };
    };
    expect(body.stats.total).toBe(2);
    expect(body.stats.by_severity).toContainEqual({ key: "high", count: 1 });
    expect(body.stats.by_source.map((entry) => entry.key)).toContain("kubernetes_audit");
  });

  it("does not treat `stats` as an alert id", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp(withAuth());

    const response = await app.request("/api/v1/alerts/stats", {}, buildEnv(db));
    // The :id route would 404; stats returns 200 with an empty aggregate.
    expect(response.status).toBe(200);
    const body = (await response.json()) as { stats: { total: number } };
    expect(body.stats.total).toBe(0);
  });

  it("filters alerts via status, severity, rule, source, and time query params", async () => {
    const db = new FakeAlertDb([
      seed({ id: "open-high", severity: "high", status: "open", rule_id: "r1", source: "aws_cloudtrail", first_seen: "2026-05-26T10:00:00.000Z", last_seen: "2026-05-26T10:10:00.000Z" }),
      seed({ id: "ack-high", severity: "high", status: "acknowledged", rule_id: "r1", source: "aws_cloudtrail", first_seen: "2026-05-26T10:00:00.000Z", last_seen: "2026-05-26T10:10:00.000Z" }),
      seed({ id: "open-low", severity: "low", status: "open", rule_id: "r2", source: "kubernetes_audit", first_seen: "2026-05-26T12:00:00.000Z", last_seen: "2026-05-26T12:10:00.000Z" })
    ]);
    const app = createAdminApp(withAuth());

    const response = await app.request(
      "/api/v1/alerts?status=open&severity=high&rule_id=r1&source=aws_cloudtrail&start_time=2026-05-26T10:05:00.000Z&end_time=2026-05-26T10:15:00.000Z",
      {},
      buildEnv(db)
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { alerts: { id: string }[] };
    expect(body.alerts.map((alert) => alert.id)).toEqual(["open-high"]);
  });

  it("sorts and paginates alerts while returning the filtered total", async () => {
    const db = new FakeAlertDb([
      seed({ id: "low", severity: "low" }),
      seed({ id: "critical", severity: "critical" }),
      seed({ id: "medium", severity: "medium" })
    ]);
    const app = createAdminApp(withAuth());

    const response = await app.request(
      "/api/v1/alerts?sort=severity&direction=desc&limit=1&offset=1",
      {},
      buildEnv(db)
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { alerts: { id: string }[]; total: number; limit: number; offset: number };
    expect(body).toMatchObject({ total: 3, limit: 1, offset: 1 });
    expect(body.alerts.map((alert) => alert.id)).toEqual(["medium"]);
  });

  it("rejects invalid alert time filters with 400", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp(withAuth());

    const response = await app.request("/api/v1/alerts?from=not-a-date", {}, buildEnv(db));
    expect(response.status).toBe(400);
  });

  it("rejects invalid status values with 400", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp(withAuth());

    const response = await app.request("/api/v1/alerts?status=bogus", {}, buildEnv(db));
    expect(response.status).toBe(400);
  });

  it("rejects non-positive limit with 400", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp(withAuth());

    const response = await app.request("/api/v1/alerts?limit=0", {}, buildEnv(db));
    expect(response.status).toBe(400);
  });

  it("bulk acknowledges selected alerts with audited actor identity", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1" }), seed({ id: "alert-2" })]);
    const app = createAdminApp(withAuth({ session: { id: "user-1", email: "analyst@example.com" } }));

    const response = await app.request(
      "/api/v1/alerts/bulk",
      {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ids: ["alert-1", "alert-2"], status: "acknowledged" })
      },
      buildEnv(db)
    );

    expect(response.status).toBe(200);
    const body = (await response.json()) as { alerts: { status: string }[]; updated_by: string };
    expect(body.updated_by).toBe("analyst@example.com");
    expect(body.alerts.every((alert) => alert.status === "acknowledged")).toBe(true);
    expect(db.timeline.filter((entry) => entry.action === "acknowledged")).toHaveLength(2);
  });

  it("rejects a bulk mutation before updating when an alert is missing", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1" })]);
    const app = createAdminApp(withAuth());

    const response = await app.request(
      "/api/v1/alerts/bulk",
      {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ids: ["alert-1", "missing"], status: "resolved" })
      },
      buildEnv(db)
    );

    expect(response.status).toBe(404);
    expect(db.alerts[0]?.status).toBe("open");
    expect(db.timeline).toHaveLength(0);
  });

  it("returns alert detail with timeline and notes", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1" })]);
    const app = createAdminApp(withAuth());

    const response = await app.request("/api/v1/alerts/alert-1", {}, buildEnv(db));
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      alert: { id: string };
      timeline: unknown[];
      notes: unknown[];
    };
    expect(body.alert.id).toBe("alert-1");
    expect(Array.isArray(body.timeline)).toBe(true);
    expect(Array.isArray(body.notes)).toBe(true);
  });

  it("returns 404 for a missing alert id", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp(withAuth());

    const response = await app.request("/api/v1/alerts/missing", {}, buildEnv(db));
    expect(response.status).toBe(404);
  });

  it("acknowledges an alert using the better-auth session email as the default actor", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1" })]);
    const app = createAdminApp(withAuth({ session: { id: "user-1", email: "alice@example.com" } }));

    const response = await app.request(
      "/api/v1/alerts/alert-1/ack",
      { method: "POST" },
      buildEnv(db)
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { acknowledged_by: string; alert: { status: string } };
    expect(body.acknowledged_by).toBe("alice@example.com");
    expect(body.alert.status).toBe("acknowledged");

    const row = db.alerts.find((alert) => alert.id === "alert-1");
    expect(row?.acknowledged_by).toBe("alice@example.com");
    expect(db.timeline).toHaveLength(1);
    expect(db.timeline[0]?.action).toBe("acknowledged");
    expect(db.timeline[0]?.actor).toBe("alice@example.com");
  });

  it("honors an explicit { by } override on ack", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1" })]);
    const app = createAdminApp(withAuth({ session: { id: "user-1", email: "alice@example.com" } }));

    const response = await app.request(
      "/api/v1/alerts/alert-1/ack",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ by: "oncall-bot" })
      },
      buildEnv(db)
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { acknowledged_by: string };
    expect(body.acknowledged_by).toBe("oncall-bot");
    expect(db.alerts[0]?.acknowledged_by).toBe("oncall-bot");
  });

  it("resolves an alert and writes a resolved timeline entry", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1" })]);
    const app = createAdminApp(withAuth({ session: { id: "user-2", email: "bob@example.com" } }));

    const response = await app.request(
      "/api/v1/alerts/alert-1/resolve",
      { method: "POST" },
      buildEnv(db)
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { resolved_by: string; alert: { status: string } };
    expect(body.resolved_by).toBe("bob@example.com");
    expect(body.alert.status).toBe("resolved");
    expect(db.timeline.find((entry) => entry.action === "resolved")).toBeDefined();
  });

  it("returns 404 when acknowledging a missing alert", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp(withAuth());

    const response = await app.request("/api/v1/alerts/missing/ack", { method: "POST" }, buildEnv(db));
    expect(response.status).toBe(404);
  });

  it("returns 404 when resolving a missing alert", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp(withAuth());

    const response = await app.request("/api/v1/alerts/missing/resolve", { method: "POST" }, buildEnv(db));
    expect(response.status).toBe(404);
  });

  it("adds a note to an alert and surfaces it on the detail endpoint", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1" })]);
    const app = createAdminApp(withAuth({ session: { id: "user-1", email: "alice@example.com" } }));

    const response = await app.request(
      "/api/v1/alerts/alert-1/notes",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ body: "Looking into this" })
      },
      buildEnv(db)
    );
    expect(response.status).toBe(201);
    const body = (await response.json()) as {
      note: { id: string; body: string; author: string };
      author: string;
    };
    expect(body.note.body).toBe("Looking into this");
    expect(body.author).toBe("alice@example.com");

    const detailResponse = await app.request("/api/v1/alerts/alert-1", {}, buildEnv(db));
    const detail = (await detailResponse.json()) as {
      notes: { id: string; body: string }[];
      timeline: { action: string }[];
    };
    expect(detail.notes).toHaveLength(1);
    expect(detail.notes[0]?.body).toBe("Looking into this");
    expect(detail.timeline.some((entry) => entry.action === "note_added")).toBe(true);
  });

  it("honors an explicit { by } override on note", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1" })]);
    const app = createAdminApp(withAuth());

    const response = await app.request(
      "/api/v1/alerts/alert-1/notes",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ body: "see slack", by: "oncall" })
      },
      buildEnv(db)
    );
    expect(response.status).toBe(201);
    const body = (await response.json()) as { author: string };
    expect(body.author).toBe("oncall");
  });

  it("rejects a notes request with an empty body", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1" })]);
    const app = createAdminApp(withAuth());

    const response = await app.request(
      "/api/v1/alerts/alert-1/notes",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ body: "   " })
      },
      buildEnv(db)
    );
    expect(response.status).toBe(400);
  });

  it("rejects a notes request with no JSON body", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1" })]);
    const app = createAdminApp(withAuth());

    const response = await app.request(
      "/api/v1/alerts/alert-1/notes",
      { method: "POST" },
      buildEnv(db)
    );
    expect(response.status).toBe(400);
  });

  it("returns 404 when adding a note to a missing alert", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp(withAuth());

    const response = await app.request(
      "/api/v1/alerts/missing/notes",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ body: "hi" })
      },
      buildEnv(db)
    );
    expect(response.status).toBe(404);
  });

  it("rejects notes requests with no Cloudflare Access token", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1" })]);
    const app = createAdminApp();

    const response = await app.request(
      "/api/v1/alerts/alert-1/notes",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ body: "hi" })
      },
      buildEnv(db)
    );
    expect(response.status).toBe(401);
  });

  it("rejects notes requests that pass Access but have no better-auth session", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1" })]);
    const app = createAdminApp({
      accessMiddleware: () => stubAccess(),
      sessionMiddleware: stubSession(null)
    });

    const response = await app.request(
      "/api/v1/alerts/alert-1/notes",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ body: "hi" })
      },
      buildEnv(db)
    );
    expect(response.status).toBe(401);
  });

  it("reopens a resolved alert", async () => {
    const db = new FakeAlertDb([
      seed({
        id: "alert-1",
        status: "resolved",
        resolved_at: "2026-05-26T10:30:00.000Z",
        resolved_by: "bob"
      })
    ]);
    const app = createAdminApp(withAuth({ session: { id: "user-1", email: "carol@example.com" } }));

    const response = await app.request(
      "/api/v1/alerts/alert-1/reopen",
      { method: "POST" },
      buildEnv(db)
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      reopened_by: string;
      alert: { status: string };
    };
    expect(body.reopened_by).toBe("carol@example.com");
    expect(body.alert.status).toBe("open");

    const row = db.alerts.find((alert) => alert.id === "alert-1");
    expect(row?.status).toBe("open");
    expect(row?.resolved_at).toBeNull();
    expect(row?.resolved_by).toBeNull();
    expect(db.timeline.find((entry) => entry.action === "reopened")).toBeDefined();
  });

  it("returns 409 when reopening an alert that is already open", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1", status: "open" })]);
    const app = createAdminApp(withAuth());

    const response = await app.request(
      "/api/v1/alerts/alert-1/reopen",
      { method: "POST" },
      buildEnv(db)
    );
    expect(response.status).toBe(409);
  });

  it("returns 404 when reopening a missing alert", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp(withAuth());

    const response = await app.request(
      "/api/v1/alerts/missing/reopen",
      { method: "POST" },
      buildEnv(db)
    );
    expect(response.status).toBe(404);
  });

  it("rejects reopen requests that pass Access but have no session", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1", status: "resolved" })]);
    const app = createAdminApp({
      accessMiddleware: () => stubAccess(),
      sessionMiddleware: stubSession(null)
    });

    const response = await app.request(
      "/api/v1/alerts/alert-1/reopen",
      { method: "POST" },
      buildEnv(db)
    );
    expect(response.status).toBe(401);
  });

  it("assigns an alert via PATCH and writes an assigned timeline entry", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1" })]);
    const app = createAdminApp(withAuth({ session: { id: "user-1", email: "alice@example.com" } }));

    const response = await app.request(
      "/api/v1/alerts/alert-1",
      {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ assignee: "carol" })
      },
      buildEnv(db)
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { alert: { assignee: string | null }; updated_by: string };
    expect(body.alert.assignee).toBe("carol");
    expect(body.updated_by).toBe("alice@example.com");
    expect(db.alerts[0]?.assignee).toBe("carol");
    expect(db.timeline.find((entry) => entry.action === "assigned")).toBeDefined();
  });

  it("clears an assignee when PATCH sends assignee: null", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1", assignee: "carol" })]);
    const app = createAdminApp(withAuth({ session: { id: "user-1", email: "alice@example.com" } }));

    const response = await app.request(
      "/api/v1/alerts/alert-1",
      {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ assignee: null })
      },
      buildEnv(db)
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { alert: { assignee: string | null } };
    expect(body.alert.assignee).toBeNull();
    expect(db.alerts[0]?.assignee).toBeNull();
  });

  it("changes status and assignee together in one PATCH", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1" })]);
    const app = createAdminApp(withAuth({ session: { id: "user-1", email: "alice@example.com" } }));

    const response = await app.request(
      "/api/v1/alerts/alert-1",
      {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ status: "acknowledged", assignee: "dave" })
      },
      buildEnv(db)
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { alert: { status: string; assignee: string | null } };
    expect(body.alert.status).toBe("acknowledged");
    expect(body.alert.assignee).toBe("dave");
  });

  it("returns 400 when PATCH has neither status nor assignee", async () => {
    const db = new FakeAlertDb([seed({ id: "alert-1" })]);
    const app = createAdminApp(withAuth());

    const response = await app.request(
      "/api/v1/alerts/alert-1",
      { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({}) },
      buildEnv(db)
    );
    expect(response.status).toBe(400);
  });

  it("returns 404 when PATCHing a missing alert", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp(withAuth());

    const response = await app.request(
      "/api/v1/alerts/missing",
      { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ assignee: "x" }) },
      buildEnv(db)
    );
    expect(response.status).toBe(404);
  });
});

describe("admin worker detections API", () => {
  it("returns null detection health before the engine has evaluated anything", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp(withAuth());

    const response = await app.request("/api/v1/detections/health", {}, buildEnv(db));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { detection_health: unknown };
    expect(body.detection_health).toBeNull();
  });

  it("requires Cloudflare Access on the detections group", async () => {
    const response = await createAdminApp().request("/api/v1/detections", {}, buildEnv(new FakeAlertDb()));
    expect(response.status).toBe(401);
  });

  it("lists scheduled detections joined with run state", async () => {
    const db = new FakeAlertDb();
    db.detectionRules.push({
      id: "sql-spike",
      title: "Spike",
      description: null,
      severity: "high",
      source: "aws_cloudtrail",
      class_name: "api_activity",
      execution: "sql",
      tags_json: "[]",
      enabled: 1,
      definition_json: JSON.stringify({ id: "sql-spike", sql: { interval: "15m" } }),
      match_count: 0,
      last_triggered_at: null,
      created_at: "2026-05-27T12:00:00.000Z",
      updated_at: "2026-05-27T12:00:00.000Z"
    });
    db.scheduledState.push({
      rule_id: "sql-spike",
      last_run_at: "2026-05-27T12:00:00.000Z",
      last_status: "ok",
      last_row_count: 3,
      last_alert_count: 2,
      last_error: null,
      updated_at: "2026-05-27T12:00:00.000Z"
    });
    const app = createAdminApp(withAuth());

    const response = await app.request("/api/v1/detections/scheduled", {}, buildEnv(db));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { scheduled: { id: string; interval: string; last_status: string }[] };
    expect(body.scheduled).toHaveLength(1);
    expect(body.scheduled[0]).toMatchObject({ id: "sql-spike", interval: "15m", last_status: "ok" });
  });

  it("returns the detection heartbeat once recorded", async () => {
    const db = new FakeAlertDb();
    db.detectionHealth = {
      last_eval_at: "2026-05-27T12:08:00.000Z",
      total_events_evaluated: 7,
      total_alerts_created: 2,
      stateless_rule_count: 4,
      stateful_rule_count: 1,
      updated_at: "2026-05-27T12:08:00.000Z"
    };
    const app = createAdminApp(withAuth());

    const response = await app.request("/api/v1/detections/health", {}, buildEnv(db));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { detection_health: { total_events_evaluated: number; stateless_rule_count: number } };
    expect(body.detection_health.total_events_evaluated).toBe(7);
    expect(body.detection_health.stateless_rule_count).toBe(4);
  });

  function seedRule(db: FakeAlertDb, id: string, overrides: Partial<FakeDetectionRuleRow> = {}): void {
    db.detectionRules.push({
      id,
      title: `Rule ${id}`,
      description: "desc",
      severity: "high",
      source: "aws_cloudtrail",
      class_name: "authentication",
      execution: "sigma",
      tags_json: JSON.stringify(["aws"]),
      enabled: 1,
      definition_json: JSON.stringify({ id }),
      match_count: 0,
      last_triggered_at: null,
      created_at: "2026-05-27T12:00:00.000Z",
      updated_at: "2026-05-27T12:00:00.000Z",
      ...overrides
    });
  }

  it("lists detection rules and filters by enabled", async () => {
    const db = new FakeAlertDb();
    seedRule(db, "rule-a");
    seedRule(db, "rule-b", { enabled: 0 });
    const app = createAdminApp(withAuth());

    const all = await app.request("/api/v1/detections", {}, buildEnv(db));
    expect(all.status).toBe(200);
    expect(((await all.json()) as { rules: unknown[] }).rules).toHaveLength(2);

    const enabledOnly = await app.request("/api/v1/detections?enabled=true", {}, buildEnv(db));
    const body = (await enabledOnly.json()) as { rules: { id: string }[] };
    expect(body.rules.map((rule) => rule.id)).toEqual(["rule-a"]);
  });

  it("returns rule detail with hydrated tags and definition", async () => {
    const db = new FakeAlertDb();
    seedRule(db, "rule-a");
    const app = createAdminApp(withAuth());

    const response = await app.request("/api/v1/detections/rule-a", {}, buildEnv(db));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { rule: { id: string; tags: string[]; definition: unknown } };
    expect(body.rule.id).toBe("rule-a");
    expect(body.rule.tags).toEqual(["aws"]);
    expect(body.rule.definition).toMatchObject({ id: "rule-a" });
  });

  it("dry-runs a stateless detection rule against a normalized event", async () => {
    const db = new FakeAlertDb();
    seedRule(db, "root-login", {
      definition_json: JSON.stringify({
        id: "root-login",
        title: "Root login",
        description: "desc",
        severity: "high",
        tags: ["aws"],
        enabled: true,
        execution: "sigma",
        logsource: { source: "aws_cloudtrail", class_name: "authentication" },
        detection: { condition: "selection", selection: { "actor.user.type": "Root" } }
      })
    });
    const app = createAdminApp(withAuth());

    const response = await app.request(
      "/api/v1/detections/test",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          rule_id: "root-login",
          event: {
            time: "2026-05-26T10:00:00.000Z",
            source: "aws_cloudtrail",
            category: "identity_access",
            class_name: "authentication",
            activity_name: "ConsoleLogin",
            status: "success",
            actor: { user: { type: "Root" } },
            metadata: { product_name: "test", raw_event: {} }
          }
        })
      },
      buildEnv(db)
    );

    expect(response.status).toBe(200);
    const body = (await response.json()) as { matched: boolean; matches: { rule_id: string }[] };
    expect(body.matched).toBe(true);
    expect(body.matches[0]?.rule_id).toBe("root-login");
  });

  it("rejects dry-run for non-sigma rules", async () => {
    const db = new FakeAlertDb();
    seedRule(db, "sql-rule", { execution: "sql", definition_json: JSON.stringify({ id: "sql-rule" }) });
    const app = createAdminApp(withAuth());

    const response = await app.request(
      "/api/v1/detections/test",
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ rule_id: "sql-rule", event: {} }) },
      buildEnv(db)
    );
    expect(response.status).toBe(400);
  });

  it("returns 404 for an unknown detection rule", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp(withAuth());
    const response = await app.request("/api/v1/detections/missing", {}, buildEnv(db));
    expect(response.status).toBe(404);
  });

  it("toggles a rule's enabled state via PATCH", async () => {
    const db = new FakeAlertDb();
    seedRule(db, "rule-a");
    const app = createAdminApp(withAuth());

    const response = await app.request(
      "/api/v1/detections/rule-a",
      { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled: false }) },
      buildEnv(db)
    );
    expect(response.status).toBe(200);
    expect(((await response.json()) as { rule: { enabled: boolean } }).rule.enabled).toBe(false);
    expect(db.detectionRules[0]?.enabled).toBe(0);
  });

  it("returns 400 when PATCH omits a boolean enabled", async () => {
    const db = new FakeAlertDb();
    seedRule(db, "rule-a");
    const app = createAdminApp(withAuth());

    const response = await app.request(
      "/api/v1/detections/rule-a",
      { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({}) },
      buildEnv(db)
    );
    expect(response.status).toBe(400);
  });

  it("returns 404 when PATCHing an unknown rule", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp(withAuth());
    const response = await app.request(
      "/api/v1/detections/missing",
      { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled: true }) },
      buildEnv(db)
    );
    expect(response.status).toBe(404);
  });
});

describe("admin worker dashboard API", () => {
  const now = new Date("2026-05-27T12:10:00.000Z");

  function appWithClock() {
    return createAdminApp({ ...withAuth(), dashboardRoutes: { now: () => now } });
  }

  it("requires Cloudflare Access", async () => {
    const db = new FakeAlertDb();
    const response = await createAdminApp().request("/api/v1/dashboard/overview", {}, buildEnv(db));
    expect(response.status).toBe(401);
  });

  it("returns an aggregated overview", async () => {
    const db = new FakeAlertDb([seed({ id: "a", severity: "high" })]);
    db.sourceHealth.push({
      source: "aws_cloudtrail",
      tenant_id: "default",
      last_event_at: "2026-05-27T12:05:00.000Z",
      last_event_count: 1,
      total_events: 5,
      total_batches: 2,
      total_errors: 0,
      last_error_at: null,
      last_error_message: null,
      updated_at: "2026-05-27T12:05:00.000Z"
    });
    db.detectionRules.push({
      id: "rule-a",
      title: "Rule A",
      description: null,
      severity: "high",
      source: "aws_cloudtrail",
      class_name: "authentication",
      execution: "sigma",
      tags_json: "[]",
      enabled: 1,
      definition_json: "{}",
      match_count: 0,
      last_triggered_at: null,
      created_at: "2026-05-27T12:00:00.000Z",
      updated_at: "2026-05-27T12:00:00.000Z"
    });

    const response = await appWithClock().request("/api/v1/dashboard/overview", {}, buildEnv(db));
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      overview: {
        generated_at: string;
        sources: { total: number; healthy: number };
        alerts: { total: number };
        detection: { rules: { total: number; enabled: number } };
      };
    };
    expect(body.overview.generated_at).toBe(now.toISOString());
    expect(body.overview.sources.total).toBe(1);
    expect(body.overview.sources.healthy).toBe(1);
    expect(body.overview.alerts.total).toBe(1);
    expect(body.overview.detection.rules).toMatchObject({ total: 1, enabled: 1 });
  });
});

describe("admin worker internal api-key mint API", () => {
  it("requires Cloudflare Access", async () => {
    const { db } = apiKeyDb();
    const env: AdminEnv = { ...buildEnv(new FakeAlertDb()), AUTH_DB: db };

    const res = await createAdminApp().request(
      "/api/v1/internal/api-keys",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ user_id: "user-1", source: "aws_cloudtrail", tenant_id: "default" })
      },
      env
    );

    expect(res.status).toBe(401);
  });

  it("creates key metadata with source and tenant_id", async () => {
    const { db, rows } = apiKeyDb();
    const app = createAdminApp({ accessMiddleware: () => stubAccess() });
    const env: AdminEnv = { ...buildEnv(new FakeAlertDb()), AUTH_DB: db };

    const res = await app.request(
      "/api/v1/internal/api-keys",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ user_id: "user-1", source: "aws_cloudtrail", tenant_id: "default" })
      },
      env
    );

    expect(res.status).toBe(201);
    const body = (await res.json()) as {
      id: string;
      key: string;
      name: string;
      metadata: { source: string; tenant_id: string };
      user_id: string;
    };
    expect(body.key).toMatch(/^pk_/);
    expect(body.name).toBe("aws_cloudtrail/default");
    expect(body.metadata).toEqual({ source: "aws_cloudtrail", tenant_id: "default" });
    expect(body.user_id).toBe("user-1");

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      id: body.id,
      configId: "default",
      name: "aws_cloudtrail/default",
      referenceId: "user-1",
      enabled: 1,
      rateLimitEnabled: 1,
      rateLimitTimeWindow: 60_000,
      rateLimitMax: 600,
      requestCount: 0,
      remaining: null,
      metadata: JSON.stringify({ source: "aws_cloudtrail", tenant_id: "default" })
    });
    expect(rows[0]?.key).toBe(await sha256Base64Url(body.key));
  });

  it("returns a key that apiKeyAuth accepts", async () => {
    const { db, rows } = apiKeyDb();
    const adminApp = createAdminApp({ accessMiddleware: () => stubAccess() });
    const env: AdminEnv = { ...buildEnv(new FakeAlertDb()), AUTH_DB: db };

    const mint = await adminApp.request(
      "/api/v1/internal/api-keys",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ user_id: "user-1", source: "aws_cloudtrail", tenant_id: "default" })
      },
      env
    );
    const minted = (await mint.json()) as { key: string };

    const protectedApp = new Hono();
    protectedApp.use("/events", apiKeyAuth(authBackedByRows(rows)));
    protectedApp.post("/events", (c) => c.json(c.get("apiKey")));

    const res = await protectedApp.request("/events", {
      method: "POST",
      headers: { "x-api-key": minted.key }
    });

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      user_id: "user-1",
      tenant_id: "default",
      source: "aws_cloudtrail"
    });
  });
});

// Loose stub for the producer-side of Queue. We only call .send() in the
// path we're testing; matching the full interface signature isn't worth it.
const fakeQueue = () => {
  const sent: Array<{ job_id: string }> = [];
  return {
    sent,
    binding: {
      send: async (message: { job_id: string }) => {
        sent.push(message);
      }
    } as unknown as Queue<{ job_id: string }>
  };
};

function withQueryAuth(): {
  accessMiddleware: () => MiddlewareHandler;
  queryRoutes: {
    uuid: () => string;
    now: () => Date;
    sleep: () => Promise<void>;
  };
} {
  let n = 0;
  return {
    accessMiddleware: () => stubAccess(),
    queryRoutes: {
      uuid: () => `job-${++n}`,
      now: () => new Date("2026-05-27T12:00:00.000Z"),
      sleep: () => Promise.resolve()
    }
  };
}

describe("admin worker async query API", () => {
  function buildQueryEnv(overrides: Partial<AdminEnv> = {}): AdminEnv {
    return {
      ...buildEnv(new FakeAlertDb()),
      PICKET_R2_WAREHOUSE: "acct_picket-lake",
      PICKET_TABLE_SUFFIX: "pure_alien",
      QUERY_JOBS_QUEUE: fakeQueue().binding,
      ...overrides
    };
  }

  it("rejects mutually exclusive preset + sql", async () => {
    const app = createAdminApp(withQueryAuth());
    const res = await app.request(
      "/api/v1/query",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ preset: "iam-changes", sql: "SELECT 1" })
      },
      buildQueryEnv()
    );
    expect(res.status).toBe(400);
  });

  it("rejects raw SQL with mutating statements", async () => {
    const app = createAdminApp(withQueryAuth());
    const res = await app.request(
      "/api/v1/query",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sql: "DELETE FROM aws_cloudtrail" })
      },
      buildQueryEnv()
    );
    expect(res.status).toBe(400);
  });

  it("500s when no warehouse is configured anywhere", async () => {
    const app = createAdminApp(withQueryAuth());
    const env = buildQueryEnv();
    delete env.PICKET_R2_WAREHOUSE;
    const res = await app.request(
      "/api/v1/query",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ preset: "iam-changes" })
      },
      env
    );
    expect(res.status).toBe(500);
  });

  it("requires Access auth", async () => {
    const res = await createAdminApp().request(
      "/api/v1/query",
      { method: "POST", body: JSON.stringify({ preset: "iam-changes" }) },
      buildQueryEnv()
    );
    expect(res.status).toBe(401);
  });

  // Integration-style tests against the real D1 query_jobs flow would need
  // a D1 stub for query_jobs (similar to FakeAlertDb). Skipped here; the
  // storage layer's behavior is exercised in @picket/core/query-jobs.test.
});

describe("admin worker query management API", () => {
  it("explains a preset without executing it", async () => {
    const app = createAdminApp(withQueryAuth());
    const res = await app.request(
      "/api/v1/query/explain",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ preset: "iam-changes" })
      },
      { ...buildEnv(new FakeAlertDb()), PICKET_TABLE_SUFFIX: "pure_alien" }
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      explain: { sql: string; valid: boolean; plan: { tables: string[]; has_limit: boolean } };
    };
    expect(body.explain.valid).toBe(true);
    expect(body.explain.sql).toContain("aws_cloudtrail_pure_alien");
    expect(body.explain.plan.tables).toContain("aws_cloudtrail_pure_alien");
    expect(body.explain.plan.has_limit).toBe(true);
  });

  it("rejects an invalid query on explain", async () => {
    const app = createAdminApp(withQueryAuth());
    const res = await app.request(
      "/api/v1/query/explain",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sql: "DELETE FROM aws_cloudtrail" })
      },
      buildEnv(new FakeAlertDb())
    );
    expect(res.status).toBe(400);
  });

  it("saves a query and lists it", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp(withQueryAuth());
    const env = buildEnv(db);

    const saveRes = await app.request(
      "/api/v1/query/save",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "my failed logins", sql: "SELECT * FROM aws_cloudtrail WHERE time > now() - interval '1' hour" })
      },
      env
    );
    expect(saveRes.status).toBe(201);
    const saved = (await saveRes.json()) as { saved: { name: string; owner: string; id: string } };
    expect(saved.saved.name).toBe("my failed logins");
    expect(saved.saved.owner).toBe("access@example.com");

    const listRes = await app.request("/api/v1/query/saved", {}, env);
    expect(listRes.status).toBe(200);
    const list = (await listRes.json()) as { saved: { name: string }[] };
    expect(list.saved.map((row) => row.name)).toEqual(["my failed logins"]);
  });

  it("requires a name on save", async () => {
    const app = createAdminApp(withQueryAuth());
    const res = await app.request(
      "/api/v1/query/save",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sql: "SELECT 1" })
      },
      buildEnv(new FakeAlertDb())
    );
    expect(res.status).toBe(400);
  });

  it("lists query history newest-first", async () => {
    const db = new FakeAlertDb();
    db.queryHistory.push(
      { id: "h1", owner: "a@x", sql: "SELECT 1", preset: null, job_id: "j1", created_at: "2026-05-27T10:00:00.000Z" },
      { id: "h2", owner: "a@x", sql: "SELECT 2", preset: "iam-changes", job_id: "j2", created_at: "2026-05-27T11:00:00.000Z" }
    );
    const app = createAdminApp(withQueryAuth());

    const res = await app.request("/api/v1/query/history", {}, buildEnv(db));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { history: { id: string }[] };
    expect(body.history.map((row) => row.id)).toEqual(["h2", "h1"]);
  });

  it("does not treat `saved` or `history` as a job id", async () => {
    const app = createAdminApp(withQueryAuth());
    const env = buildEnv(new FakeAlertDb());
    const saved = await app.request("/api/v1/query/saved", {}, env);
    expect(saved.status).toBe(200);
    const history = await app.request("/api/v1/query/history", {}, env);
    expect(history.status).toBe(200);
  });

  it("requires Access auth", async () => {
    const res = await createAdminApp().request("/api/v1/query/saved", {}, buildEnv(new FakeAlertDb()));
    expect(res.status).toBe(401);
  });

  function appWithNl(generate: (input: { system: string; question: string }) => Promise<{ sql: string; rationale?: string }>) {
    return createAdminApp({
      accessMiddleware: () => stubAccess(),
      queryRoutes: { uuid: () => "job-nl", now: () => new Date("2026-05-27T12:00:00.000Z"), sleep: () => Promise.resolve(), nlSqlClient: { generate } }
    });
  }

  it("rejects a natural query with no question", async () => {
    const app = appWithNl(async () => ({ sql: "SELECT 1" }));
    const res = await app.request(
      "/api/v1/query/natural",
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({}) },
      buildEnv(new FakeAlertDb())
    );
    expect(res.status).toBe(400);
  });

  it("500s a natural query when ANTHROPIC_API_KEY is not configured", async () => {
    const app = createAdminApp(withQueryAuth());
    const res = await app.request(
      "/api/v1/query/natural",
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ question: "failed logins" }) },
      buildEnv(new FakeAlertDb())
    );
    expect(res.status).toBe(500);
  });

  it("returns 422 with the generated SQL when validation rejects it", async () => {
    const app = appWithNl(async () => ({ sql: "DELETE FROM aws_cloudtrail" }));
    const res = await app.request(
      "/api/v1/query/natural",
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ question: "wipe the table" }) },
      buildEnv(new FakeAlertDb())
    );
    expect(res.status).toBe(422);
    const body = (await res.json()) as { generated_sql: string; details: string[] };
    expect(body.generated_sql).toBe("DELETE FROM aws_cloudtrail");
    expect(body.details.length).toBeGreaterThan(0);
  });

  it("passes the OCSF schema + tables to the model and 502s on an NL error", async () => {
    let capturedSystem = "";
    const app = appWithNl(async ({ system }) => {
      capturedSystem = system;
      throw new (await import("@picket/query")).NlSqlError("upstream boom");
    });
    const res = await app.request(
      "/api/v1/query/natural",
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ question: "anything" }) },
      { ...buildEnv(new FakeAlertDb()), PICKET_TABLE_SUFFIX: "pure_alien" }
    );
    expect(res.status).toBe(502);
    // The prompt advertised the suffixed tables + OCSF columns.
    expect(capturedSystem).toContain("aws_cloudtrail_pure_alien");
    expect(capturedSystem).toContain("actor_user_uid");
  });
});

describe("admin worker sources API", () => {
  it("returns source health rows", async () => {
    const db = new FakeAlertDb();
    db.sourceHealth.push({
      source: "aws_cloudtrail",
      tenant_id: "tenant-a",
      last_event_at: "2026-05-27T12:05:00.000Z",
      last_event_count: 1,
      total_events: 12,
      total_batches: 4,
      total_errors: 0,
      last_error_at: null,
      last_error_message: null,
      updated_at: "2026-05-27T12:05:00.000Z"
    });

    const app = createAdminApp(withAuth());
    const res = await app.request("/api/v1/sources", {}, buildEnv(db));

    expect(res.status).toBe(200);
    const body = (await res.json()) as { sources: Array<{ source: string }> };
    expect(body.sources).toHaveLength(1);
    expect(body.sources[0]?.source).toBe("aws_cloudtrail");
  });

  it("returns 404 when --source filter has no match", async () => {
    const db = new FakeAlertDb();
    const app = createAdminApp(withAuth());
    const res = await app.request("/api/v1/sources?source=nope", {}, buildEnv(db));
    expect(res.status).toBe(404);
  });

  it("requires Access auth", async () => {
    const res = await createAdminApp().request("/api/v1/sources", {}, buildEnv(new FakeAlertDb()));
    expect(res.status).toBe(401);
  });

  it("returns single-source status with health classification", async () => {
    const db = new FakeAlertDb();
    db.sourceHealth.push({
      source: "aws_cloudtrail",
      tenant_id: "default",
      last_event_at: "2026-05-27T12:05:00.000Z", // 5min before the injected clock → healthy
      last_event_count: 1,
      total_events: 12,
      total_batches: 4,
      total_errors: 0,
      last_error_at: null,
      last_error_message: null,
      updated_at: "2026-05-27T12:05:00.000Z"
    });
    const app = createAdminApp({
      ...withAuth(),
      queryRoutes: { now: () => new Date("2026-05-27T12:10:00.000Z") }
    });

    const res = await app.request("/api/v1/sources/aws_cloudtrail/status", {}, buildEnv(db));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: { source: string; health: string } };
    expect(body.status.source).toBe("aws_cloudtrail");
    expect(body.status.health).toBe("healthy");
  });

  it("returns 404 for status of an unreported source", async () => {
    const app = createAdminApp(withAuth());
    const res = await app.request("/api/v1/sources/aws_cloudtrail/status", {}, buildEnv(new FakeAlertDb()));
    expect(res.status).toBe(404);
  });

  it("returns the OCSF field schema for a known source", async () => {
    const app = createAdminApp(withAuth());
    const res = await app.request("/api/v1/sources/aws_cloudtrail/schema", {}, buildEnv(new FakeAlertDb()));
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      schema: { source: string; field_count: number; fields: { name: string }[] };
    };
    expect(body.schema.source).toBe("aws_cloudtrail");
    expect(body.schema.field_count).toBe(body.schema.fields.length);
    expect(body.schema.fields.map((f) => f.name)).toContain("actor_user_uid");
    expect(body.schema.fields.map((f) => f.name)).toContain("time");
  });

  it("returns 404 schema for an unknown source", async () => {
    const app = createAdminApp(withAuth());
    const res = await app.request("/api/v1/sources/not_a_source/schema", {}, buildEnv(new FakeAlertDb()));
    expect(res.status).toBe(404);
  });

  it("returns source ingestion history and recent errors", async () => {
    const db = new FakeAlertDb();
    db.sourceHealth.push({
      source: "aws_cloudtrail",
      tenant_id: "default",
      last_event_at: "2026-05-27T12:05:00.000Z",
      last_event_count: 2,
      total_events: 2,
      total_batches: 1,
      total_errors: 1,
      last_error_at: "2026-05-27T12:06:00.000Z",
      last_error_message: "bad record",
      updated_at: "2026-05-27T12:06:00.000Z"
    });
    db.sourceHealthHistory.push(
      {
        id: 1,
        source: "aws_cloudtrail",
        tenant_id: "default",
        kind: "batch",
        event_count: 2,
        last_event_at: "2026-05-27T12:05:00.000Z",
        error_message: null,
        recorded_at: "2026-05-27T12:05:00.000Z"
      },
      {
        id: 2,
        source: "aws_cloudtrail",
        tenant_id: "default",
        kind: "error",
        event_count: 0,
        last_event_at: null,
        error_message: "bad record",
        recorded_at: "2026-05-27T12:06:00.000Z"
      }
    );
    const app = createAdminApp(withAuth());

    const historyRes = await app.request("/api/v1/sources/aws_cloudtrail/history", {}, buildEnv(db));
    expect(historyRes.status).toBe(200);
    const historyBody = (await historyRes.json()) as { history: Array<{ kind: string }> };
    expect(historyBody.history.map((entry) => entry.kind)).toEqual(["error", "batch"]);

    const errorsRes = await app.request("/api/v1/sources/aws_cloudtrail/errors", {}, buildEnv(db));
    expect(errorsRes.status).toBe(200);
    const errorsBody = (await errorsRes.json()) as { errors: Array<{ error_message: string }> };
    expect(errorsBody.errors).toEqual([expect.objectContaining({ error_message: "bad record" })]);
  });

  it("validates source history limits", async () => {
    const db = new FakeAlertDb();
    db.sourceHealth.push({
      source: "aws_cloudtrail",
      tenant_id: "default",
      last_event_at: null,
      last_event_count: 0,
      total_events: 0,
      total_batches: 0,
      total_errors: 0,
      last_error_at: null,
      last_error_message: null,
      updated_at: "2026-05-27T12:00:00.000Z"
    });
    const app = createAdminApp(withAuth());
    const res = await app.request("/api/v1/sources/aws_cloudtrail/history?limit=201", {}, buildEnv(db));
    expect(res.status).toBe(400);
  });

  it("rejects sample for an unknown source before touching the query flow", async () => {
    const app = createAdminApp(withQueryAuth());
    const res = await app.request("/api/v1/sources/not_a_source/sample", {}, {
      ...buildEnv(new FakeAlertDb()),
      PICKET_R2_WAREHOUSE: "acct_picket-lake",
      PICKET_TABLE_SUFFIX: "pure_alien",
      QUERY_JOBS_QUEUE: fakeQueue().binding
    });
    expect(res.status).toBe(404);
  });

  it("500s sample when no warehouse is configured", async () => {
    const app = createAdminApp(withQueryAuth());
    const res = await app.request("/api/v1/sources/aws_cloudtrail/sample", {}, buildEnv(new FakeAlertDb()));
    expect(res.status).toBe(500);
  });

  it("requires Access auth for single-source endpoints", async () => {
    const res = await createAdminApp().request(
      "/api/v1/sources/aws_cloudtrail/schema",
      {},
      buildEnv(new FakeAlertDb())
    );
    expect(res.status).toBe(401);
  });
});

describe("admin worker meta endpoint", () => {
  it("is unauthenticated and reports access_required + verification_uri", async () => {
    const res = await createAdminApp().request(
      "http://api.test/api/v1/meta",
      {},
      buildEnv(new FakeAlertDb())
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_required: boolean; verification_uri: string; api_url: string };
    expect(body.access_required).toBe(true);
    expect(body.verification_uri).toBe("http://api.test/device");
    expect(body.api_url).toBe("http://api.test");
  });
});

describe("admin worker device approval", () => {
  // Minimal PicketAuth stub: tracks calls and decides synchronously. The real
  // implementation talks to D1 via Kysely; that's exercised in higher-level
  // smoke tests, not here.
  interface FakeAuthState {
    users: Map<string, { id: string; email: string }>;
    deviceCodes: Map<string, { status: "pending" | "approved" | "denied"; userId?: string; expiresAt: Date }>;
  }
  function fakeAuth(state: FakeAuthState) {
    return {
      api: {} as never,
      handler: async () => new Response("not used", { status: 404 }),
      findOrCreateUserByEmail: async (email: string) => {
        let user = state.users.get(email);
        if (!user) {
          user = { id: `user-${state.users.size + 1}`, email };
          state.users.set(email, user);
        }
        return user;
      },
      decideDeviceCode: async (userCode: string, userId: string, decision: "approved" | "denied") => {
        const code = userCode.replace(/-/g, "");
        const rec = state.deviceCodes.get(code);
        if (!rec) return { ok: false as const, reason: "not_found" as const };
        if (rec.expiresAt.getTime() < Date.now()) return { ok: false as const, reason: "expired" as const };
        if (rec.status !== "pending") return { ok: false as const, reason: "already_processed" as const };
        rec.status = decision;
        rec.userId = userId;
        return { ok: true as const, status: decision };
      }
    };
  }

  function appWithFakeAuth(state: FakeAuthState) {
    return createAdminApp({
      accessMiddleware: () => stubAccess({ email: "alice@example.com" }),
      resolveAuth: () => fakeAuth(state) as never
    });
  }

  it("renders the device page with the user code", async () => {
    const state: FakeAuthState = { users: new Map(), deviceCodes: new Map() };
    const res = await appWithFakeAuth(state).request(
      "/device?user_code=ABCD-EFGH",
      {},
      buildEnv(new FakeAlertDb())
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    const html = await res.text();
    expect(html).toContain("ABCD-EFGH");
    expect(html).toContain("/device/approve");
    expect(html).toContain("/device/deny");
  });

  it("approves a pending code via Access identity and find-or-creates the user", async () => {
    const state: FakeAuthState = {
      users: new Map(),
      deviceCodes: new Map([["ABCDEFGH", { status: "pending", expiresAt: new Date(Date.now() + 60_000) }]])
    };
    const app = appWithFakeAuth(state);
    const res = await app.request(
      "/device/approve",
      {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ user_code: "ABCD-EFGH" })
      },
      buildEnv(new FakeAlertDb())
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("approved");
    expect(state.deviceCodes.get("ABCDEFGH")?.status).toBe("approved");
    expect(state.users.get("alice@example.com")?.id).toBe("user-1");
    expect(state.deviceCodes.get("ABCDEFGH")?.userId).toBe("user-1");
  });

  it("denies a pending code", async () => {
    const state: FakeAuthState = {
      users: new Map(),
      deviceCodes: new Map([["ABCDEFGH", { status: "pending", expiresAt: new Date(Date.now() + 60_000) }]])
    };
    const res = await appWithFakeAuth(state).request(
      "/device/deny",
      {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ user_code: "ABCD-EFGH" })
      },
      buildEnv(new FakeAlertDb())
    );
    expect(res.status).toBe(200);
    expect(state.deviceCodes.get("ABCDEFGH")?.status).toBe("denied");
  });

  it("redirects (303) with an error param for form posts that hit a missing code", async () => {
    const state: FakeAuthState = { users: new Map(), deviceCodes: new Map() };
    const res = await appWithFakeAuth(state).request(
      "/device/approve",
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ user_code: "ABCD-EFGH" }).toString(),
        redirect: "manual"
      },
      buildEnv(new FakeAlertDb())
    );
    expect(res.status).toBe(303);
    const loc = res.headers.get("location") ?? "";
    expect(loc).toContain("/device?");
    expect(loc).toContain("error=");
  });

  it("requires Access auth on /device", async () => {
    const res = await createAdminApp().request(
      "/device?user_code=ABCD-EFGH",
      {},
      buildEnv(new FakeAlertDb())
    );
    expect(res.status).toBe(401);
  });
});

describe("enrichment routes", () => {
  function fakeKv() {
    const store = new Map<string, { value: string; metadata?: Record<string, unknown> }>();
    return {
      store,
      async get(key: string) {
        return store.get(key)?.value ?? null;
      },
      async put(key: string, value: string, options?: { metadata?: Record<string, unknown> }) {
        store.set(key, { value, metadata: options?.metadata });
      },
      async delete(key: string) {
        store.delete(key);
      },
      async list(options?: { prefix?: string; cursor?: string; limit?: number }) {
        const prefix = options?.prefix ?? "";
        const all = [...store.entries()].filter(([name]) => name.startsWith(prefix));
        return {
          keys: all.map(([name, entry]) => ({ name, metadata: entry.metadata })),
          list_complete: true
        };
      }
    };
  }

  function fakePipeline() {
    const sent: Record<string, unknown>[][] = [];
    return {
      sent,
      pipeline: {
        async send(records: Record<string, unknown>[]) {
          sent.push(records);
        }
      }
    };
  }

  function envWithKv(
    kv: ReturnType<typeof fakeKv>,
    pipelines: { threatIntel?: ReturnType<typeof fakePipeline>; assets?: ReturnType<typeof fakePipeline>; users?: ReturnType<typeof fakePipeline> } = {}
  ): AdminEnv {
    return {
      ...buildEnv(new FakeAlertDb()),
      ENRICHMENT_KV: kv as unknown as AdminEnv["ENRICHMENT_KV"],
      ...(pipelines.threatIntel ? { THREAT_INTEL_PIPELINE: pipelines.threatIntel.pipeline } : {}),
      ...(pipelines.assets ? { ASSETS_PIPELINE: pipelines.assets.pipeline } : {}),
      ...(pipelines.users ? { USERS_PIPELINE: pipelines.users.pipeline } : {})
    };
  }

  it("requires Access auth on /api/v1/enrichment/iocs", async () => {
    const res = await createAdminApp().request("/api/v1/enrichment/iocs", {}, envWithKv(fakeKv()));
    expect(res.status).toBe(401);
  });

  it("503s when ENRICHMENT_KV is unbound", async () => {
    const app = createAdminApp(withAuth());
    const res = await app.request("/api/v1/enrichment/iocs", {}, buildEnv(new FakeAlertDb()));
    expect(res.status).toBe(503);
  });

  it("adds and lists IOCs", async () => {
    const kv = fakeKv();
    const app = createAdminApp(withAuth());
    const post = await app.request(
      "/api/v1/enrichment/iocs",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ iocs: [
          { indicator: "6.6.6.6", indicator_type: "ipv4", feed_name: "abuse.ch", threat_type: "c2" },
          { indicator: "evil.com", indicator_type: "domain" }
        ] })
      },
      envWithKv(kv)
    );
    expect(post.status).toBe(201);
    expect(await post.json()).toEqual({ written: 2 });

    const list = await app.request("/api/v1/enrichment/iocs?type=ipv4", {}, envWithKv(kv));
    expect(list.status).toBe(200);
    const body = (await list.json()) as { iocs: { indicator: string; feed_name?: string }[] };
    expect(body.iocs).toHaveLength(1);
    expect(body.iocs[0]).toMatchObject({ indicator: "6.6.6.6", feed_name: "abuse.ch" });
  });

  it("lists feeds from IOC metadata", async () => {
    const kv = fakeKv();
    const app = createAdminApp(withAuth());
    await app.request(
      "/api/v1/enrichment/iocs",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ iocs: [
          { indicator: "6.6.6.6", indicator_type: "ipv4", feed_name: "abuse.ch", added_at: "2026-05-26T10:00:00.000Z" },
          { indicator: "evil.com", indicator_type: "domain", feed_name: "abuse.ch", added_at: "2026-05-26T11:00:00.000Z" }
        ] })
      },
      envWithKv(kv)
    );

    const res = await app.request("/api/v1/enrichment/feeds", {}, envWithKv(kv));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { feeds: { name: string; indicator_count: number; last_updated: string | null }[] };
    expect(body.feeds).toEqual([{ name: "abuse.ch", type: "ioc", indicator_count: 2, last_updated: "2026-05-26T11:00:00.000Z" }]);
  });

  it("creates a feed with IOC rows", async () => {
    const kv = fakeKv();
    const pipe = fakePipeline();
    const app = createAdminApp(withAuth());
    const res = await app.request(
      "/api/v1/enrichment/feeds",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: "manual-feed",
          type: "csv",
          iocs: [{ indicator: "1.2.3.4", indicator_type: "ipv4", threat_type: "scanner" }]
        })
      },
      envWithKv(kv, { threatIntel: pipe })
    );
    expect(res.status).toBe(201);
    const body = (await res.json()) as { feed: { name: string; indicator_count: number } };
    expect(body.feed).toMatchObject({ name: "manual-feed", indicator_count: 1 });
    expect(pipe.sent[0]?.[0]).toMatchObject({ indicator: "1.2.3.4", feed_name: "manual-feed", active: true });
  });

  it("checks indicators against loaded IOCs", async () => {
    const kv = fakeKv();
    const app = createAdminApp(withAuth());
    await app.request(
      "/api/v1/enrichment/iocs",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ indicator: "6.6.6.6", indicator_type: "ipv4", feed_name: "abuse.ch" })
      },
      envWithKv(kv)
    );

    const res = await app.request(
      "/api/v1/enrichment/iocs/check",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ indicators: [
          { indicator: "6.6.6.6", indicator_type: "ipv4" },
          { indicator: "7.7.7.7", indicator_type: "ipv4" }
        ] })
      },
      envWithKv(kv)
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { match_count: number; results: { matched: boolean; ioc: unknown }[] };
    expect(body.match_count).toBe(1);
    expect(body.results.map((result) => result.matched)).toEqual([true, false]);
  });

  it("appends active threat_intel rows when IOCs are added", async () => {
    const kv = fakeKv();
    const pipe = fakePipeline();
    const app = createAdminApp(withAuth());
    const res = await app.request(
      "/api/v1/enrichment/iocs",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ indicator: "6.6.6.6", indicator_type: "ipv4", feed_name: "abuse.ch", threat_type: "c2" })
      },
      envWithKv(kv, { threatIntel: pipe })
    );
    expect(res.status).toBe(201);
    expect(pipe.sent).toHaveLength(1);
    expect(pipe.sent[0]).toHaveLength(1);
    expect(pipe.sent[0]?.[0]).toMatchObject({
      indicator: "6.6.6.6",
      indicator_type: "ipv4",
      feed_name: "abuse.ch",
      threat_type: "c2",
      active: true
    });
    expect(typeof pipe.sent[0]?.[0]?.added_at).toBe("string");
    expect(typeof pipe.sent[0]?.[0]?.loaded_at).toBe("string");
  });

  it("accepts a single IOC object", async () => {
    const kv = fakeKv();
    const app = createAdminApp(withAuth());
    const res = await app.request(
      "/api/v1/enrichment/iocs",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ indicator: "1.1.1.1", indicator_type: "ipv4" })
      },
      envWithKv(kv)
    );
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ written: 1 });
  });

  it("rejects an invalid indicator_type with 400", async () => {
    const app = createAdminApp(withAuth());
    const res = await app.request(
      "/api/v1/enrichment/iocs",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ indicator: "x", indicator_type: "carrier-pigeon" })
      },
      envWithKv(fakeKv())
    );
    expect(res.status).toBe(400);
  });

  it("deletes an IOC, 404 when absent", async () => {
    const kv = fakeKv();
    const pipe = fakePipeline();
    const app = createAdminApp(withAuth());
    await app.request(
      "/api/v1/enrichment/iocs",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ indicator: "6.6.6.6", indicator_type: "ipv4" })
      },
      envWithKv(kv, { threatIntel: pipe })
    );

    const del = await app.request("/api/v1/enrichment/iocs/ipv4/6.6.6.6", { method: "DELETE" }, envWithKv(kv, { threatIntel: pipe }));
    expect(del.status).toBe(200);
    expect(await del.json()).toEqual({ deleted: true });
    expect(pipe.sent.at(-1)?.[0]).toMatchObject({ indicator: "6.6.6.6", indicator_type: "ipv4", active: false });

    const again = await app.request("/api/v1/enrichment/iocs/ipv4/6.6.6.6", { method: "DELETE" }, envWithKv(kv, { threatIntel: pipe }));
    expect(again.status).toBe(404);
  });

  it("imports IOC CSV rows into KV and threat_intel", async () => {
    const kv = fakeKv();
    const pipe = fakePipeline();
    const app = createAdminApp(withAuth());
    const res = await app.request(
      "/api/v1/enrichment/iocs/import?feed=manual&threat_type=c2",
      {
        method: "POST",
        headers: { "content-type": "text/csv" },
        body: "indicator,indicator_type\n6.6.6.6,ipv4\nevil.com,domain\n"
      },
      envWithKv(kv, { threatIntel: pipe })
    );
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ written: 2 });
    expect(pipe.sent[0]).toHaveLength(2);
    expect(pipe.sent[0]?.[0]).toMatchObject({ indicator: "6.6.6.6", indicator_type: "ipv4", feed_name: "manual", threat_type: "c2", active: true });
  });

  it("loads assets into the assets dimension pipeline", async () => {
    const pipe = fakePipeline();
    const app = createAdminApp(withAuth());
    const res = await app.request(
      "/api/v1/enrichment/assets",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ assets: [{ asset_uid: "i-123", hostname: "web-1", criticality: "high" }] })
      },
      envWithKv(fakeKv(), { assets: pipe })
    );
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ written: 1 });
    expect(pipe.sent[0]?.[0]).toMatchObject({ asset_uid: "i-123", hostname: "web-1", criticality: "high", active: true });
  });

  it("loads users into the users dimension pipeline", async () => {
    const pipe = fakePipeline();
    const app = createAdminApp(withAuth());
    const res = await app.request(
      "/api/v1/enrichment/users",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ users: [{ user_uid: "alice", user_email: "alice@example.com", department: "security" }] })
      },
      envWithKv(fakeKv(), { users: pipe })
    );
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ written: 1 });
    expect(pipe.sent[0]?.[0]).toMatchObject({ user_uid: "alice", user_email: "alice@example.com", department: "security", active: true });
  });
});
