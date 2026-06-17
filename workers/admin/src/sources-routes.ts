import type { Hono } from "hono";

import {
  classifySourceHealth,
  getSourceHealth,
  listSourceHealth,
  listSourceHealthHistory
} from "@picket/core/source-health";
import { isKnownSource, ocsfSchemaForSource, sampleQuery } from "@picket/core/sources";

import type { AdminEnv } from "./index";
import { resolveQueryDeps, submitQueryJob, type QueryRoutesOptions } from "./query-routes";

export interface SourcesRoutesOptions {
  // Reuses the query-job injection points (uuid/now/sleep) so /sample can be
  // driven deterministically in tests, just like POST /api/v1/query.
  query?: QueryRoutesOptions;
}

export function registerSourcesRoutes(
  app: Hono<{ Bindings: AdminEnv }>,
  options: SourcesRoutesOptions = {}
): void {
  const queryDeps = resolveQueryDeps(options.query);
  const now = queryDeps.now;

  app.get("/api/v1/sources", async (c) => {
    const url = new URL(c.req.url);
    const tenant = url.searchParams.get("tenant") ?? undefined;
    const source = url.searchParams.get("source");

    const rows = await listSourceHealth(c.env.ALERT_STATE_DB, tenant ? { tenant_id: tenant } : {});
    const filtered = source ? rows.filter((row) => row.source === source) : rows;

    if (source && filtered.length === 0) {
      return c.json({ error: `Source not found: ${source}` }, 404);
    }

    return c.json({ sources: filtered });
  });

  // Single-source ingestion health, with the same freshness classification used
  // by `picket status` and the dashboard.
  app.get("/api/v1/sources/:id/status", async (c) => {
    const id = c.req.param("id");
    const url = new URL(c.req.url);
    const tenant = url.searchParams.get("tenant") ?? undefined;

    const row = await getSourceHealth(c.env.ALERT_STATE_DB, id, tenant);
    if (!row) return c.json({ error: `Source not found: ${id}` }, 404);

    return c.json({ status: { ...row, health: classifySourceHealth(row, now()) } });
  });

  // OCSF field list for the source, derived from the normalized event shape.
  app.get("/api/v1/sources/:id/schema", async (c) => {
    const id = c.req.param("id");
    if (!isKnownSource(id)) {
      return c.json({ error: `Unknown source: ${id}` }, 404);
    }
    return c.json({ schema: ocsfSchemaForSource(id) });
  });

  app.get("/api/v1/sources/:id/history", async (c) => {
    const id = c.req.param("id");
    const url = new URL(c.req.url);
    const tenant = url.searchParams.get("tenant") ?? undefined;
    const limit = parseHistoryLimit(url.searchParams.get("limit"));
    if (limit instanceof Error) return c.json({ error: limit.message }, 400);
    const status = await getSourceHealth(c.env.ALERT_STATE_DB, id, tenant);
    if (!status) return c.json({ error: `Source not found: ${id}` }, 404);
    const history = await listSourceHealthHistory(c.env.ALERT_STATE_DB, id, { tenant_id: tenant, limit });
    return c.json({ history });
  });

  app.get("/api/v1/sources/:id/errors", async (c) => {
    const id = c.req.param("id");
    const url = new URL(c.req.url);
    const tenant = url.searchParams.get("tenant") ?? undefined;
    const limit = parseHistoryLimit(url.searchParams.get("limit"));
    if (limit instanceof Error) return c.json({ error: limit.message }, 400);
    const status = await getSourceHealth(c.env.ALERT_STATE_DB, id, tenant);
    if (!status) return c.json({ error: `Source not found: ${id}` }, 404);
    const errors = await listSourceHealthHistory(c.env.ALERT_STATE_DB, id, {
      tenant_id: tenant,
      kind: "error",
      limit
    });
    return c.json({ errors });
  });

  // Recent events for the source via R2 SQL (LIMIT 10) through the async
  // query-job flow. Returns the same job response shape as POST /api/v1/query.
  app.get("/api/v1/sources/:id/sample", async (c) => {
    const id = c.req.param("id");
    if (!isKnownSource(id)) {
      return c.json({ error: `Unknown source: ${id}` }, 404);
    }

    const tableSuffix = c.env.PICKET_TABLE_SUFFIX || null;
    const sql = sampleQuery(id, tableSuffix);

    return submitQueryJob(c, queryDeps, {
      sql,
      preset: null,
      tableSuffix,
      idempotencyKey: null
    });
  });
}

function parseHistoryLimit(raw: string | null): number | undefined | Error {
  if (raw === null) return undefined;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 200) {
    return new Error("`limit` must be an integer between 1 and 200.");
  }
  return parsed;
}
