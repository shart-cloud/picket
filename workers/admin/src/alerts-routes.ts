import type { Context, Hono } from "hono";

import {
  acknowledgeAlert,
  addAlertNote,
  alertStats,
  ALERT_SEVERITIES,
  ALERT_STATUSES,
  AlertAlreadyOpenError,
  AlertNotFoundError,
  AlertNoteBodyRequiredError,
  assignAlert,
  countAlerts,
  getAlertWithHistory,
  listAlerts,
  reopenAlert,
  resolveAlert,
  type AlertSeverity,
  type AlertSortDirection,
  type AlertSortField,
  type AlertStatus
} from "@picket/core/alerts";

import type { AdminEnv } from "./index";

const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 200;
const MAX_OFFSET = 1_000_000;
const ALERT_SORT_FIELDS = ["last_seen", "severity", "match_count"] as const satisfies readonly AlertSortField[];
const ALERT_SORT_DIRECTIONS = ["asc", "desc"] as const satisfies readonly AlertSortDirection[];

interface ActorBody {
  by?: unknown;
  body?: unknown;
  status?: unknown;
  assignee?: unknown;
  ids?: unknown;
}

export function registerAlertsRoutes(app: Hono<{ Bindings: AdminEnv }>): void {
  app.get("/api/v1/alerts", async (c) => {
    const url = new URL(c.req.url);
    const status = url.searchParams.get("status");
    const severity = url.searchParams.get("severity");
    const ruleId = url.searchParams.get("rule_id") ?? url.searchParams.get("rule");
    const source = url.searchParams.get("source");
    const startTime = url.searchParams.get("start_time") ?? url.searchParams.get("from");
    const endTime = url.searchParams.get("end_time") ?? url.searchParams.get("to");
    const limitParam = url.searchParams.get("limit");
    const offsetParam = url.searchParams.get("offset");
    const sortParam = url.searchParams.get("sort");
    const directionParam = url.searchParams.get("direction");

    if (status && !(ALERT_STATUSES as readonly string[]).includes(status)) {
      return c.json({ error: `Invalid status. Must be one of: ${ALERT_STATUSES.join(", ")}` }, 400);
    }
    if (severity && !(ALERT_SEVERITIES as readonly string[]).includes(severity)) {
      return c.json({ error: `Invalid severity. Must be one of: ${ALERT_SEVERITIES.join(", ")}` }, 400);
    }
    if (startTime && Number.isNaN(Date.parse(startTime))) {
      return c.json({ error: "Invalid start_time/from. Must be an ISO-8601 timestamp." }, 400);
    }
    if (endTime && Number.isNaN(Date.parse(endTime))) {
      return c.json({ error: "Invalid end_time/to. Must be an ISO-8601 timestamp." }, 400);
    }

    let limit = DEFAULT_LIMIT;
    if (limitParam !== null) {
      const parsed = Number(limitParam);
      if (!Number.isInteger(parsed) || parsed <= 0 || parsed > MAX_LIMIT) {
        return c.json({ error: `Invalid limit. Must be an integer in [1, ${MAX_LIMIT}].` }, 400);
      }
      limit = parsed;
    }

    let offset = 0;
    if (offsetParam !== null) {
      const parsed = Number(offsetParam);
      if (!Number.isInteger(parsed) || parsed < 0 || parsed > MAX_OFFSET) {
        return c.json({ error: `Invalid offset. Must be an integer in [0, ${MAX_OFFSET}].` }, 400);
      }
      offset = parsed;
    }
    if (sortParam && !(ALERT_SORT_FIELDS as readonly string[]).includes(sortParam)) {
      return c.json({ error: `Invalid sort. Must be one of: ${ALERT_SORT_FIELDS.join(", ")}` }, 400);
    }
    if (directionParam && !(ALERT_SORT_DIRECTIONS as readonly string[]).includes(directionParam)) {
      return c.json({ error: `Invalid direction. Must be one of: ${ALERT_SORT_DIRECTIONS.join(", ")}` }, 400);
    }

    const filters = {
      status: (status as AlertStatus | null) ?? undefined,
      severity: (severity as AlertSeverity | null) ?? undefined,
      rule_id: ruleId ?? undefined,
      source: source ?? undefined,
      start_time: startTime ?? undefined,
      end_time: endTime ?? undefined
    };
    const [alerts, total] = await Promise.all([
      listAlerts(c.env.ALERT_STATE_DB, {
        ...filters,
        limit,
        offset,
        sort: (sortParam as AlertSortField | null) ?? undefined,
        direction: (directionParam as AlertSortDirection | null) ?? undefined
      }),
      countAlerts(c.env.ALERT_STATE_DB, filters)
    ]);

    return c.json({ alerts, total, limit, offset });
  });

  // Registered before `/:id` so "stats" isn't captured as an alert id.
  app.get("/api/v1/alerts/stats", async (c) => {
    const stats = await alertStats(c.env.ALERT_STATE_DB);
    return c.json({ stats });
  });

  app.patch("/api/v1/alerts/bulk", async (c) => {
    const body = await readActorBody(c.req.raw.clone());
    if (!Array.isArray(body.ids) || body.ids.length === 0 || body.ids.length > 100) {
      return c.json({ error: "`ids` must be an array containing 1 to 100 alert ids." }, 400);
    }
    const ids = [...new Set(body.ids.filter((id): id is string => typeof id === "string" && id.trim().length > 0).map((id) => id.trim()))];
    if (ids.length !== body.ids.length) {
      return c.json({ error: "Every alert id must be a unique, non-empty string." }, 400);
    }
    if (body.status !== "acknowledged" && body.status !== "resolved") {
      return c.json({ error: "Bulk status must be `acknowledged` or `resolved`." }, 400);
    }

    const missing = [];
    for (const id of ids) {
      const row = await c.env.ALERT_STATE_DB.prepare("SELECT id FROM alerts WHERE id = ?").bind(id).first<{ id: string }>();
      if (!row) missing.push(id);
    }
    if (missing.length > 0) return c.json({ error: "Some alerts were not found.", missing }, 404);

    const actor = resolveActorFromBody(c, body);
    const alerts = [];
    for (const id of ids) {
      alerts.push(
        body.status === "acknowledged"
          ? await acknowledgeAlert(c.env.ALERT_STATE_DB, id, actor)
          : await resolveAlert(c.env.ALERT_STATE_DB, id, actor)
      );
    }
    return c.json({ alerts, updated_by: actor });
  });

  app.get("/api/v1/alerts/:id", async (c) => {
    try {
      const detail = await getAlertWithHistory(c.env.ALERT_STATE_DB, c.req.param("id"));
      return c.json(detail);
    } catch (error) {
      if (error instanceof AlertNotFoundError) return c.json({ error: error.message }, 404);
      throw error;
    }
  });

  app.post("/api/v1/alerts/:id/ack", async (c) => {
    const actor = await resolveActor(c);
    try {
      const alert = await acknowledgeAlert(c.env.ALERT_STATE_DB, c.req.param("id"), actor);
      return c.json({ alert, acknowledged_by: actor });
    } catch (error) {
      if (error instanceof AlertNotFoundError) return c.json({ error: error.message }, 404);
      throw error;
    }
  });

  app.post("/api/v1/alerts/:id/resolve", async (c) => {
    const actor = await resolveActor(c);
    try {
      const alert = await resolveAlert(c.env.ALERT_STATE_DB, c.req.param("id"), actor);
      return c.json({ alert, resolved_by: actor });
    } catch (error) {
      if (error instanceof AlertNotFoundError) return c.json({ error: error.message }, 404);
      throw error;
    }
  });

  app.post("/api/v1/alerts/:id/reopen", async (c) => {
    const actor = await resolveActor(c);
    try {
      const alert = await reopenAlert(c.env.ALERT_STATE_DB, c.req.param("id"), actor);
      return c.json({ alert, reopened_by: actor });
    } catch (error) {
      if (error instanceof AlertNotFoundError) return c.json({ error: error.message }, 404);
      if (error instanceof AlertAlreadyOpenError) return c.json({ error: error.message }, 409);
      throw error;
    }
  });

  // Unified mutation endpoint (PRD Phase 1): change status and/or assignee in one
  // call. The status verbs reuse the existing ack/resolve/reopen transitions.
  app.patch("/api/v1/alerts/:id", async (c) => {
    const id = c.req.param("id");
    const body = await readActorBody(c.req.raw.clone());
    const actor = resolveActorFromBody(c, body);

    const hasStatus = body.status !== undefined;
    const hasAssignee = body.assignee !== undefined;
    if (!hasStatus && !hasAssignee) {
      return c.json({ error: "Request body must include `status` and/or `assignee`." }, 400);
    }
    if (hasStatus && !(ALERT_STATUSES as readonly string[]).includes(String(body.status))) {
      return c.json({ error: `Invalid status. Must be one of: ${ALERT_STATUSES.join(", ")}` }, 400);
    }
    if (hasAssignee && body.assignee !== null && typeof body.assignee !== "string") {
      return c.json({ error: "`assignee` must be a string or null." }, 400);
    }

    try {
      if (hasStatus) {
        const status = body.status as AlertStatus;
        if (status === "acknowledged") await acknowledgeAlert(c.env.ALERT_STATE_DB, id, actor);
        else if (status === "resolved") await resolveAlert(c.env.ALERT_STATE_DB, id, actor);
        else if (status === "open") await reopenAlert(c.env.ALERT_STATE_DB, id, actor);
      }
      if (hasAssignee) {
        await assignAlert(c.env.ALERT_STATE_DB, id, body.assignee as string | null, actor);
      }
      const detail = await getAlertWithHistory(c.env.ALERT_STATE_DB, id);
      return c.json({ alert: detail.alert, updated_by: actor });
    } catch (error) {
      if (error instanceof AlertNotFoundError) return c.json({ error: error.message }, 404);
      if (error instanceof AlertAlreadyOpenError) return c.json({ error: error.message }, 409);
      throw error;
    }
  });

  app.post("/api/v1/alerts/:id/notes", async (c) => {
    const body = await readActorBody(c.req.raw.clone());
    const noteBody = typeof body.body === "string" ? body.body : "";
    if (noteBody.trim().length === 0) {
      return c.json({ error: "Request body must include a non-empty `body` string." }, 400);
    }
    const actor = resolveActorFromBody(c, body);
    try {
      const note = await addAlertNote(c.env.ALERT_STATE_DB, c.req.param("id"), noteBody, actor);
      return c.json({ note, author: actor }, 201);
    } catch (error) {
      if (error instanceof AlertNotFoundError) return c.json({ error: error.message }, 404);
      if (error instanceof AlertNoteBodyRequiredError) return c.json({ error: error.message }, 400);
      throw error;
    }
  });
}

async function resolveActor(c: Context<{ Bindings: AdminEnv }>): Promise<string> {
  const body = await readActorBody(c.req.raw.clone());
  return resolveActorFromBody(c, body);
}

function resolveActorFromBody(c: Context<{ Bindings: AdminEnv }>, body: ActorBody): string {
  if (typeof body.by === "string" && body.by.trim().length > 0) return body.by.trim();
  const sessionUser = c.get("sessionUser");
  if (sessionUser?.email) return sessionUser.email;
  if (sessionUser?.id) return sessionUser.id;
  return "admin";
}

async function readActorBody(request: Request): Promise<ActorBody> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) return {};
  try {
    const parsed = (await request.json()) as unknown;
    if (parsed && typeof parsed === "object") return parsed as ActorBody;
    return {};
  } catch {
    return {};
  }
}
