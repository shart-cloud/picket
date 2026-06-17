import type { Context, Hono } from "hono";

import {
  createOrGetQueryJob,
  failQueryJob,
  getQueryJob,
  type QueryJobRow,
  type QueryJobStatus
} from "@picket/core/query-jobs";
import {
  listQueryHistory,
  listSavedQueries,
  recordQueryHistory,
  saveQuery,
  SavedQueryNameRequiredError
} from "@picket/core/saved-queries";
import {
  buildNlSqlSystem,
  createAnthropicNlSqlClient,
  explainQuery,
  naturalLanguageToSql,
  NlSqlError,
  presetQuery,
  PRESET_QUERY_NAMES,
  validateR2Sql,
  type NlSqlClient,
  type PresetQueryName
} from "@picket/query";
import { OCSF_EVENT_FIELDS } from "@picket/core/sources";

import type { AdminEnv } from "./index";

interface QueryBody {
  preset?: unknown;
  sql?: unknown;
  hours?: unknown;
  limit?: unknown;
  table_suffix?: unknown;
  warehouse?: unknown;
  name?: unknown;
  description?: unknown;
  question?: unknown;
}

const PRESETS = new Set<PresetQueryName>(PRESET_QUERY_NAMES);

// How long the POST handler waits for the runner to finish before returning
// 202 + the polling location. 22s leaves headroom below the 30s Workers CPU
// limit; the request stays alive longer than that since we're sleeping on
// D1 reads, but we want a clean budget.
const LONG_POLL_MS = 22_000;
const LONG_POLL_INTERVAL_MS = 500;

export interface QueryRoutesOptions {
  uuid?: () => string;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
  // Tests inject a fake NL→SQL client; production builds the Anthropic client
  // from env.ANTHROPIC_API_KEY.
  nlSqlClient?: NlSqlClient;
}

// Source event tables advertised to the NL→SQL model (uniform OCSF schema).
const NL_QUERY_TABLES = ["aws_cloudtrail", "kubernetes_audit", "cloudflare_audit"];
const MAX_QUESTION_LENGTH = 2000;

export interface ResolvedQueryDeps {
  newId: () => string;
  now: () => Date;
  sleep: (ms: number) => Promise<void>;
}

export function resolveQueryDeps(options: QueryRoutesOptions = {}): ResolvedQueryDeps {
  return {
    newId: options.uuid ?? (() => crypto.randomUUID()),
    now: options.now ?? (() => new Date()),
    sleep: options.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)))
  };
}

// Create + enqueue a query job for an already-resolved SQL string, then long-poll
// for completion. Shared by POST /api/v1/query and the per-source /sample
// endpoint. Returns 200 with the finished job, or 202 + a polling location when
// the job is still running past the long-poll budget.
export async function submitQueryJob(
  c: Context<{ Bindings: AdminEnv }>,
  deps: ResolvedQueryDeps,
  args: {
    sql: string;
    preset: string | null;
    tableSuffix: string | null;
    idempotencyKey: string | null;
    warehouse?: string;
    owner?: string | null;
    // Extra fields merged into the JSON response (e.g. the NL-generated SQL).
    extra?: Record<string, unknown>;
  }
): Promise<Response> {
  const { newId, now, sleep } = deps;

  const warehouse = args.warehouse ?? c.env.PICKET_R2_WAREHOUSE;
  if (!warehouse) {
    return c.json(
      { error: "No warehouse configured. Set PICKET_R2_WAREHOUSE on the Worker or pass `warehouse` in the body." },
      500
    );
  }

  const requestedBy = resolveRequestedBy(c);

  const { job, created } = await createOrGetQueryJob(c.env.ALERT_STATE_DB, {
    id: newId(),
    idempotency_key: args.idempotencyKey,
    sql: args.sql,
    warehouse,
    requested_by: requestedBy,
    tenant_id: null, // TODO: thread tenant once Access JWT exposes it
    preset: args.preset,
    table_suffix: args.tableSuffix,
    now: now().toISOString()
  });

  if (created) {
    if (!c.env.QUERY_JOBS_QUEUE) {
      await failQueryJob(c.env.ALERT_STATE_DB, {
        id: job.id,
        now: now().toISOString(),
        error: "QUERY_JOBS_QUEUE binding missing on picket-admin"
      });
      return c.json({ error: "Query queue not configured on the server." }, 500);
    }
    await c.env.QUERY_JOBS_QUEUE.send({ job_id: job.id });

    // Log the submission to query_history (best-effort; never blocks the request).
    await recordHistoryBestEffort(c, {
      id: newId(),
      owner: args.owner ?? requestedBy,
      sql: args.sql,
      preset: args.preset,
      job_id: job.id
    });
  }

  const completed = await pollUntilDone(c.env.ALERT_STATE_DB, job.id, sleep, now);
  if (completed) return c.json({ ...toJobResponse(completed), ...args.extra }, 200);

  return c.json(
    {
      id: job.id,
      status: job.status,
      location: `/api/v1/query/${job.id}`,
      idempotency_key: args.idempotencyKey,
      ...args.extra
    },
    202
  );
}

// Resolve the body of a query request into a concrete SQL string, expanding a
// preset or validating raw SQL. Shared by POST /query, /query/save, and
// /query/explain. Returns either the resolved SQL or an error response to send.
type SqlResolution =
  | { ok: true; sql: string; preset: string | null; tableSuffix: string | null }
  | { ok: false; status: 400; body: Record<string, unknown> };

function resolveQuerySql(c: Context<{ Bindings: AdminEnv }>, body: QueryBody): SqlResolution {
  const preset = typeof body.preset === "string" ? body.preset : undefined;
  const rawSql = typeof body.sql === "string" ? body.sql : undefined;

  if (preset && rawSql !== undefined) {
    return { ok: false, status: 400, body: { error: "`preset` and `sql` are mutually exclusive." } };
  }
  if (!preset && rawSql === undefined) {
    return { ok: false, status: 400, body: { error: "Provide either `preset` or `sql`." } };
  }

  const hours = optionalPositiveInt(body.hours, "hours");
  const limit = optionalPositiveInt(body.limit, "limit");
  if (hours instanceof Error) return { ok: false, status: 400, body: { error: hours.message } };
  if (limit instanceof Error) return { ok: false, status: 400, body: { error: limit.message } };
  if ((hours !== undefined || limit !== undefined) && rawSql !== undefined) {
    return { ok: false, status: 400, body: { error: "`hours` and `limit` are only valid with `preset`." } };
  }

  const tableSuffix =
    typeof body.table_suffix === "string" && body.table_suffix.length > 0
      ? body.table_suffix
      : c.env.PICKET_TABLE_SUFFIX || null;

  if (preset) {
    if (!PRESETS.has(preset as PresetQueryName)) {
      return { ok: false, status: 400, body: { error: `Unknown preset. Available: ${[...PRESETS].join(", ")}` } };
    }
    const sql = presetQuery(preset as PresetQueryName, { hours, limit, tableSuffix: tableSuffix ?? undefined });
    return { ok: true, sql, preset, tableSuffix };
  }

  const validation = validateR2Sql(rawSql as string);
  if (!validation.valid) {
    return { ok: false, status: 400, body: { error: "Query rejected", details: validation.errors } };
  }
  return { ok: true, sql: rawSql as string, preset: null, tableSuffix };
}

export function registerQueryRoutes(
  app: Hono<{ Bindings: AdminEnv }>,
  options: QueryRoutesOptions = {}
): void {
  const deps = resolveQueryDeps(options);

  app.post("/api/v1/query", async (c) => {
    const body = await readQueryBody(c);
    const resolved = resolveQuerySql(c, body);
    if (!resolved.ok) return c.json(resolved.body, resolved.status);

    // Per-request warehouse override stays a POST-only affordance.
    const bodyWarehouse =
      typeof body.warehouse === "string" && body.warehouse.length > 0 ? body.warehouse : undefined;

    const idempotencyKey = c.req.header("idempotency-key") ?? null;
    return submitQueryJob(c, deps, {
      sql: resolved.sql,
      preset: resolved.preset,
      tableSuffix: resolved.tableSuffix,
      idempotencyKey,
      warehouse: bodyWarehouse,
      owner: resolveRequestedBy(c)
    });
  });

  // Natural-language → R2 SQL (Milestone 4). Generate a query with Claude,
  // validate it, then run it through the same async job flow. Returns the
  // generated SQL (for transparency) alongside the job/results.
  app.post("/api/v1/query/natural", async (c) => {
    const body = await readQueryBody(c);
    const question = typeof body.question === "string" ? body.question.trim() : "";
    if (question.length === 0) {
      return c.json({ error: "Request body must include a non-empty `question`." }, 400);
    }
    if (question.length > MAX_QUESTION_LENGTH) {
      return c.json({ error: `\`question\` must be at most ${MAX_QUESTION_LENGTH} characters.` }, 400);
    }

    const client = options.nlSqlClient ?? buildNlSqlClient(c);
    if (!client) {
      return c.json({ error: "Natural-language query is not configured (ANTHROPIC_API_KEY missing)." }, 500);
    }

    const tableSuffix = c.env.PICKET_TABLE_SUFFIX || null;
    const tables = NL_QUERY_TABLES.map((table) => (tableSuffix ? `${table}_${tableSuffix}` : table));
    const system = buildNlSqlSystem({ fields: OCSF_EVENT_FIELDS, tables });

    let generated: Awaited<ReturnType<typeof naturalLanguageToSql>>;
    try {
      generated = await naturalLanguageToSql(client, { system, question }, validateR2Sql);
    } catch (error) {
      if (error instanceof NlSqlError) return c.json({ error: error.message }, 502);
      throw error;
    }

    if (!generated.valid) {
      return c.json(
        { error: "Generated query was rejected by validation.", generated_sql: generated.sql, details: generated.errors },
        422
      );
    }

    return submitQueryJob(c, deps, {
      sql: generated.sql,
      preset: null,
      tableSuffix,
      idempotencyKey: null,
      owner: resolveRequestedBy(c),
      extra: { generated_sql: generated.sql, rationale: generated.rationale ?? null }
    });
  });

  // Validate + plan a query without executing it.
  app.post("/api/v1/query/explain", async (c) => {
    const body = await readQueryBody(c);
    const resolved = resolveQuerySql(c, body);
    if (!resolved.ok) return c.json(resolved.body, resolved.status);
    return c.json({ explain: explainQuery(resolved.sql) });
  });

  // Save a named, reusable query (upsert by owner+name).
  app.post("/api/v1/query/save", async (c) => {
    const body = await readQueryBody(c);
    const name = typeof body.name === "string" ? body.name : "";
    if (name.trim().length === 0) {
      return c.json({ error: "Request body must include a non-empty `name`." }, 400);
    }
    const resolved = resolveQuerySql(c, body);
    if (!resolved.ok) return c.json(resolved.body, resolved.status);

    try {
      const saved = await saveQuery(c.env.ALERT_STATE_DB, {
        id: deps.newId(),
        owner: resolveRequestedBy(c) ?? "unknown",
        name,
        description: typeof body.description === "string" ? body.description : null,
        sql: resolved.sql,
        preset: resolved.preset
      });
      return c.json({ saved }, 201);
    } catch (error) {
      if (error instanceof SavedQueryNameRequiredError) return c.json({ error: error.message }, 400);
      throw error;
    }
  });

  app.get("/api/v1/query/saved", async (c) => {
    const url = new URL(c.req.url);
    const owner = url.searchParams.get("owner") ?? undefined;
    const limit = parseLimitParam(url.searchParams.get("limit"));
    if (limit instanceof Error) return c.json({ error: limit.message }, 400);
    const saved = await listSavedQueries(c.env.ALERT_STATE_DB, { owner, limit });
    return c.json({ saved });
  });

  app.get("/api/v1/query/history", async (c) => {
    const url = new URL(c.req.url);
    const owner = url.searchParams.get("owner") ?? undefined;
    const limit = parseLimitParam(url.searchParams.get("limit"));
    if (limit instanceof Error) return c.json({ error: limit.message }, 400);
    const history = await listQueryHistory(c.env.ALERT_STATE_DB, { owner, limit });
    return c.json({ history });
  });

  app.get("/api/v1/query/:id", async (c) => {
    const job = await getQueryJob(c.env.ALERT_STATE_DB, c.req.param("id"));
    if (!job) return c.json({ error: "Job not found" }, 404);
    return c.json(toJobResponse(job));
  });
}

function buildNlSqlClient(c: Context<{ Bindings: AdminEnv }>): NlSqlClient | null {
  if (!c.env.ANTHROPIC_API_KEY) return null;
  return createAnthropicNlSqlClient({
    apiKey: c.env.ANTHROPIC_API_KEY,
    model: c.env.PICKET_NL_QUERY_MODEL || undefined
  });
}

function parseLimitParam(raw: string | null): number | undefined | Error {
  if (raw === null) return undefined;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) return new Error("`limit` must be a positive integer.");
  return parsed;
}

// Best-effort query-history write. Never throws into the request path.
async function recordHistoryBestEffort(
  c: Context<{ Bindings: AdminEnv }>,
  input: { id: string; owner: string | null; sql: string; preset: string | null; job_id: string | null }
): Promise<void> {
  try {
    await recordQueryHistory(c.env.ALERT_STATE_DB, input);
  } catch (error) {
    console.log(
      JSON.stringify({ message: "query-history write failed", error: error instanceof Error ? error.message : String(error) })
    );
  }
}

async function pollUntilDone(
  db: D1Database,
  id: string,
  sleep: (ms: number) => Promise<void>,
  now: () => Date
): Promise<QueryJobRow | null> {
  const deadline = now().getTime() + LONG_POLL_MS;
  for (;;) {
    const row = await getQueryJob(db, id);
    if (row && (row.status === "succeeded" || row.status === "failed")) return row;
    if (now().getTime() >= deadline) return null;
    await sleep(LONG_POLL_INTERVAL_MS);
  }
}

interface QueryJobResponse {
  id: string;
  status: QueryJobStatus;
  preset: string | null;
  warehouse: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  bytes_scanned: number | null;
  files_scanned: number | null;
  row_count: number | null;
  result?: unknown;
  error?: string;
}

function toJobResponse(row: QueryJobRow): QueryJobResponse {
  const base: QueryJobResponse = {
    id: row.id,
    status: row.status,
    preset: row.preset,
    warehouse: row.warehouse,
    created_at: row.created_at,
    started_at: row.started_at,
    finished_at: row.finished_at,
    bytes_scanned: row.bytes_scanned,
    files_scanned: row.files_scanned,
    row_count: row.row_count
  };
  if (row.status === "succeeded" && row.result_json) {
    try {
      base.result = JSON.parse(row.result_json);
    } catch {
      base.error = "result JSON corrupt";
    }
  }
  if (row.status === "failed" && row.error_message) base.error = row.error_message;
  return base;
}

function resolveRequestedBy(c: Context<{ Bindings: AdminEnv }>): string | null {
  const session = c.get("sessionUser");
  if (session?.email) return session.email;
  if (session?.id) return session.id;
  const access = c.get("accessUser");
  if (access?.email) return access.email;
  if (access?.sub) return access.sub;
  return null;
}

async function readQueryBody(c: Context<{ Bindings: AdminEnv }>): Promise<QueryBody> {
  const contentType = c.req.header("content-type") ?? "";
  if (!contentType.includes("application/json")) return {};
  try {
    const parsed = (await c.req.raw.clone().json()) as unknown;
    return parsed && typeof parsed === "object" ? (parsed as QueryBody) : {};
  } catch {
    return {};
  }
}

function optionalPositiveInt(value: unknown, name: string): number | undefined | Error {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
    return new Error(`\`${name}\` must be a positive integer.`);
  }
  return value;
}
