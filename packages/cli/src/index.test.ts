import { describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  acknowledgeAlert,
  addAlertNote,
  alertStats,
  assignAlert,
  getAlertWithHistory,
  listAlerts,
  reopenAlert,
  resolveAlert,
  type AlertRow,
  type AlertSeverity,
  type AlertStatus
} from "@picket/core/alerts";
import { FakeAlertDb, type FakeAlertRow } from "@picket/core/alerts-fake-db";
import { classifySourceHealth, getSourceHealth, listSourceHealth } from "@picket/core/source-health";
import { buildDashboardOverview } from "@picket/core/dashboard";
import { isKnownSource, ocsfSchemaForSource } from "@picket/core/sources";
import { getDetectionHealth } from "@picket/core/detection-health";
import { listScheduledDetections } from "@picket/core/scheduled-detection";
import {
  getDetectionRule,
  listDetectionRules,
  seedDetectionRules,
  setDetectionRuleEnabled
} from "@picket/core/detection-rules";
import {
  deleteIoc,
  isIndicatorType,
  listIocs,
  putIocs,
  type IndicatorType,
  type IocKvNamespace,
  type IocMetadata,
  type IocRecord
} from "@picket/core/enrichment";
import { explainQuery, presetQuery, type R2SqlResult } from "@picket/query";
import {
  listQueryHistory,
  listSavedQueries,
  saveQuery,
  type SavedQueryRow
} from "@picket/core/saved-queries";
import { AdminClient, type QueryJob } from "./admin-client.js";
import type { CredentialRecord, CredentialsIo, CredentialsStore } from "./auth/credentials.js";
import type { CloudflaredRunner } from "./auth/cloudflared.js";
import { main, type MainOptions } from "./index.js";

interface FakeRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
  bodyText?: string;
}

interface FakeResponse {
  status: number;
  body: unknown;
}

function fakeFetch(handler: (req: FakeRequest) => FakeResponse | Promise<FakeResponse>) {
  const calls: FakeRequest[] = [];
  const fn: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const method = init?.method ?? "GET";
    const headerEntries: [string, string][] = [];
    const rawHeaders = init?.headers;
    if (rawHeaders) {
      if (rawHeaders instanceof Headers) {
        rawHeaders.forEach((v, k) => headerEntries.push([k.toLowerCase(), v]));
      } else if (Array.isArray(rawHeaders)) {
        for (const [k, v] of rawHeaders) headerEntries.push([k.toLowerCase(), v]);
      } else {
        for (const [k, v] of Object.entries(rawHeaders)) headerEntries.push([k.toLowerCase(), String(v)]);
      }
    }
    const headers = Object.fromEntries(headerEntries);
    const bodyText = typeof init?.body === "string" ? init.body : undefined;
    const body = bodyText && headers["content-type"]?.includes("application/json") ? JSON.parse(bodyText) : undefined;
    const req: FakeRequest = { url, method, headers, body, bodyText };
    calls.push(req);
    const res = await handler(req);
    return new Response(JSON.stringify(res.body), {
      status: res.status,
      headers: { "content-type": "application/json" }
    });
  };
  return { fetch: fn, calls };
}

function makeJob(overrides: Partial<QueryJob> & { id: string; status: QueryJob["status"] }): QueryJob {
  return {
    preset: null,
    warehouse: "test-warehouse",
    created_at: "2026-05-27T00:00:00.000Z",
    started_at: null,
    finished_at: null,
    bytes_scanned: null,
    files_scanned: null,
    row_count: null,
    ...overrides
  };
}

function makeAdminClient(
  handler: (req: FakeRequest) => FakeResponse | Promise<FakeResponse>,
  overrides: { uuid?: () => string } = {}
) {
  const fetched = fakeFetch(handler);
  const client = new AdminClient({
    baseUrl: "https://test.example",
    fetch: fetched.fetch,
    uuid: overrides.uuid ?? (() => "uuid-fixed"),
    sleep: async () => undefined,
    pollInitialMs: 0,
    pollMaxMs: 0,
    pollBackoff: 1,
    pollDeadlineMs: 1_000
  });
  return { client, calls: fetched.calls };
}

function makeFakeIocKv(): IocKvNamespace {
  const store = new Map<string, { value: string; metadata?: IocMetadata }>();
  return {
    async get(key) {
      return store.get(key)?.value ?? null;
    },
    async put(key, value, options) {
      store.set(key, { value, metadata: options?.metadata });
    },
    async delete(key) {
      store.delete(key);
    },
    async list(options) {
      const prefix = options?.prefix ?? "";
      const all = [...store.entries()].filter(([name]) => name.startsWith(prefix));
      return {
        keys: all.map(([name, entry]) => ({ name, metadata: entry.metadata })),
        list_complete: true
      };
    }
  };
}

function makeApiBackedAdminClient(db: FakeAlertDb, opts: { now?: Date; iocKv?: IocKvNamespace } = {}) {
  const now = opts.now ?? new Date("2026-05-27T12:10:00.000Z");
  const iocKv = opts.iocKv ?? makeFakeIocKv();
  const { client } = makeAdminClient(async (req) => {
    const url = new URL(req.url);
    const path = url.pathname;

    if (req.method === "GET" && path === "/api/v1/dashboard/overview") {
      const tenant = url.searchParams.get("tenant") ?? undefined;
      const overview = await buildDashboardOverview(db, { now, tenant_id: tenant });
      return { status: 200, body: { overview } };
    }

    if (req.method === "GET" && path === "/api/v1/alerts") {
      const status = url.searchParams.get("status") as AlertStatus | null;
      const severity = url.searchParams.get("severity") as AlertSeverity | null;
      const limit = Number(url.searchParams.get("limit") ?? "20");
      const alerts = await listAlerts(db, {
        status: status ?? undefined,
        severity: severity ?? undefined,
        limit
      });
      return { status: 200, body: { alerts } };
    }

    if (req.method === "GET" && path === "/api/v1/alerts/stats") {
      return { status: 200, body: { stats: await alertStats(db) } };
    }

    const alertMatch = path.match(/^\/api\/v1\/alerts\/([^/]+)(?:\/(ack|resolve|reopen|notes))?$/);
    if (alertMatch) {
      const id = decodeURIComponent(alertMatch[1] ?? "");
      const action = alertMatch[2];
      const body = (req.body && typeof req.body === "object" ? req.body : {}) as {
        by?: string;
        body?: string;
        status?: AlertStatus;
        assignee?: string | null;
      };
      try {
        if (req.method === "GET" && !action) {
          return { status: 200, body: await getAlertWithHistory(db, id) };
        }
        if (req.method === "PATCH" && !action) {
          const by = body.by ?? "admin";
          if (body.status === "acknowledged") await acknowledgeAlert(db, id, by);
          else if (body.status === "resolved") await resolveAlert(db, id, by);
          else if (body.status === "open") await reopenAlert(db, id, by);
          if (body.assignee !== undefined) await assignAlert(db, id, body.assignee, by);
          return { status: 200, body: { alert: (await getAlertWithHistory(db, id)).alert, updated_by: by } };
        }
        if (req.method === "POST" && action === "ack") {
          const by = body.by ?? "admin";
          return { status: 200, body: { alert: await acknowledgeAlert(db, id, by), acknowledged_by: by } };
        }
        if (req.method === "POST" && action === "resolve") {
          const by = body.by ?? "admin";
          return { status: 200, body: { alert: await resolveAlert(db, id, by), resolved_by: by } };
        }
        if (req.method === "POST" && action === "reopen") {
          const by = body.by ?? "admin";
          return { status: 200, body: { alert: await reopenAlert(db, id, by), reopened_by: by } };
        }
        if (req.method === "POST" && action === "notes") {
          const by = body.by ?? "admin";
          return { status: 201, body: { note: await addAlertNote(db, id, body.body ?? "", by), author: by } };
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return { status: message.includes("already open") ? 409 : message.includes("non-empty") ? 400 : 404, body: { error: message } };
      }
    }

    if (req.method === "GET" && path === "/api/v1/detections/health") {
      return { status: 200, body: { detection_health: await getDetectionHealth(db) } };
    }

    if (req.method === "GET" && path === "/api/v1/detections/scheduled") {
      return { status: 200, body: { scheduled: await listScheduledDetections(db, now) } };
    }

    if (req.method === "GET" && path === "/api/v1/detections") {
      const enabledParam = url.searchParams.get("enabled");
      const source = url.searchParams.get("source") ?? undefined;
      const rules = await listDetectionRules(db, {
        enabled: enabledParam === null ? undefined : enabledParam === "true",
        source
      });
      return { status: 200, body: { rules } };
    }

    const detectionMatch = path.match(/^\/api\/v1\/detections\/([^/]+)$/);
    if (detectionMatch && detectionMatch[1] !== "health") {
      const id = decodeURIComponent(detectionMatch[1] ?? "");
      if (req.method === "GET") {
        const rule = await getDetectionRule(db, id);
        if (!rule) return { status: 404, body: { error: `Detection rule not found: ${id}` } };
        return { status: 200, body: { rule } };
      }
      if (req.method === "PATCH") {
        const enabled = (req.body as { enabled?: boolean })?.enabled;
        try {
          const rule = await setDetectionRuleEnabled(db, id, Boolean(enabled));
          return { status: 200, body: { rule } };
        } catch {
          return { status: 404, body: { error: `Detection rule not found: ${id}` } };
        }
      }
    }

    if (req.method === "GET" && path === "/api/v1/sources") {
      const tenant = url.searchParams.get("tenant") ?? undefined;
      const source = url.searchParams.get("source");
      const rows = await listSourceHealth(db, tenant ? { tenant_id: tenant } : {});
      const sources = source ? rows.filter((row) => row.source === source) : rows;
      if (source && sources.length === 0) return { status: 404, body: { error: `Source not found: ${source}` } };
      return { status: 200, body: { sources } };
    }

    if (req.method === "POST" && path === "/api/v1/query/explain") {
      const b = (req.body ?? {}) as { preset?: string; sql?: string; hours?: number; limit?: number; table_suffix?: string };
      const sql = b.sql ?? presetQuery(b.preset as never, { hours: b.hours, limit: b.limit, tableSuffix: b.table_suffix });
      return { status: 200, body: { explain: explainQuery(sql) } };
    }

    if (req.method === "POST" && path === "/api/v1/query/save") {
      const b = (req.body ?? {}) as { name?: string; description?: string; preset?: string; sql?: string; hours?: number; limit?: number; table_suffix?: string };
      if (!b.name || b.name.trim().length === 0) return { status: 400, body: { error: "name required" } };
      const sql = b.sql ?? presetQuery(b.preset as never, { hours: b.hours, limit: b.limit, tableSuffix: b.table_suffix });
      const saved = await saveQuery(db, {
        id: `sq-${db.savedQueries.length + 1}`,
        owner: "admin",
        name: b.name,
        description: b.description ?? null,
        sql,
        preset: b.preset ?? null
      });
      return { status: 201, body: { saved } };
    }

    if (req.method === "GET" && path === "/api/v1/query/saved") {
      const owner = url.searchParams.get("owner") ?? undefined;
      const limit = url.searchParams.get("limit");
      const saved = await listSavedQueries(db, { owner, limit: limit ? Number(limit) : undefined });
      return { status: 200, body: { saved } };
    }

    if (req.method === "GET" && path === "/api/v1/query/history") {
      const owner = url.searchParams.get("owner") ?? undefined;
      const limit = url.searchParams.get("limit");
      const history = await listQueryHistory(db, { owner, limit: limit ? Number(limit) : undefined });
      return { status: 200, body: { history } };
    }

    const sourceItemMatch = path.match(/^\/api\/v1\/sources\/([^/]+)\/(status|schema|sample)$/);
    if (req.method === "GET" && sourceItemMatch) {
      const id = decodeURIComponent(sourceItemMatch[1] ?? "");
      const kind = sourceItemMatch[2];
      if (kind === "status") {
        const tenant = url.searchParams.get("tenant") ?? undefined;
        const row = await getSourceHealth(db, id, tenant);
        if (!row) return { status: 404, body: { error: `Source not found: ${id}` } };
        return { status: 200, body: { status: { ...row, health: classifySourceHealth(row, now) } } };
      }
      if (kind === "schema") {
        if (!isKnownSource(id)) return { status: 404, body: { error: `Unknown source: ${id}` } };
        return { status: 200, body: { schema: ocsfSchemaForSource(id) } };
      }
      // sample: synthesize a completed job (the real query-job flow is covered
      // by @picket/core/query-jobs + the admin worker tests).
      if (!isKnownSource(id)) return { status: 404, body: { error: `Unknown source: ${id}` } };
      const result: R2SqlResult = {
        columns: ["time", "actor_user_uid"],
        rows: [{ time: "2026-05-27T10:00:00Z", actor_user_uid: "u1" }]
      };
      return {
        status: 200,
        body: makeJob({
          id: `sample-${id}`,
          status: "succeeded",
          preset: null,
          result,
          row_count: 1
        })
      };
    }

    if (req.method === "GET" && path === "/api/v1/enrichment/iocs") {
      const typeParam = url.searchParams.get("type");
      if (typeParam !== null && !isIndicatorType(typeParam)) {
        return { status: 400, body: { error: `Invalid indicator type: ${typeParam}` } };
      }
      const limit = url.searchParams.get("limit");
      const iocs = await listIocs(iocKv, {
        ...(typeParam ? { indicator_type: typeParam as IndicatorType } : {}),
        ...(limit ? { limit: Number(limit) } : {})
      });
      return { status: 200, body: { iocs } };
    }

    if (req.method === "POST" && path === "/api/v1/enrichment/iocs") {
      const b = (req.body ?? {}) as { iocs?: IocRecord[] };
      const written = await putIocs(iocKv, b.iocs ?? []);
      return { status: 201, body: { written } };
    }

    if (req.method === "POST" && path === "/api/v1/enrichment/iocs/import") {
      const lines = (req.bodyText ?? "").trim().split(/\r?\n/).filter(Boolean);
      return { status: 201, body: { written: Math.max(0, lines.length - 1) } };
    }

    if (req.method === "POST" && path === "/api/v1/enrichment/assets") {
      const b = (req.body ?? {}) as { assets?: unknown[] };
      return { status: 201, body: { written: b.assets?.length ?? 0 } };
    }

    if (req.method === "POST" && path === "/api/v1/enrichment/users") {
      const b = (req.body ?? {}) as { users?: unknown[] };
      return { status: 201, body: { written: b.users?.length ?? 0 } };
    }

    const iocMatch = path.match(/^\/api\/v1\/enrichment\/iocs\/([^/]+)\/(.+)$/);
    if (req.method === "DELETE" && iocMatch) {
      const type = decodeURIComponent(iocMatch[1] ?? "");
      const indicator = decodeURIComponent(iocMatch[2] ?? "");
      if (!isIndicatorType(type)) return { status: 400, body: { error: `Invalid indicator type: ${type}` } };
      const removed = await deleteIoc(iocKv, type, indicator);
      if (!removed) return { status: 404, body: { error: `IOC not found: ${type}/${indicator}` } };
      return { status: 200, body: { deleted: true } };
    }

    return { status: 404, body: { error: "not found" } };
  });
  return client;
}

function withClient(client: AdminClient, env: NodeJS.ProcessEnv = {}): MainOptions {
  return { adminClient: client, env };
}

function capture() {
  let stdout = "";
  let stderr = "";

  return {
    io: {
      stdout: { write: (chunk: string) => ((stdout += chunk), true) },
      stderr: { write: (chunk: string) => ((stderr += chunk), true) }
    },
    output: () => ({ stdout, stderr })
  };
}

function seedRow(overrides: Partial<FakeAlertRow> & { id: string }): FakeAlertRow {
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

function withDb(db: FakeAlertDb): MainOptions {
  return { adminClient: makeApiBackedAdminClient(db), env: { USER: "tester" } };
}

function withDbAndClock(db: FakeAlertDb, now: Date): MainOptions {
  return { adminClient: makeApiBackedAdminClient(db, { now }), env: { USER: "tester" }, now: () => now };
}

describe("picket CLI", () => {
  it("normalizes a CloudTrail fixture and evaluates alerts", async () => {
    const captured = capture();
    const exitCode = await main(["test-event", "../../fixtures/cloudtrail/root-console-login.json"], captured.io);
    const result = JSON.parse(captured.output().stdout) as Record<string, unknown>;

    expect(exitCode).toBe(0);
    expect(result.normalized_event).toMatchObject({
      source: "aws_cloudtrail",
      activity_name: "ConsoleLogin"
    });
    expect(result.alerts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ rule_id: "aws-root-account-usage" }),
        expect.objectContaining({ rule_id: "aws-console-login-without-mfa" })
      ])
    );
  });

  it("supports picket test as a local event dry-run alias", async () => {
    const captured = capture();
    const exitCode = await main(["test", "../../fixtures/cloudtrail/root-console-login.json"], captured.io);
    const result = JSON.parse(captured.output().stdout) as Record<string, unknown>;

    expect(exitCode).toBe(0);
    expect(result.normalized_event).toMatchObject({ source: "aws_cloudtrail" });
    expect(result.alerts).toEqual(
      expect.arrayContaining([expect.objectContaining({ rule_id: "aws-root-account-usage" })])
    );
  });

  it("initializes a Picket project scaffold", async () => {
    const root = await mkdtemp(join(tmpdir(), "picket-cli-"));
    try {
      const captured = capture();
      const exitCode = await main(["init", "demo"], captured.io, { cwd: root });

      expect(exitCode).toBe(0);
      expect(captured.output().stdout).toContain("Initialized Picket project in demo");
      expect(await readFile(join(root, "demo", "picket.config.yml"), "utf8")).toContain("detections_dir");
      expect(await readFile(join(root, "demo", "terraform", "main.tf"), "utf8")).toContain("picket_platform");
      expect(await readFile(join(root, "demo", "enrichment", "threat_intel.csv"), "utf8")).toContain("indicator_type");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("does not overwrite an init scaffold unless --force is passed", async () => {
    const root = await mkdtemp(join(tmpdir(), "picket-cli-"));
    try {
      const first = capture();
      expect(await main(["init", "demo"], first.io, { cwd: root })).toBe(0);

      const second = capture();
      expect(await main(["init", "demo"], second.io, { cwd: root })).toBe(1);
      expect(second.output().stderr).toContain("EEXIST");

      const third = capture();
      expect(await main(["init", "demo", "--force"], third.io, { cwd: root })).toBe(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("runs deploy steps in Terraform, binding sync, Worker order", async () => {
    const captured = capture();
    const calls: Array<{ command: string; args: string[]; cwd?: string }> = [];
    const exitCode = await main(["deploy"], captured.io, {
      cwd: "/repo",
      runCommand: async (command, args, options) => {
        calls.push({ command, args, cwd: options?.cwd });
      }
    });

    expect(exitCode).toBe(0);
    expect(calls).toEqual([
      { command: "terraform", args: ["-chdir=terraform/platform", "apply"], cwd: "/repo" },
      { command: "pnpm", args: ["sync:wrangler-bindings"], cwd: "/repo" },
      { command: "pnpm", args: ["deploy:cloudflare"], cwd: "/repo" }
    ]);
    expect(captured.output().stdout).toContain("Picket deployment steps completed");
  });

  it("supports skipping deploy phases", async () => {
    const captured = capture();
    const calls: string[] = [];
    const exitCode = await main(["deploy", "--skip-terraform", "--skip-bindings"], captured.io, {
      runCommand: async (command, args) => {
        calls.push(`${command} ${args.join(" ")}`);
      }
    });

    expect(exitCode).toBe(0);
    expect(calls).toEqual(["pnpm deploy:cloudflare"]);
  });

  it("prints preset query SQL with --print-only", async () => {
    const captured = capture();
    const exitCode = await main(
      ["query", "--preset", "threat-intel-ip-matches", "--hours", "1", "--limit", "25", "--print-only"],
      captured.io
    );

    expect(exitCode).toBe(0);
    expect(captured.output().stdout).toContain("JOIN threat_intel ti");
    expect(captured.output().stdout).toContain("interval '1' hour");
    expect(captured.output().stdout).toContain("LIMIT 25");
  });

  it("returns an error for unknown query presets", async () => {
    const captured = capture();
    const exitCode = await main(["query", "--preset", "missing", "--print-only"], captured.io);

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Unknown query preset: missing");
  });
});

describe("picket query execution", () => {
  const sampleResult: R2SqlResult = {
    columns: ["time", "actor_user_uid", "status"],
    rows: [
      { time: "2026-05-27T10:00:00Z", actor_user_uid: "u1", status: "failure" },
      { time: "2026-05-27T10:05:00Z", actor_user_uid: "u2", status: "failure" }
    ]
  };

  it("submits a preset, gets 200, renders a table", async () => {
    const { client, calls } = makeAdminClient((req) => {
      expect(req.method).toBe("POST");
      expect(req.url).toBe("https://test.example/api/v1/query");
      expect(req.headers["idempotency-key"]).toBe("uuid-fixed");
      expect(req.body).toMatchObject({ preset: "failed-logins" });
      return {
        status: 200,
        body: makeJob({
          id: "job-1",
          status: "succeeded",
          result: sampleResult,
          row_count: 2,
          bytes_scanned: 1024
        })
      };
    });
    const captured = capture();

    const exitCode = await main(
      ["query", "--preset", "failed-logins"],
      captured.io,
      withClient(client)
    );

    expect(exitCode).toBe(0);
    expect(calls).toHaveLength(1);
    const out = captured.output().stdout;
    expect(out).toContain("u1");
    expect(out).toContain("u2");
    expect(captured.output().stderr).toContain("rows=2");
    expect(captured.output().stderr).toContain("bytes=1024");
  });

  it("polls when the API returns 202", async () => {
    let getCount = 0;
    const { client, calls } = makeAdminClient((req) => {
      if (req.method === "POST") {
        return {
          status: 202,
          body: makeJob({
            id: "job-2",
            status: "pending",
            location: "/api/v1/query/job-2"
          })
        };
      }
      getCount += 1;
      if (getCount === 1) return { status: 200, body: makeJob({ id: "job-2", status: "running" }) };
      return {
        status: 200,
        body: makeJob({ id: "job-2", status: "succeeded", result: sampleResult, row_count: 2 })
      };
    });
    const captured = capture();

    const exitCode = await main(["query", "--preset", "failed-logins"], captured.io, withClient(client));

    expect(exitCode).toBe(0);
    expect(calls.map((c) => c.method)).toEqual(["POST", "GET", "GET"]);
    expect(captured.output().stdout).toContain("u1");
  });

  it("propagates a failed job as exit 1", async () => {
    const { client } = makeAdminClient((req) => {
      if (req.method === "POST") {
        return { status: 202, body: makeJob({ id: "job-3", status: "pending" }) };
      }
      return { status: 200, body: makeJob({ id: "job-3", status: "failed", error: "boom" }) };
    });
    const captured = capture();

    const exitCode = await main(["query", "--sql", "SELECT 1"], captured.io, withClient(client));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Query failed (job-3): boom");
  });

  it("forwards --idempotency-key as the header", async () => {
    const { client, calls } = makeAdminClient(() => ({
      status: 200,
      body: makeJob({ id: "j", status: "succeeded", result: sampleResult })
    }));
    const captured = capture();

    const exitCode = await main(
      ["query", "--sql", "SELECT 1", "--idempotency-key", "user-key-7"],
      captured.io,
      withClient(client)
    );

    expect(exitCode).toBe(0);
    expect(calls[0]?.headers["idempotency-key"]).toBe("user-key-7");
  });

  it("--async returns the job id without polling on 202", async () => {
    const { client, calls } = makeAdminClient(() => ({
      status: 202,
      body: makeJob({ id: "job-async", status: "pending", location: "/api/v1/query/job-async" })
    }));
    const captured = capture();

    const exitCode = await main(
      ["query", "--sql", "SELECT 1", "--async"],
      captured.io,
      withClient(client)
    );

    expect(exitCode).toBe(0);
    expect(calls).toHaveLength(1);
    const parsed = JSON.parse(captured.output().stdout) as { id: string; status: string };
    expect(parsed.id).toBe("job-async");
    expect(parsed.status).toBe("pending");
  });

  it("--job-id polls an existing job to completion", async () => {
    let getCount = 0;
    const { client, calls } = makeAdminClient(() => {
      getCount += 1;
      if (getCount === 1) return { status: 200, body: makeJob({ id: "job-x", status: "running" }) };
      return {
        status: 200,
        body: makeJob({ id: "job-x", status: "succeeded", result: sampleResult, row_count: 2 })
      };
    });
    const captured = capture();

    const exitCode = await main(["query", "--job-id", "job-x"], captured.io, withClient(client));

    expect(exitCode).toBe(0);
    expect(calls.map((c) => c.method)).toEqual(["GET", "GET"]);
    expect(captured.output().stdout).toContain("u1");
  });

  it("rejects --preset and --sql together", async () => {
    const { client, calls } = makeAdminClient(() => ({
      status: 200,
      body: makeJob({ id: "j", status: "succeeded", result: sampleResult })
    }));
    const captured = capture();

    const exitCode = await main(
      ["query", "--preset", "failed-logins", "--sql", "SELECT 1"],
      captured.io,
      withClient(client)
    );

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("mutually exclusive");
    expect(calls).toHaveLength(0);
  });

  it("requires --api-url or PICKET_API_URL when no admin client injected", async () => {
    const captured = capture();
    const exitCode = await main(["query", "--sql", "SELECT 1"], captured.io, { env: {} });
    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Admin API URL required");
  });

  it("--format json emits a parseable array of rows", async () => {
    const { client } = makeAdminClient(() => ({
      status: 200,
      body: makeJob({ id: "j", status: "succeeded", result: sampleResult, row_count: 2 })
    }));
    const captured = capture();

    const exitCode = await main(
      ["query", "--preset", "failed-logins", "--format", "json"],
      captured.io,
      withClient(client)
    );

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(captured.output().stdout) as Array<Record<string, unknown>>;
    expect(parsed).toEqual(sampleResult.rows);
  });

  it("reports HTTP errors with exit 1", async () => {
    const { client } = makeAdminClient(() => ({ status: 400, body: { error: "bad preset" } }));
    const captured = capture();

    const exitCode = await main(["query", "--preset", "failed-logins"], captured.io, withClient(client));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Query failed: bad preset");
  });

  it("--print-only does not call the API", async () => {
    const { client, calls } = makeAdminClient(() => ({
      status: 200,
      body: makeJob({ id: "j", status: "succeeded", result: sampleResult })
    }));
    const captured = capture();

    const exitCode = await main(
      ["query", "--preset", "failed-logins", "--print-only"],
      captured.io,
      withClient(client)
    );

    expect(exitCode).toBe(0);
    expect(calls).toHaveLength(0);
    expect(captured.output().stdout).toContain("FROM okta_auth");
  });

  it("rejects --hours/--limit when used with --sql", async () => {
    const { client, calls } = makeAdminClient(() => ({
      status: 200,
      body: makeJob({ id: "j", status: "succeeded", result: sampleResult })
    }));
    const captured = capture();

    const exitCode = await main(
      ["query", "--sql", "SELECT 1", "--hours", "1"],
      captured.io,
      withClient(client)
    );

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("--hours and --limit are only valid with --preset");
    expect(calls).toHaveLength(0);
  });
});

describe("picket query natural", () => {
  const sampleResult: R2SqlResult = {
    columns: ["actor_user_uid"],
    rows: [{ actor_user_uid: "u1" }, { actor_user_uid: "u2" }]
  };

  it("generates SQL, runs it, prints the SQL to stderr and rows to stdout", async () => {
    const { client, calls } = makeAdminClient((req) => {
      expect(req.method).toBe("POST");
      expect(req.url).toBe("https://test.example/api/v1/query/natural");
      expect(req.body).toMatchObject({ question: "non-US logins in the last day" });
      return {
        status: 200,
        body: {
          ...makeJob({ id: "job-nl", status: "succeeded", result: sampleResult, row_count: 2 }),
          generated_sql: "SELECT actor_user_uid FROM aws_cloudtrail WHERE ... LIMIT 100",
          rationale: "recent non-US activity"
        }
      };
    });
    const captured = capture();

    const exitCode = await main(
      ["query", "natural", "non-US logins in the last day"],
      captured.io,
      withClient(client)
    );

    expect(exitCode).toBe(0);
    expect(calls).toHaveLength(1);
    expect(captured.output().stdout).toContain("u1");
    const err = captured.output().stderr;
    expect(err).toContain("generated SQL");
    expect(err).toContain("SELECT actor_user_uid FROM aws_cloudtrail");
  });

  it("requires a question", async () => {
    const { client, calls } = makeAdminClient(() => ({ status: 200, body: makeJob({ id: "x", status: "succeeded" }) }));
    const captured = capture();

    const exitCode = await main(["query", "natural"], captured.io, withClient(client));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Usage: picket query natural");
    expect(calls).toHaveLength(0);
  });

  it("reports a rejected generation (HTTP 422) as an error", async () => {
    const { client } = makeAdminClient(() => ({
      status: 422,
      body: { error: "Generated query was rejected by validation.", generated_sql: "DELETE FROM aws_cloudtrail", details: ["read-only"] }
    }));
    const captured = capture();

    const exitCode = await main(["query", "natural", "wipe the table"], captured.io, withClient(client));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Generated query was rejected");
  });
});

describe("picket alerts list", () => {
  it("prints a table with key columns", async () => {
    const db = new FakeAlertDb([
      seedRow({ id: "alert-a", title: "Alpha", updated_at: "2026-05-26T11:00:00.000Z" }),
      seedRow({ id: "alert-b", title: "Beta", severity: "low", updated_at: "2026-05-26T12:00:00.000Z" })
    ]);
    const captured = capture();

    const exitCode = await main(["alerts", "list"], captured.io, withDb(db));

    expect(exitCode).toBe(0);
    const out = captured.output().stdout;
    expect(out).toContain("id");
    expect(out).toContain("severity");
    expect(out).toContain("status");
    expect(out).toContain("rule_id");
    expect(out).toContain("source");
    expect(out).toContain("match_count");
    expect(out).toContain("last_seen");
    expect(out).toContain("title");
    expect(out).toContain("alert-a");
    expect(out).toContain("alert-b");
    expect(out.indexOf("alert-b")).toBeLessThan(out.indexOf("alert-a"));
  });

  it("supports --format json", async () => {
    const db = new FakeAlertDb([seedRow({ id: "alert-a" })]);
    const captured = capture();

    const exitCode = await main(["alerts", "list", "--format", "json"], captured.io, withDb(db));

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(captured.output().stdout) as AlertRow[];
    expect(parsed).toHaveLength(1);
    expect(parsed[0]).toMatchObject({ id: "alert-a", severity: "high", status: "open" });
  });

  it("filters by status and severity", async () => {
    const db = new FakeAlertDb([
      seedRow({ id: "open-high", severity: "high", status: "open" }),
      seedRow({ id: "ack-high", severity: "high", status: "acknowledged" }),
      seedRow({ id: "open-low", severity: "low", status: "open" })
    ]);
    const captured = capture();

    const exitCode = await main(
      ["alerts", "list", "--status", "open", "--severity", "high", "--format", "json"],
      captured.io,
      withDb(db)
    );

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(captured.output().stdout) as AlertRow[];
    expect(parsed.map((alert) => alert.id)).toEqual(["open-high"]);
  });

  it("rejects non-positive limits", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["alerts", "list", "--limit", "0"], captured.io, withDb(db));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("--limit must be a positive integer");
  });

  it("rejects unknown status values", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["alerts", "list", "--status", "bogus"], captured.io, withDb(db));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("--status must be one of");
  });

  it("honors --limit when fewer rows fit", async () => {
    const db = new FakeAlertDb([
      seedRow({ id: "a1", updated_at: "2026-05-26T10:00:00.000Z" }),
      seedRow({ id: "a2", updated_at: "2026-05-26T11:00:00.000Z" }),
      seedRow({ id: "a3", updated_at: "2026-05-26T12:00:00.000Z" })
    ]);
    const captured = capture();

    const exitCode = await main(
      ["alerts", "list", "--limit", "2", "--format", "json"],
      captured.io,
      withDb(db)
    );

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(captured.output().stdout) as AlertRow[];
    expect(parsed.map((alert) => alert.id)).toEqual(["a3", "a2"]);
  });
});

describe("picket alerts stats", () => {
  it("renders an aggregate table", async () => {
    const db = new FakeAlertDb([
      seedRow({ id: "a", severity: "high", status: "open", rule_id: "r1", source: "aws_cloudtrail" }),
      seedRow({ id: "b", severity: "low", status: "resolved", rule_id: "r2", source: "kubernetes_audit" })
    ]);
    const captured = capture();

    const exitCode = await main(["alerts", "stats"], captured.io, withDb(db));

    expect(exitCode).toBe(0);
    const out = captured.output().stdout;
    expect(out).toContain("Total alerts: 2");
    expect(out).toContain("By severity:");
    expect(out).toContain("By status:");
    expect(out).toContain("By rule:");
    expect(out).toContain("By source:");
    expect(out).toContain("aws_cloudtrail");
  });

  it("supports --format json", async () => {
    const db = new FakeAlertDb([seedRow({ id: "a", severity: "high" })]);
    const captured = capture();

    const exitCode = await main(["alerts", "stats", "--format", "json"], captured.io, withDb(db));

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(captured.output().stdout) as {
      total: number;
      by_severity: { key: string; count: number }[];
    };
    expect(parsed.total).toBe(1);
    expect(parsed.by_severity).toContainEqual({ key: "high", count: 1 });
  });
});

describe("picket alerts show", () => {
  it("prints the alert and its timeline after an ack", async () => {
    const db = new FakeAlertDb([seedRow({ id: "alert-1" })]);
    const ack = capture();
    expect(await main(["alerts", "ack", "alert-1", "--by", "alice"], ack.io, withDb(db))).toBe(0);

    const captured = capture();
    const exitCode = await main(["alerts", "show", "alert-1"], captured.io, withDb(db));

    expect(exitCode).toBe(0);
    const out = captured.output().stdout;
    expect(out).toContain("Alert alert-1");
    expect(out).toContain("status:      acknowledged");
    expect(out).toContain("acknowledged ");
    expect(out).toContain("Timeline:");
    expect(out).toContain("acknowledged by alice");
  });

  it("returns JSON detail with timeline and notes arrays", async () => {
    const db = new FakeAlertDb([seedRow({ id: "alert-1" })]);
    const captured = capture();

    const exitCode = await main(["alerts", "show", "alert-1", "--format", "json"], captured.io, withDb(db));

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(captured.output().stdout) as {
      alert: { id: string; status: string };
      timeline: unknown[];
      notes: unknown[];
    };
    expect(parsed.alert.id).toBe("alert-1");
    expect(Array.isArray(parsed.timeline)).toBe(true);
    expect(Array.isArray(parsed.notes)).toBe(true);
  });

  it("returns a non-zero exit code when the alert does not exist", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["alerts", "show", "missing"], captured.io, withDb(db));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Alert not found: missing");
  });
});

describe("picket alerts resolve", () => {
  it("resolves an existing alert and writes a timeline entry", async () => {
    const db = new FakeAlertDb([seedRow({ id: "alert-1" })]);
    const captured = capture();

    const exitCode = await main(
      ["alerts", "resolve", "alert-1", "--by", "bob"],
      captured.io,
      withDb(db)
    );

    expect(exitCode).toBe(0);
    expect(captured.output().stdout).toContain("Resolved alert alert-1");
    expect(captured.output().stdout).toContain("by=bob");

    const row = db.alerts.find((alert) => alert.id === "alert-1");
    expect(row?.status).toBe("resolved");
    expect(row?.resolved_by).toBe("bob");
    expect(row?.resolved_at).toBeTruthy();
    expect(row?.updated_at).toBe(row?.resolved_at);

    expect(db.timeline).toHaveLength(1);
    const [entry] = db.timeline;
    expect(entry?.action).toBe("resolved");
    expect(entry?.actor).toBe("bob");
  });

  it("returns a non-zero exit code when the alert does not exist", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["alerts", "resolve", "missing"], captured.io, withDb(db));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Alert not found: missing");
    expect(db.timeline).toHaveLength(0);
  });
});

describe("picket alerts note", () => {
  it("adds a note to an existing alert", async () => {
    const db = new FakeAlertDb([seedRow({ id: "alert-1" })]);
    const captured = capture();

    const exitCode = await main(
      ["alerts", "note", "alert-1", "--body", "Investigating now", "--by", "alice"],
      captured.io,
      withDb(db)
    );

    expect(exitCode).toBe(0);
    expect(captured.output().stdout).toContain("Added note");
    expect(captured.output().stdout).toContain("by=alice");

    expect(db.notes).toHaveLength(1);
    expect(db.notes[0]?.body).toBe("Investigating now");
    expect(db.notes[0]?.author).toBe("alice");

    expect(db.timeline).toHaveLength(1);
    expect(db.timeline[0]?.action).toBe("note_added");
    expect(db.timeline[0]?.body).toBe("Investigating now");
  });

  it("uses the API actor when --by is omitted", async () => {
    const db = new FakeAlertDb([seedRow({ id: "alert-1" })]);
    const captured = capture();

    const exitCode = await main(
      ["alerts", "note", "alert-1", "--body", "looking"],
      captured.io,
      withDb(db)
    );

    expect(exitCode).toBe(0);
    expect(captured.output().stdout).toContain("by=admin");
    expect(db.notes[0]?.author).toBe("admin");
  });

  it("requires --body", async () => {
    const db = new FakeAlertDb([seedRow({ id: "alert-1" })]);
    const captured = capture();

    const exitCode = await main(["alerts", "note", "alert-1"], captured.io, withDb(db));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Usage: picket alerts note");
  });

  it("returns a non-zero exit code when the alert is missing", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(
      ["alerts", "note", "missing", "--body", "hi"],
      captured.io,
      withDb(db)
    );

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Alert not found: missing");
  });

  it("rejects an empty body string", async () => {
    const db = new FakeAlertDb([seedRow({ id: "alert-1" })]);
    const captured = capture();

    const exitCode = await main(
      ["alerts", "note", "alert-1", "--body", "   "],
      captured.io,
      withDb(db)
    );

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("non-empty");
  });
});

describe("picket alerts reopen", () => {
  it("reopens a resolved alert and clears resolved fields", async () => {
    const db = new FakeAlertDb([seedRow({ id: "alert-1" })]);

    expect(
      await main(["alerts", "resolve", "alert-1", "--by", "bob"], capture().io, withDb(db))
    ).toBe(0);
    expect(db.alerts[0]?.status).toBe("resolved");

    const captured = capture();
    const exitCode = await main(
      ["alerts", "reopen", "alert-1", "--by", "carol"],
      captured.io,
      withDb(db)
    );

    expect(exitCode).toBe(0);
    expect(captured.output().stdout).toContain("Reopened alert alert-1");
    expect(captured.output().stdout).toContain("by=carol");

    const row = db.alerts[0];
    expect(row?.status).toBe("open");
    expect(row?.resolved_at).toBeNull();
    expect(row?.resolved_by).toBeNull();

    expect(db.timeline.map((entry) => entry.action)).toEqual(["resolved", "reopened"]);
    expect(db.timeline.at(-1)?.actor).toBe("carol");
  });

  it("reopens an acknowledged alert", async () => {
    const db = new FakeAlertDb([seedRow({ id: "alert-1" })]);
    expect(await main(["alerts", "ack", "alert-1", "--by", "alice"], capture().io, withDb(db))).toBe(0);

    const captured = capture();
    const exitCode = await main(["alerts", "reopen", "alert-1"], captured.io, withDb(db));

    expect(exitCode).toBe(0);
    expect(db.alerts[0]?.status).toBe("open");
    expect(captured.output().stdout).toContain("by=admin");
  });

  it("returns a non-zero exit code when the alert is already open", async () => {
    const db = new FakeAlertDb([seedRow({ id: "alert-1", status: "open" })]);
    const captured = capture();

    const exitCode = await main(["alerts", "reopen", "alert-1"], captured.io, withDb(db));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("already open");
  });

  it("returns a non-zero exit code when the alert is missing", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["alerts", "reopen", "missing"], captured.io, withDb(db));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Alert not found: missing");
  });
});

describe("picket alerts ack", () => {
  it("acknowledges an existing alert and writes a timeline entry", async () => {
    const db = new FakeAlertDb([seedRow({ id: "alert-1" })]);
    const captured = capture();

    const exitCode = await main(
      ["alerts", "ack", "alert-1", "--by", "alice"],
      captured.io,
      withDb(db)
    );

    expect(exitCode).toBe(0);
    expect(captured.output().stdout).toContain("Acknowledged alert alert-1");
    expect(captured.output().stdout).toContain("by=alice");

    const row = db.alerts.find((alert) => alert.id === "alert-1");
    expect(row?.status).toBe("acknowledged");
    expect(row?.acknowledged_by).toBe("alice");
    expect(row?.acknowledged_at).toBeTruthy();
    expect(row?.updated_at).toBe(row?.acknowledged_at);

    expect(db.timeline).toHaveLength(1);
    const [entry] = db.timeline;
    expect(entry?.action).toBe("acknowledged");
    expect(entry?.actor).toBe("alice");
    expect(JSON.parse(entry?.metadata_json ?? "{}")).toMatchObject({ alert_id: "alert-1" });
  });

  it("uses the API actor when --by is omitted", async () => {
    const db = new FakeAlertDb([seedRow({ id: "alert-1" })]);
    const captured = capture();

    const exitCode = await main(["alerts", "ack", "alert-1"], captured.io, withDb(db));

    expect(exitCode).toBe(0);
    expect(captured.output().stdout).toContain("by=admin");
    expect(db.alerts[0]?.acknowledged_by).toBe("admin");
  });

  it("returns a non-zero exit code when the alert does not exist", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["alerts", "ack", "missing-id"], captured.io, withDb(db));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Alert not found: missing-id");
    expect(db.timeline).toHaveLength(0);
  });

  it("requires an alert id", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["alerts", "ack"], captured.io, withDb(db));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Usage: picket alerts ack");
  });
});

describe("picket alerts assign", () => {
  it("assigns an alert to a user via positional argument", async () => {
    const db = new FakeAlertDb([seedRow({ id: "alert-1" })]);
    const captured = capture();

    const exitCode = await main(["alerts", "assign", "alert-1", "carol", "--by", "alice"], captured.io, withDb(db));

    expect(exitCode).toBe(0);
    expect(captured.output().stdout).toContain("Alert alert-1 assigned to carol");
    expect(captured.output().stdout).toContain("by=alice");
    expect(db.alerts[0]?.assignee).toBe("carol");
    expect(db.timeline.find((entry) => entry.action === "assigned")).toBeDefined();
  });

  it("unassigns an alert with --unassign", async () => {
    const db = new FakeAlertDb([seedRow({ id: "alert-1", assignee: "carol" })]);
    const captured = capture();

    const exitCode = await main(["alerts", "assign", "alert-1", "--unassign"], captured.io, withDb(db));

    expect(exitCode).toBe(0);
    expect(captured.output().stdout).toContain("Alert alert-1 unassigned");
    expect(db.alerts[0]?.assignee).toBeNull();
  });

  it("returns a non-zero exit code when the alert does not exist", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["alerts", "assign", "missing-id", "carol"], captured.io, withDb(db));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Alert not found: missing-id");
  });

  it("requires an alert id and an assignee", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["alerts", "assign", "alert-1"], captured.io, withDb(db));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Usage: picket alerts assign");
  });
});

describe("picket detections", () => {
  async function withRules(db: FakeAlertDb): Promise<FakeAlertDb> {
    await seedDetectionRules(db, [
      { id: "aws-root", title: "AWS root", description: "root usage", severity: "high", source: "aws_cloudtrail", class_name: "authentication", execution: "sigma", tags: ["aws"], enabled: true, definition: { id: "aws-root" } },
      { id: "k8s-anon", title: "K8s anon", description: "anon access", severity: "medium", source: "kubernetes_audit", class_name: "api_activity", execution: "sigma", tags: ["k8s"], enabled: true, definition: { id: "k8s-anon" } }
    ]);
    return db;
  }

  it("lists registered rules as a table", async () => {
    const db = await withRules(new FakeAlertDb());
    const captured = capture();

    const exitCode = await main(["detections", "list"], captured.io, withDb(db));

    expect(exitCode).toBe(0);
    const out = captured.output().stdout;
    expect(out).toContain("aws-root");
    expect(out).toContain("k8s-anon");
    expect(out).toContain("severity");
    expect(out).toContain("matches");
  });

  it("lists as json and filters by --enabled", async () => {
    const db = await withRules(new FakeAlertDb());
    await setDetectionRuleEnabled(db, "k8s-anon", false);
    const captured = capture();

    const exitCode = await main(["detections", "list", "--enabled", "true", "--format", "json"], captured.io, withDb(db));

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(captured.output().stdout) as Array<{ id: string }>;
    expect(parsed.map((rule) => rule.id)).toEqual(["aws-root"]);
  });

  it("shows rule detail including the definition", async () => {
    const db = await withRules(new FakeAlertDb());
    const captured = capture();

    const exitCode = await main(["detections", "show", "aws-root"], captured.io, withDb(db));

    expect(exitCode).toBe(0);
    const out = captured.output().stdout;
    expect(out).toContain("Detection rule aws-root");
    expect(out).toContain("Definition:");
  });

  it("disables and re-enables a rule", async () => {
    const db = await withRules(new FakeAlertDb());
    const captured = capture();

    expect(await main(["detections", "disable", "aws-root"], captured.io, withDb(db))).toBe(0);
    expect(captured.output().stdout).toContain("Disabled detection rule aws-root (enabled=false)");
    expect(db.detectionRules.find((rule) => rule.id === "aws-root")?.enabled).toBe(0);

    const captured2 = capture();
    expect(await main(["detections", "enable", "aws-root"], captured2.io, withDb(db))).toBe(0);
    expect(captured2.output().stdout).toContain("enabled=true");
  });

  it("returns a non-zero exit for an unknown rule", async () => {
    const db = await withRules(new FakeAlertDb());
    const captured = capture();

    const exitCode = await main(["detections", "show", "nope"], captured.io, withDb(db));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Detection rule not found: nope");
  });

  it("lists scheduled detections with run health", async () => {
    const db = new FakeAlertDb();
    await seedDetectionRules(db, [
      {
        id: "sql-spike",
        title: "Spike",
        severity: "high",
        source: "aws_cloudtrail",
        class_name: "api_activity",
        execution: "sql",
        tags: [],
        enabled: true,
        definition: { id: "sql-spike", sql: { interval: "15m" } }
      }
    ]);
    db.scheduledState.push({
      rule_id: "sql-spike",
      last_run_at: "2026-05-27T12:00:00.000Z",
      last_status: "ok",
      last_row_count: 3,
      last_alert_count: 2,
      last_error: null,
      updated_at: "2026-05-27T12:00:00.000Z"
    });

    const captured = capture();
    const exitCode = await main(["detections", "scheduled"], captured.io, withDbAndClock(db, new Date("2026-05-27T12:30:00.000Z")));

    expect(exitCode).toBe(0);
    const out = captured.output().stdout;
    expect(out).toContain("sql-spike");
    expect(out).toContain("interval");
    expect(out).toContain("15m");
  });

  it("scheduled --format json returns the joined rows", async () => {
    const db = new FakeAlertDb();
    await seedDetectionRules(db, [
      {
        id: "sql-spike",
        title: "Spike",
        severity: "high",
        source: "aws_cloudtrail",
        class_name: "api_activity",
        execution: "sql",
        tags: [],
        enabled: true,
        definition: { id: "sql-spike", sql: { interval: "15m" } }
      }
    ]);
    const captured = capture();

    const exitCode = await main(["detections", "scheduled", "--format", "json"], captured.io, withDbAndClock(db, new Date("2026-05-27T12:30:00.000Z")));

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(captured.output().stdout) as Array<{ id: string; due: boolean }>;
    expect(parsed.map((r) => r.id)).toEqual(["sql-spike"]);
    expect(parsed[0]?.due).toBe(true);
  });
});

describe("picket enrichment", () => {
  it("adds an IOC then lists it as a table", async () => {
    // Reuse one options object so both calls share the same fake KV.
    const opts = withDb(new FakeAlertDb());
    const add = capture();
    const addExit = await main(
      ["enrichment", "add", "6.6.6.6", "--type", "ipv4", "--feed", "abuse.ch", "--threat-type", "c2"],
      add.io,
      opts
    );
    expect(addExit).toBe(0);
    expect(add.output().stdout).toContain("Added 1 IOC");

    const list = capture();
    const listExit = await main(["enrichment", "list"], list.io, opts);
    expect(listExit).toBe(0);
    const out = list.output().stdout;
    expect(out).toContain("6.6.6.6");
    expect(out).toContain("abuse.ch");
    expect(out).toContain("INDICATOR");
  });

  it("lists as json filtered by --type", async () => {
    const opts = withDb(new FakeAlertDb());
    const seed = capture();
    await main(["enrichment", "add", "1.1.1.1", "--type", "ipv4"], seed.io, opts);
    await main(["enrichment", "add", "evil.com", "--type", "domain"], seed.io, opts);

    const list = capture();
    const exit = await main(["enrichment", "list", "--type", "ipv4", "--format", "json"], list.io, opts);
    expect(exit).toBe(0);
    const parsed = JSON.parse(list.output().stdout) as IocRecord[];
    expect(parsed.map((r) => r.indicator)).toEqual(["1.1.1.1"]);
  });

  it("removes an IOC, reporting 404 as not found", async () => {
    const opts = withDb(new FakeAlertDb());
    const seed = capture();
    await main(["enrichment", "add", "6.6.6.6", "--type", "ipv4"], seed.io, opts);

    const rm = capture();
    const rmExit = await main(["enrichment", "remove", "ipv4", "6.6.6.6"], rm.io, opts);
    expect(rmExit).toBe(0);
    expect(rm.output().stdout).toContain("Removed IOC ipv4/6.6.6.6");

    const again = capture();
    const againExit = await main(["enrichment", "remove", "ipv4", "6.6.6.6"], again.io, opts);
    expect(againExit).toBe(1);
    expect(again.output().stderr).toContain("IOC not found");
  });

  it("imports IOCs from CSV", async () => {
    const root = await mkdtemp(join(tmpdir(), "picket-cli-"));
    try {
      const file = join(root, "threat_intel.csv");
      await writeFile(file, "indicator,indicator_type\n6.6.6.6,ipv4\nevil.com,domain\n");
      const captured = capture();
      const exit = await main(["enrichment", "import-csv", file, "--feed", "manual"], captured.io, withDb(new FakeAlertDb()));
      expect(exit).toBe(0);
      expect(captured.output().stdout).toContain("Imported 2 IOCs");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("loads assets and users from JSON files", async () => {
    const root = await mkdtemp(join(tmpdir(), "picket-cli-"));
    try {
      const assetsFile = join(root, "assets.json");
      const usersFile = join(root, "users.json");
      await writeFile(assetsFile, JSON.stringify({ assets: [{ asset_uid: "i-123", hostname: "web-1" }] }));
      await writeFile(usersFile, JSON.stringify([{ user_uid: "alice", user_email: "alice@example.com" }]));
      const opts = withDb(new FakeAlertDb());

      const assets = capture();
      expect(await main(["enrichment", "load-assets", assetsFile], assets.io, opts)).toBe(0);
      expect(assets.output().stdout).toContain("Loaded 1 asset");

      const users = capture();
      expect(await main(["enrichment", "load-users", usersFile], users.io, opts)).toBe(0);
      expect(users.output().stdout).toContain("Loaded 1 user");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("requires an indicator and --type for add", async () => {
    const captured = capture();
    const exit = await main(["enrichment", "add", "6.6.6.6"], captured.io, withDb(new FakeAlertDb()));
    expect(exit).toBe(1);
    expect(captured.output().stderr).toContain("Usage: picket enrichment add");
  });
});

describe("picket status", () => {
  const now = new Date("2026-05-27T12:10:00.000Z");

  it("renders 'No sources reporting.' on an empty DB", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["status"], captured.io, withDbAndClock(db, now));

    expect(exitCode).toBe(0);
    expect(captured.output().stdout).toContain("No sources reporting.");
  });

  it("renders a table with status, last_event_at, and totals", async () => {
    const db = new FakeAlertDb();
    db.sourceHealth.push({
      source: "aws_cloudtrail",
      tenant_id: "tenant-a",
      last_event_at: "2026-05-27T12:05:00.000Z", // 5min ago, healthy
      last_event_count: 1,
      total_events: 12,
      total_batches: 4,
      total_errors: 0,
      last_error_at: null,
      last_error_message: null,
      updated_at: "2026-05-27T12:05:00.000Z"
    });
    db.sourceHealth.push({
      source: "kubernetes_audit",
      tenant_id: "tenant-a",
      last_event_at: "2026-05-27T12:00:00.000Z", // 10min ago, k8s window=5min → stale
      last_event_count: 1,
      total_events: 4,
      total_batches: 2,
      total_errors: 1,
      last_error_at: "2026-05-27T12:01:00.000Z",
      last_error_message: "bad ndjson",
      updated_at: "2026-05-27T12:01:00.000Z"
    });
    const captured = capture();

    const exitCode = await main(["status"], captured.io, withDbAndClock(db, now));

    expect(exitCode).toBe(0);
    const out = captured.output().stdout;
    expect(out).toContain("source");
    expect(out).toContain("status");
    expect(out).toContain("last_event_at");
    expect(out).toContain("total_events");
    expect(out).toContain("total_errors");
    expect(out).toContain("aws_cloudtrail");
    expect(out).toContain("kubernetes_audit");
    expect(out).toContain("healthy");
    expect(out).toContain("stale");
  });

  it("supports --format json", async () => {
    const db = new FakeAlertDb();
    db.sourceHealth.push({
      source: "aws_cloudtrail",
      tenant_id: "tenant-a",
      last_event_at: "2026-05-27T12:05:00.000Z",
      last_event_count: 1,
      total_events: 1,
      total_batches: 1,
      total_errors: 0,
      last_error_at: null,
      last_error_message: null,
      updated_at: "2026-05-27T12:05:00.000Z"
    });
    const captured = capture();

    const exitCode = await main(
      ["status", "--format", "json"],
      captured.io,
      withDbAndClock(db, now)
    );

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(captured.output().stdout) as {
      sources: Array<{ source: string }>;
      detection_health: unknown;
    };
    expect(parsed.sources).toHaveLength(1);
    expect(parsed.sources[0]?.source).toBe("aws_cloudtrail");
    expect(parsed).toHaveProperty("detection_health");
  });

  it("renders detection-engine health below the source table", async () => {
    const db = new FakeAlertDb();
    db.detectionHealth = {
      last_eval_at: "2026-05-27T12:08:00.000Z", // 2min ago → healthy
      total_events_evaluated: 42,
      total_alerts_created: 3,
      stateless_rule_count: 4,
      stateful_rule_count: 1,
      updated_at: "2026-05-27T12:08:00.000Z"
    };
    const captured = capture();

    const exitCode = await main(["status"], captured.io, withDbAndClock(db, now));

    expect(exitCode).toBe(0);
    const out = captured.output().stdout;
    expect(out).toContain("Detection engine: healthy");
    expect(out).toContain("rules:            5 (4 stateless, 1 stateful)");
    expect(out).toContain("events_evaluated: 42");
  });

  it("reports unknown detection health when the engine has not evaluated anything", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["status"], captured.io, withDbAndClock(db, now));

    expect(exitCode).toBe(0);
    expect(captured.output().stdout).toContain("Detection engine: unknown");
  });

  it("returns a non-zero exit and stderr 'Source not found' for --source missing", async () => {
    const db = new FakeAlertDb();
    db.sourceHealth.push({
      source: "aws_cloudtrail",
      tenant_id: "tenant-a",
      last_event_at: "2026-05-27T12:05:00.000Z",
      last_event_count: 1,
      total_events: 1,
      total_batches: 1,
      total_errors: 0,
      last_error_at: null,
      last_error_message: null,
      updated_at: "2026-05-27T12:05:00.000Z"
    });
    const captured = capture();

    const exitCode = await main(
      ["status", "--source", "no_such_thing"],
      captured.io,
      withDbAndClock(db, now)
    );

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Source not found");
  });

  it("filters by --tenant", async () => {
    const db = new FakeAlertDb();
    db.sourceHealth.push({
      source: "aws_cloudtrail",
      tenant_id: "t1",
      last_event_at: "2026-05-27T12:05:00.000Z",
      last_event_count: 1,
      total_events: 1,
      total_batches: 1,
      total_errors: 0,
      last_error_at: null,
      last_error_message: null,
      updated_at: "2026-05-27T12:05:00.000Z"
    });
    db.sourceHealth.push({
      source: "aws_cloudtrail",
      tenant_id: "t2",
      last_event_at: "2026-05-27T12:05:00.000Z",
      last_event_count: 1,
      total_events: 1,
      total_batches: 1,
      total_errors: 0,
      last_error_at: null,
      last_error_message: null,
      updated_at: "2026-05-27T12:05:00.000Z"
    });
    const captured = capture();

    const exitCode = await main(
      ["status", "--tenant", "t1", "--format", "json"],
      captured.io,
      withDbAndClock(db, now)
    );

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(captured.output().stdout) as { sources: Array<{ tenant_id: string }> };
    expect(parsed.sources).toHaveLength(1);
    expect(parsed.sources[0]?.tenant_id).toBe("t1");
  });
});

describe("picket dashboard", () => {
  const now = new Date("2026-05-27T12:10:00.000Z");

  function seedSources(db: FakeAlertDb): void {
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
  }

  it("renders a readable overview", async () => {
    const db = new FakeAlertDb([seedRow({ id: "a", severity: "high" })]);
    seedSources(db);
    const captured = capture();

    const exitCode = await main(["dashboard"], captured.io, withDbAndClock(db, now));

    expect(exitCode).toBe(0);
    const out = captured.output().stdout;
    expect(out).toContain("Picket dashboard");
    expect(out).toContain("Sources: 1");
    expect(out).toContain("aws_cloudtrail");
    expect(out).toContain("Alerts: 1 total");
    expect(out).toContain("Detection engine:");
  });

  it("supports --format json", async () => {
    const db = new FakeAlertDb([seedRow({ id: "a" })]);
    seedSources(db);
    const captured = capture();

    const exitCode = await main(["dashboard", "--format", "json"], captured.io, withDbAndClock(db, now));

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(captured.output().stdout) as {
      generated_at: string;
      sources: { total: number };
      alerts: { total: number };
      detection: { status: string };
    };
    expect(parsed.sources.total).toBe(1);
    expect(parsed.alerts.total).toBe(1);
    expect(parsed.detection.status).toBe("unknown");
  });
});

describe("picket sources", () => {
  const now = new Date("2026-05-27T12:10:00.000Z");

  function withSource(db: FakeAlertDb): FakeAlertDb {
    db.sourceHealth.push({
      source: "aws_cloudtrail",
      tenant_id: "default",
      last_event_at: "2026-05-27T12:05:00.000Z",
      last_event_count: 1,
      total_events: 12,
      total_batches: 4,
      total_errors: 0,
      last_error_at: null,
      last_error_message: null,
      updated_at: "2026-05-27T12:05:00.000Z"
    });
    return db;
  }

  it("shows single-source status with health", async () => {
    const db = withSource(new FakeAlertDb());
    const captured = capture();

    const exitCode = await main(["sources", "status", "aws_cloudtrail"], captured.io, withDbAndClock(db, now));

    expect(exitCode).toBe(0);
    const out = captured.output().stdout;
    expect(out).toContain("Source aws_cloudtrail");
    expect(out).toContain("health:        healthy");
  });

  it("returns non-zero for status of an unreported source", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["sources", "status", "aws_cloudtrail"], captured.io, withDbAndClock(db, now));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Source not found: aws_cloudtrail");
  });

  it("prints the OCSF schema for a known source", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["sources", "schema", "aws_cloudtrail"], captured.io, withDbAndClock(db, now));

    expect(exitCode).toBe(0);
    const out = captured.output().stdout;
    expect(out).toContain("OCSF schema for aws_cloudtrail");
    expect(out).toContain("actor_user_uid");
  });

  it("schema --format json lists fields", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(
      ["sources", "schema", "aws_cloudtrail", "--format", "json"],
      captured.io,
      withDbAndClock(db, now)
    );

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(captured.output().stdout) as { source: string; fields: { name: string }[] };
    expect(parsed.source).toBe("aws_cloudtrail");
    expect(parsed.fields.map((f) => f.name)).toContain("time");
  });

  it("returns non-zero schema for an unknown source", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["sources", "schema", "not_a_source"], captured.io, withDbAndClock(db, now));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Unknown source: not_a_source");
  });

  it("samples recent events for a source and renders a table", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["sources", "sample", "aws_cloudtrail"], captured.io, withDbAndClock(db, now));

    expect(exitCode).toBe(0);
    expect(captured.output().stdout).toContain("u1");
  });

  it("returns non-zero when sampling an unknown source", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["sources", "sample", "not_a_source"], captured.io, withDbAndClock(db, now));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Unknown source: not_a_source");
  });
});

describe("picket query management", () => {
  it("explains a query without executing it", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(
      ["query", "explain", "--sql", "SELECT * FROM aws_cloudtrail WHERE time > now() - interval '1' hour LIMIT 10"],
      captured.io,
      withDb(db)
    );

    expect(exitCode).toBe(0);
    const out = captured.output().stdout;
    expect(out).toContain("valid:           true");
    expect(out).toContain("tables:          aws_cloudtrail");
  });

  it("explain --format json returns the structured plan", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(
      ["query", "explain", "--preset", "iam-changes", "--format", "json"],
      captured.io,
      withDb(db)
    );

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(captured.output().stdout) as { valid: boolean; plan: { tables: string[] } };
    expect(parsed.valid).toBe(true);
    expect(parsed.plan.tables.length).toBeGreaterThan(0);
  });

  it("saves a query then lists it under saved", async () => {
    const db = new FakeAlertDb();

    const save = capture();
    const saveCode = await main(
      ["query", "save", "--name", "recent ct", "--sql", "SELECT * FROM aws_cloudtrail WHERE time > now() - interval '1' hour"],
      save.io,
      withDb(db)
    );
    expect(saveCode).toBe(0);
    expect(save.output().stdout).toContain('Saved query "recent ct"');

    const list = capture();
    const listCode = await main(["query", "saved"], list.io, withDb(db));
    expect(listCode).toBe(0);
    expect(list.output().stdout).toContain("recent ct");

    const json = capture();
    await main(["query", "saved", "--format", "json"], json.io, withDb(db));
    const parsed = JSON.parse(json.output().stdout) as SavedQueryRow[];
    expect(parsed.map((row) => row.name)).toEqual(["recent ct"]);
  });

  it("requires --name on save", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["query", "save", "--sql", "SELECT 1"], captured.io, withDb(db));

    expect(exitCode).toBe(1);
    expect(captured.output().stderr).toContain("Usage: picket query save");
  });

  it("lists query history newest-first", async () => {
    const db = new FakeAlertDb();
    db.queryHistory.push(
      { id: "h1", owner: "admin", sql: "SELECT 1", preset: null, job_id: "j1", created_at: "2026-05-27T10:00:00.000Z" },
      { id: "h2", owner: "admin", sql: "SELECT 2", preset: "iam-changes", job_id: "j2", created_at: "2026-05-27T11:00:00.000Z" }
    );
    const captured = capture();

    const exitCode = await main(["query", "history", "--format", "json"], captured.io, withDb(db));

    expect(exitCode).toBe(0);
    const parsed = JSON.parse(captured.output().stdout) as Array<{ id: string }>;
    expect(parsed.map((row) => row.id)).toEqual(["h2", "h1"]);
  });

  it("renders an empty saved-queries table", async () => {
    const db = new FakeAlertDb();
    const captured = capture();

    const exitCode = await main(["query", "saved"], captured.io, withDb(db));

    expect(exitCode).toBe(0);
    expect(captured.output().stdout).toContain("No saved queries.");
  });
});

function inMemoryCredentialsIo(initial: CredentialRecord[] = []): CredentialsIo & {
  latest: () => CredentialsStore;
} {
  let store: CredentialsStore = {
    records: Object.fromEntries(initial.map((r) => [r.api_url, r]))
  };
  return {
    filePath: "/tmp/picket-creds.json",
    read: async () => store,
    write: async (next) => {
      store = next;
    },
    delete: async () => {
      store = { records: {} };
    },
    latest: () => store
  };
}

function noopCloudflared(): CloudflaredRunner {
  return { run: async () => ({ stdout: "", stderr: "", code: 1 }) };
}

describe("picket login/logout/whoami", () => {
  it("login persists a credential record on success", async () => {
    const credIo = inMemoryCredentialsIo();
    let attempt = 0;
    const jsonRes = (body: unknown, status = 200) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const fakeFetch: typeof fetch = async (input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.endsWith("/api/v1/meta")) return jsonRes({ access_required: false });
      if (url.endsWith("/api/v1/auth/device/code")) {
        return jsonRes({
          device_code: "D",
          user_code: "ABCD-EFGH",
          verification_uri: "https://api.test/device",
          verification_uri_complete: "https://api.test/device?user_code=ABCD-EFGH",
          expires_in: 60,
          interval: 1
        });
      }
      if (url.endsWith("/api/v1/auth/device/token")) {
        attempt += 1;
        if (attempt === 1) return jsonRes({ error: "authorization_pending", error_description: "wait" }, 400);
        return jsonRes({ access_token: "session-tok", token_type: "Bearer", expires_in: 3600 });
      }
      return jsonRes({ error: "not found" }, 404);
    };

    const cap = capture();
    const exitCode = await main(
      ["login", "--api-url", "https://api.test", "--no-browser"],
      cap.io,
      {
        env: {},
        fetch: fakeFetch,
        sleep: async () => undefined,
        cloudflared: noopCloudflared(),
        credentialsIo: credIo
      }
    );
    expect(exitCode).toBe(0);
    const stored = Object.values(credIo.latest().records);
    expect(stored).toHaveLength(1);
    expect(stored[0]?.access_token).toBe("session-tok");
    expect(cap.output().stdout).toContain("ABCD-EFGH");
  });

  it("logout removes credentials for the given api-url", async () => {
    const record: CredentialRecord = {
      api_url: "https://api.test",
      access_token: "tok",
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      obtained_at: new Date().toISOString()
    };
    const credIo = inMemoryCredentialsIo([record]);

    const exitCode = await main(["logout", "--api-url", "https://api.test"], capture().io, {
      env: {},
      credentialsIo: credIo
    });
    expect(exitCode).toBe(0);
    expect(Object.keys(credIo.latest().records)).toHaveLength(0);
  });

  it("whoami uses the stored bearer and prints the session email", async () => {
    const credIo = inMemoryCredentialsIo([
      {
        api_url: "https://api.test",
        access_token: "tok-123",
        expires_at: new Date(Date.now() + 60_000).toISOString(),
        obtained_at: new Date().toISOString()
      }
    ]);
    let sawBearer = false;
    const fakeFetch: typeof fetch = async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.endsWith("/api/v1/auth/get-session")) {
        const headers = (init?.headers ?? {}) as Record<string, string>;
        const auth = headers.authorization ?? headers.Authorization;
        if (auth === "Bearer tok-123") sawBearer = true;
        return new Response(
          JSON.stringify({ user: { id: "u1", email: "alice@example.com" } }),
          { status: 200 }
        );
      }
      return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
    };

    const cap = capture();
    const exitCode = await main(["whoami", "--api-url", "https://api.test"], cap.io, {
      env: { PICKET_SKIP_ACCESS: "1" },
      fetch: fakeFetch,
      credentialsIo: credIo
    });
    expect(exitCode).toBe(0);
    expect(sawBearer).toBe(true);
    expect(cap.output().stdout).toContain("alice@example.com");
  });

  it("whoami exits 1 when no credentials are present", async () => {
    const credIo = inMemoryCredentialsIo();
    const cap = capture();
    const exitCode = await main(["whoami", "--api-url", "https://api.test"], cap.io, {
      env: { PICKET_SKIP_ACCESS: "1" },
      credentialsIo: credIo
    });
    expect(exitCode).toBe(1);
    expect(cap.output().stderr).toContain("Not logged in");
  });
});
