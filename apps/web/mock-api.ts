import type { IncomingMessage, ServerResponse } from "node:http";
import type { Plugin } from "vite";

type Severity = "critical" | "high" | "medium" | "low" | "informational";
type AlertStatus = "open" | "acknowledged" | "resolved";
type IndicatorType = "ipv4" | "ipv6" | "domain" | "url" | "sha256";

interface AlertRow {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  source: string;
  status: AlertStatus;
  match_count: number;
  first_seen: string;
  last_seen: string;
  updated_at: string;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  assignee: string | null;
  event_json: string;
}

interface IocRecord {
  indicator: string;
  indicator_type: IndicatorType;
  feed_name?: string;
  threat_type?: string;
  added_at?: string;
}

const now = Date.now();
const iso = (offsetMinutes: number) => new Date(now + offsetMinutes * 60_000).toISOString();

const events = [
  {
    time: iso(-18),
    source: "aws_cloudtrail",
    class_name: "API Activity",
    activity_name: "ConsoleLogin",
    status: "failure",
    actor: { user: { email: "root@example.com", uid: "root" } },
    user: { email: "root@example.com", uid: "root" },
    src_endpoint: { ip: "203.0.113.44" },
    api: { operation: "ConsoleLogin", service: { name: "signin.amazonaws.com" } },
    cloud: { provider: "AWS", region: "us-east-1", account: { uid: "111111111111" } },
    threat_match: {
      indicator: "203.0.113.44",
      indicator_type: "ipv4",
      matched_field: "src_endpoint_ip",
      feed_name: "demo-feed",
      threat_type: "scanner"
    }
  },
  {
    time: iso(-16),
    source: "aws_cloudtrail",
    class_name: "API Activity",
    activity_name: "AttachUserPolicy",
    status: "success",
    actor: { user: { email: "root@example.com", uid: "root" } },
    user: { email: "root@example.com", uid: "root" },
    src_endpoint: { ip: "203.0.113.44" },
    api: { operation: "AttachUserPolicy", service: { name: "iam.amazonaws.com" } },
    cloud: { provider: "AWS", region: "us-east-1", account: { uid: "111111111111" } }
  },
  {
    time: iso(-12),
    source: "github_audit",
    class_name: "API Activity",
    activity_name: "repo.visibility_change",
    status: "success",
    actor: { user: { email: "dev@example.com", uid: "dev" } },
    user: { email: "dev@example.com", uid: "dev" },
    src_endpoint: { ip: "198.51.100.8" },
    api: { operation: "repo.visibility_change", service: { name: "github" } },
    cloud: { provider: "GitHub" }
  }
];

let alerts: AlertRow[] = [
  {
    id: "alert-root-login",
    rule_id: "aws-root-account-usage",
    title: "AWS root account used without expected controls",
    severity: "critical",
    source: "aws_cloudtrail",
    status: "open",
    match_count: 2,
    first_seen: iso(-18),
    last_seen: iso(-16),
    updated_at: iso(-16),
    acknowledged_at: null,
    acknowledged_by: null,
    resolved_at: null,
    resolved_by: null,
    assignee: null,
    event_json: JSON.stringify(events[0])
  },
  {
    id: "alert-github-public",
    rule_id: "github-audit-repo-visibility-public",
    title: "GitHub repository made public",
    severity: "high",
    source: "github_audit",
    status: "acknowledged",
    match_count: 1,
    first_seen: iso(-12),
    last_seen: iso(-12),
    updated_at: iso(-10),
    acknowledged_at: iso(-10),
    acknowledged_by: "analyst@example.com",
    resolved_at: null,
    resolved_by: null,
    assignee: "devsecops@example.com",
    event_json: JSON.stringify(events[2])
  }
];

let detections = [
  rule("aws-root-account-usage", "AWS root account usage", "critical", "aws_cloudtrail", "sigma", ["aws", "identity"], 3, iso(-16)),
  rule("github-audit-repo-visibility-public", "GitHub repository visibility changed to public", "high", "github_audit", "sigma", ["github"], 1, iso(-12)),
  rule("aws-cloudtrail-threat-intel-ip-match", "CloudTrail source IP matched threat intel", "high", "aws_cloudtrail", "sql", ["aws", "threat-intel"], 4, iso(-6)),
  rule("aws-k8s-cross-source-identity", "Identity appeared in AWS and Kubernetes", "medium", "aws_cloudtrail", "sql", ["correlation"], 0, null)
];

let iocs: IocRecord[] = [
  { indicator: "203.0.113.44", indicator_type: "ipv4", feed_name: "demo-feed", threat_type: "scanner", added_at: iso(-120) },
  { indicator: "bad.example.test", indicator_type: "domain", feed_name: "demo-feed", threat_type: "phishing", added_at: iso(-90) }
];

export function mockApiPlugin(enabled: boolean): Plugin {
  return {
    name: "picket-mock-api",
    configureServer(server) {
      if (!enabled) return;
      server.middlewares.use(async (req, res, next) => {
        if (!req.url || (!req.url.startsWith("/api/") && req.url !== "/health")) {
          next();
          return;
        }
        try {
          await handle(req, res);
        } catch (error) {
          send(res, 500, { error: error instanceof Error ? error.message : String(error) });
        }
      });
    }
  };
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", "http://mock.local");
  const method = req.method ?? "GET";

  if (url.pathname === "/health") return send(res, 200, { ok: true, worker: "picket-admin-mock" });
  if (url.pathname === "/api/v1/auth/get-session") return send(res, 200, { user: { id: "mock-user", email: "analyst@example.com" }, session: { id: "mock-session" } });
  if (url.pathname === "/api/v1/me") return send(res, 200, { access: { email: "analyst@example.com", sub: "mock" }, session: { user: { id: "mock-user", email: "analyst@example.com" } } });
  if (url.pathname === "/api/v1/auth/access-session" && method === "POST") return send(res, 201, { user: { id: "mock-user", email: "analyst@example.com" }, session: { id: "mock-session" }, created: false });

  if (url.pathname === "/api/v1/dashboard/overview") return send(res, 200, { overview: dashboardOverview() });
  if (url.pathname === "/api/v1/alerts" && method === "GET") return send(res, 200, listAlertsResponse(url));
  if (url.pathname === "/api/v1/alerts/bulk" && method === "PATCH") return bulkAlerts(res, await body(req));
  if (url.pathname === "/api/v1/alerts/stats") return send(res, 200, { stats: alertStats() });
  if (url.pathname.startsWith("/api/v1/alerts/")) return alertDetailRoutes(req, res, url);

  if (url.pathname === "/api/v1/detections") return send(res, 200, { rules: detections });
  if (url.pathname === "/api/v1/detections/scheduled") return send(res, 200, { scheduled: scheduledDetections() });
  if (url.pathname.startsWith("/api/v1/detections/")) return detectionRoutes(req, res, url);

  if (url.pathname === "/api/v1/sources") return send(res, 200, { sources: sourceRows() });
  if (url.pathname.startsWith("/api/v1/sources/")) return sourceRoutes(res, url);

  if (url.pathname === "/api/v1/query" && method === "POST") return queryResponse(res, await body(req));
  if (url.pathname === "/api/v1/query/natural" && method === "POST") return naturalQueryResponse(res, await body(req));
  if (url.pathname === "/api/v1/query/explain" && method === "POST") return send(res, 200, { explain: explain(await body(req)) });
  if (url.pathname === "/api/v1/query/save" && method === "POST") return send(res, 201, { saved: savedQuery(await body(req)) });
  if (url.pathname === "/api/v1/query/saved") return send(res, 200, { saved: [savedQuery({ name: "Recent root activity", sql: "SELECT * FROM aws_cloudtrail ORDER BY time DESC LIMIT 50" })] });
  if (url.pathname === "/api/v1/query/history") return send(res, 200, { history: [historyRow("SELECT * FROM aws_cloudtrail ORDER BY time DESC LIMIT 50")] });
  if (url.pathname.startsWith("/api/v1/query/")) return send(res, 200, queryJob("SELECT * FROM aws_cloudtrail ORDER BY time DESC LIMIT 50"));

  if (url.pathname === "/api/v1/enrichment/feeds") return enrichmentFeeds(req, res);
  if (url.pathname === "/api/v1/enrichment/iocs") return enrichmentIocs(req, res, url);
  if (url.pathname === "/api/v1/enrichment/iocs/import" && method === "POST") return importIocs(req, res, url);
  if (url.pathname.startsWith("/api/v1/enrichment/iocs/") && method === "DELETE") return deleteIoc(res, url);

  send(res, 404, { error: "Mock route not found" });
}

function rule(id: string, title: string, severity: string, source: string, execution: string, tags: string[], matchCount: number, lastTriggered: string | null) {
  return {
    id,
    title,
    description: `${title} demo rule.`,
    severity,
    source,
    class_name: "api_activity",
    execution,
    tags,
    enabled: true,
    definition: execution === "sql"
      ? { sql: { query: `SELECT * FROM ${source} WHERE time > now() - interval '1' hour LIMIT 100`, interval: "15m", threshold: 1, count_field: "cnt", group_by: ["actor_user_uid"] } }
      : { id, title, severity, enabled: true, execution: "sigma", logsource: { source }, detection: { selection: { status: "failure" }, condition: "selection" } },
    match_count: matchCount,
    last_triggered_at: lastTriggered,
    created_at: iso(-240),
    updated_at: iso(-5)
  };
}

function listAlertsResponse(url: URL) {
  let rows = [...alerts];
  const status = url.searchParams.get("status");
  const severity = url.searchParams.get("severity");
  const ruleId = url.searchParams.get("rule_id") ?? url.searchParams.get("rule");
  const source = url.searchParams.get("source");
  if (status) rows = rows.filter((row) => row.status === status);
  if (severity) rows = rows.filter((row) => row.severity === severity);
  if (ruleId) rows = rows.filter((row) => row.rule_id === ruleId);
  if (source) rows = rows.filter((row) => row.source === source);
  rows.sort((left, right) => right.last_seen.localeCompare(left.last_seen));
  const limit = Number(url.searchParams.get("limit") ?? 20);
  const offset = Number(url.searchParams.get("offset") ?? 0);
  return { alerts: rows.slice(offset, offset + limit).map(alertListRow), total: rows.length, limit, offset };
}

async function alertDetailRoutes(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
  const parts = url.pathname.split("/");
  const id = decodeURIComponent(parts[4] ?? "");
  const alert = alerts.find((row) => row.id === id);
  if (!alert) return send(res, 404, { error: `Alert not found: ${id}` });
  if (parts[5] === "notes" && req.method === "POST") {
    const input = await body(req);
    return send(res, 201, { note: { id: `note-${Date.now()}`, body: String(input.body ?? ""), author: "analyst@example.com", created_at: iso(0) } });
  }
  if (req.method === "PATCH") {
    const input = await body(req);
    if (input.status === "open" || input.status === "acknowledged" || input.status === "resolved") alert.status = input.status;
    if ("assignee" in input) alert.assignee = typeof input.assignee === "string" ? input.assignee : null;
    alert.updated_at = iso(0);
    return send(res, 200, { alert: alertDetailRow(alert) });
  }
  return send(res, 200, {
    alert: alertDetailRow(alert),
    timeline: [
      { id: "tl-1", action: "created", actor: "system", body: null, metadata_json: null, created_at: alert.first_seen },
      { id: "tl-2", action: "routed", actor: "alert-router", body: "Sent to demo webhook", metadata_json: null, created_at: alert.last_seen }
    ],
    notes: []
  });
}

async function detectionRoutes(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
  const id = decodeURIComponent(url.pathname.split("/")[4] ?? "");
  const detection = detections.find((row) => row.id === id);
  if (!detection) return send(res, 404, { error: `Detection rule not found: ${id}` });
  if (req.method === "PATCH") {
    const input = await body(req);
    detection.enabled = Boolean(input.enabled);
  }
  send(res, 200, { rule: detection });
}

function sourceRoutes(res: ServerResponse, url: URL) {
  const [, , , , source, action] = url.pathname.split("/");
  const row = sourceRows().find((entry) => entry.source === decodeURIComponent(source ?? ""));
  if (!row) return send(res, 404, { error: "Source not found" });
  if (action === "status") return send(res, 200, { status: { ...row, health: "healthy" } });
  if (action === "schema") return send(res, 200, { schema: { source: row.source, field_count: 8, fields: ["time", "activity_name", "status", "actor_user_email", "src_endpoint_ip", "api_operation", "cloud_provider", "threat_match_indicator"].map((name) => ({ name, type: "string", group: name.includes("_") ? name.split("_")[0] : "base" })) } });
  if (action === "history") return send(res, 200, { history: [{ id: 1, source: row.source, tenant_id: row.tenant_id, kind: "batch", event_count: row.last_event_count, last_event_at: row.last_event_at, error_message: null, recorded_at: iso(-10) }] });
  if (action === "errors") return send(res, 200, { errors: [] });
  if (action === "sample") return send(res, 200, queryJob(`SELECT * FROM ${row.source} ORDER BY time DESC LIMIT 10`));
  send(res, 404, { error: "Source action not found" });
}

function queryResponse(res: ServerResponse, input: Record<string, unknown>) {
  send(res, 200, queryJob(typeof input.sql === "string" ? input.sql : "SELECT * FROM aws_cloudtrail LIMIT 100"));
}

function naturalQueryResponse(res: ServerResponse, input: Record<string, unknown>) {
  const sql = `SELECT time, source, activity_name, status, actor_user_email, src_endpoint_ip FROM aws_cloudtrail ORDER BY time DESC LIMIT 100`;
  send(res, 200, { ...queryJob(sql), generated_sql: sql, rationale: `Mock SQL for: ${String(input.question ?? "recent events")}` });
}

function queryJob(sql: string) {
  const rows = contextRows(sql);
  return {
    id: `job-${Date.now()}`,
    status: "succeeded",
    preset: null,
    warehouse: "mock-warehouse",
    created_at: iso(0),
    started_at: iso(0),
    finished_at: iso(0),
    bytes_scanned: 1024,
    files_scanned: 1,
    row_count: rows.length,
    result: { columns: Object.keys(rows[0] ?? { time: "", source: "", activity_name: "", status: "" }), rows }
  };
}

function contextRows(sql: string) {
  const source = /FROM\s+([a-z0-9_]+)/i.exec(sql)?.[1];
  return events
    .filter((event) => !source || event.source === source)
    .map((event) => ({
      time: event.time,
      source: event.source,
      activity_name: event.activity_name,
      status: event.status,
      actor_user_email: event.actor?.user?.email,
      actor_user_uid: event.actor?.user?.uid,
      src_endpoint_ip: event.src_endpoint?.ip,
      api_operation: event.api?.operation,
      cloud_provider: event.cloud?.provider,
      threat_match_indicator: event.threat_match?.indicator,
      event_json: JSON.stringify(event)
    }));
}

function enrichmentFeeds(req: IncomingMessage, res: ServerResponse) {
  if (req.method !== "GET") return send(res, 405, { error: "Method not allowed" });
  const feeds = [...new Map(iocs.map((ioc) => [ioc.feed_name ?? "manual", ioc.feed_name ?? "manual"])).values()].map((name) => {
    const rows = iocs.filter((ioc) => (ioc.feed_name ?? "manual") === name);
    return { name, type: "ioc", indicator_count: rows.length, last_updated: rows.map((row) => row.added_at ?? "").sort().at(-1) ?? null };
  });
  send(res, 200, { feeds });
}

async function enrichmentIocs(req: IncomingMessage, res: ServerResponse, url: URL) {
  if (req.method === "GET") {
    const type = url.searchParams.get("type");
    const rows = type ? iocs.filter((ioc) => ioc.indicator_type === type) : iocs;
    return send(res, 200, { iocs: rows });
  }
  if (req.method === "POST") {
    const input = await body(req);
    const rows = Array.isArray(input.iocs) ? input.iocs : [input];
    for (const row of rows) {
      if (isIoc(row)) iocs = upsertIoc({ ...row, added_at: row.added_at ?? iso(0) });
    }
    return send(res, 201, { written: rows.length });
  }
  send(res, 405, { error: "Method not allowed" });
}

async function importIocs(req: IncomingMessage, res: ServerResponse, url: URL) {
  const feed = url.searchParams.get("feed") ?? "csv-import";
  const text = await textBody(req);
  const rows = text.trim().split(/\r?\n/).slice(1).filter(Boolean);
  for (const row of rows) {
    const [indicator, indicator_type, feed_name, threat_type] = row.split(",").map((cell) => cell.trim());
    if (indicator && isIndicatorType(indicator_type)) iocs = upsertIoc({ indicator, indicator_type, feed_name: feed_name || feed, threat_type: threat_type || undefined, added_at: iso(0) });
  }
  send(res, 201, { written: rows.length });
}

function deleteIoc(res: ServerResponse, url: URL) {
  const [, , , , , type, ...indicatorParts] = url.pathname.split("/");
  const indicator = decodeURIComponent(indicatorParts.join("/"));
  iocs = iocs.filter((ioc) => !(ioc.indicator_type === type && ioc.indicator === indicator));
  send(res, 200, { deleted: true });
}

function dashboardOverview() {
  const rules = detections;
  return {
    generated_at: iso(0),
    sources: { total: sourceRows().length, healthy: sourceRows().length, stale: 0, unknown: 0, items: sourceRows().map((row) => ({ ...row, health: "healthy" })) },
    alerts: alertStats(),
    detection: { health: { last_eval_at: iso(-1), total_events_evaluated: 128, total_alerts_created: alerts.length, stateless_rule_count: 2, stateful_rule_count: 0, updated_at: iso(-1) }, status: "healthy", rules: { total: rules.length, enabled: rules.filter((rule) => rule.enabled).length, disabled: rules.filter((rule) => !rule.enabled).length } }
  };
}

function alertStats() {
  const by = (keys: string[], read: (alert: AlertRow) => string) => keys.map((key) => ({ key, count: alerts.filter((alert) => read(alert) === key).length }));
  return {
    total: alerts.length,
    by_severity: by(["critical", "high", "medium", "low", "informational"], (alert) => alert.severity),
    by_status: by(["open", "acknowledged", "resolved"], (alert) => alert.status),
    by_rule: [...new Set(alerts.map((alert) => alert.rule_id))].map((key) => ({ key, count: alerts.filter((alert) => alert.rule_id === key).length })),
    by_source: [...new Set(alerts.map((alert) => alert.source))].map((key) => ({ key, count: alerts.filter((alert) => alert.source === key).length }))
  };
}

function sourceRows() {
  return [
    { source: "aws_cloudtrail", tenant_id: "demo", last_event_at: iso(-4), last_event_count: 18, total_events: 4521, total_batches: 91, total_errors: 0, last_error_at: null, last_error_message: null, updated_at: iso(-4) },
    { source: "github_audit", tenant_id: "demo", last_event_at: iso(-12), last_event_count: 3, total_events: 211, total_batches: 21, total_errors: 1, last_error_at: iso(-180), last_error_message: "One webhook retry exceeded demo timeout", updated_at: iso(-12) }
  ];
}

function scheduledDetections() {
  return detections.filter((rule) => rule.execution === "sql").map((rule, index) => ({ id: rule.id, title: rule.title, severity: rule.severity, source: rule.source, enabled: rule.enabled, interval: "15m", last_run_at: index === 0 ? iso(-7) : null, last_status: index === 0 ? "ok" : null, last_row_count: index === 0 ? 4 : null, last_alert_count: index === 0 ? 1 : null, last_error: null, due: index !== 0 }));
}

function alertListRow(alert: AlertRow) {
  const { event_json, acknowledged_at, acknowledged_by, resolved_at, resolved_by, assignee, ...row } = alert;
  return row;
}

function alertDetailRow(alert: AlertRow) {
  return { ...alert };
}

function bulkAlerts(res: ServerResponse, input: Record<string, unknown>) {
  const ids = Array.isArray(input.ids) ? input.ids : [];
  const status = input.status === "acknowledged" || input.status === "resolved" ? input.status : null;
  if (!status) return send(res, 400, { error: "Invalid status" });
  alerts = alerts.map((alert) => ids.includes(alert.id) ? { ...alert, status, updated_at: iso(0) } : alert);
  send(res, 200, { alerts: alerts.filter((alert) => ids.includes(alert.id)).map(alertListRow) });
}

function savedQuery(input: Record<string, unknown>) {
  return { id: `saved-${Date.now()}`, owner: "analyst@example.com", name: String(input.name ?? "Saved query"), description: typeof input.description === "string" ? input.description : null, sql: String(input.sql ?? ""), preset: null, created_at: iso(0), updated_at: iso(0) };
}

function historyRow(sql: string) {
  return { id: `history-${Date.now()}`, owner: "analyst@example.com", sql, preset: null, job_id: "job-demo", created_at: iso(-5) };
}

function explain(input: Record<string, unknown>) {
  const sql = String(input.sql ?? "");
  return { sql, valid: sql.trim().length > 0, errors: [], warnings: sql.toLowerCase().includes("limit") ? [] : ["Add LIMIT for interactive hunts."], plan: { tables: [...sql.matchAll(/\bFROM\s+([a-z0-9_]+)/gi)].map((match) => match[1]), has_time_filter: /time\s*[<>=]/i.test(sql), has_join: /\bJOIN\b/i.test(sql), has_limit: /\bLIMIT\b/i.test(sql), read_only: true } };
}

function upsertIoc(record: IocRecord) {
  return [...iocs.filter((ioc) => !(ioc.indicator_type === record.indicator_type && ioc.indicator === record.indicator)), record];
}

function isIoc(value: unknown): value is IocRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) && typeof (value as IocRecord).indicator === "string" && isIndicatorType((value as IocRecord).indicator_type);
}

function isIndicatorType(value: unknown): value is IndicatorType {
  return value === "ipv4" || value === "ipv6" || value === "domain" || value === "url" || value === "sha256";
}

async function body(req: IncomingMessage): Promise<Record<string, unknown>> {
  const text = await textBody(req);
  if (!text) return {};
  try {
    const parsed = JSON.parse(text) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

async function textBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

function send(res: ServerResponse, status: number, data: unknown): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.end(JSON.stringify(data));
}
