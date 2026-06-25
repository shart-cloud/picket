import type {
  AlertDetail,
  AlertNoteEntry,
  AlertRow,
  AlertSortDirection,
  AlertSortField,
  AlertStats,
  AlertStatus,
  AlertSeverity,
  AlertWithHistory
} from "@picket/core/alerts";
import type { DashboardOverview } from "@picket/core/dashboard";
import type { DetectionRuleRow } from "@picket/core/detection-rules";
import type { SourceHealthHistoryRow, SourceHealthRow } from "@picket/core/source-health";
import type { OcsfSourceSchema, SourceStatus } from "@picket/core/sources";
import type { QueryHistoryRow, SavedQueryRow } from "@picket/core/saved-queries";

export class ApiError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
    this.name = "ApiError";
  }
}

export interface SessionUser {
  id?: string;
  email?: string;
  name?: string;
}

export interface AuthSession {
  user?: SessionUser;
  session?: unknown;
}

export interface AccessIdentity {
  email?: string;
  sub?: string;
}

export interface MeResponse {
  access: AccessIdentity | null;
  session: AuthSession | null;
}

export interface QueryJob {
  id: string;
  status: "pending" | "running" | "succeeded" | "failed";
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
  generated_sql?: string;
  rationale?: string | null;
}

export interface QueryResult {
  columns: string[];
  rows: Record<string, unknown>[];
}

export interface ScheduledDetectionView {
  id: string;
  title: string;
  severity: string;
  source: string;
  enabled: boolean;
  interval: string | null;
  last_run_at: string | null;
  last_status: "ok" | "error" | "skipped" | null;
  last_row_count: number | null;
  last_alert_count: number | null;
  last_error: string | null;
  due: boolean;
}

export type IndicatorType = "ipv4" | "ipv6" | "domain" | "url" | "sha256";

export interface IocRecord {
  indicator: string;
  indicator_type: IndicatorType;
  feed_name?: string;
  threat_type?: string;
  added_at?: string;
}

export interface EnrichmentFeed {
  name: string;
  type: string;
  indicator_count: number;
  last_updated: string | null;
}

export interface QueryExplain {
  sql: string;
  valid: boolean;
  errors: string[];
  warnings: string[];
  plan: {
    tables: string[];
    has_time_filter: boolean;
    has_join: boolean;
    has_limit: boolean;
    read_only: boolean;
  };
}

export interface ListAlertsOptions {
  status?: AlertStatus;
  severity?: AlertSeverity;
  ruleId?: string;
  source?: string;
  startTime?: string;
  endTime?: string;
  sort?: Exclude<AlertSortField, "updated_at">;
  direction?: AlertSortDirection;
  limit?: number;
  offset?: number;
}

export interface AlertPage {
  alerts: AlertRow[];
  total: number;
  limit: number;
  offset: number;
}

export async function getSession(): Promise<AuthSession | null> {
  try {
    return await request<AuthSession>("/api/v1/auth/get-session");
  } catch (error) {
    if (error instanceof ApiError && (error.status === 401 || error.status === 404)) return null;
    throw error;
  }
}

export async function getMe(): Promise<MeResponse> {
  return request<MeResponse>("/api/v1/me");
}

export async function createAccessSession(): Promise<AuthSession> {
  return request<AuthSession>("/api/v1/auth/access-session", { method: "POST" });
}

export async function getDashboardOverview(): Promise<DashboardOverview> {
  const body = await request<{ overview: DashboardOverview }>("/api/v1/dashboard/overview");
  return body.overview;
}

export async function listAlerts(options: ListAlertsOptions = {}): Promise<AlertPage> {
  const params = new URLSearchParams();
  if (options.status) params.set("status", options.status);
  if (options.severity) params.set("severity", options.severity);
  if (options.ruleId) params.set("rule_id", options.ruleId);
  if (options.source) params.set("source", options.source);
  if (options.startTime) params.set("start_time", options.startTime);
  if (options.endTime) params.set("end_time", options.endTime);
  if (options.sort) params.set("sort", options.sort);
  if (options.direction) params.set("direction", options.direction);
  if (options.limit !== undefined) params.set("limit", String(options.limit));
  if (options.offset !== undefined) params.set("offset", String(options.offset));
  const suffix = params.size > 0 ? `?${params}` : "";
  return request<AlertPage>(`/api/v1/alerts${suffix}`);
}

export async function bulkUpdateAlertStatus(ids: string[], status: "acknowledged" | "resolved"): Promise<AlertRow[]> {
  const body = await request<{ alerts: AlertRow[] }>("/api/v1/alerts/bulk", {
    method: "PATCH",
    body: JSON.stringify({ ids, status })
  });
  return body.alerts;
}

export async function getAlert(id: string): Promise<AlertWithHistory> {
  return request<AlertWithHistory>(`/api/v1/alerts/${encodeURIComponent(id)}`);
}

export async function updateAlertStatus(id: string, status: AlertStatus): Promise<AlertDetail> {
  const body = await request<{ alert: AlertDetail }>(`/api/v1/alerts/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify({ status })
  });
  return body.alert;
}

export async function assignAlert(id: string, assignee: string | null): Promise<AlertDetail> {
  const body = await request<{ alert: AlertDetail }>(`/api/v1/alerts/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify({ assignee })
  });
  return body.alert;
}

export async function addAlertNote(id: string, note: string): Promise<AlertNoteEntry> {
  const body = await request<{ note: AlertNoteEntry }>(`/api/v1/alerts/${encodeURIComponent(id)}/notes`, {
    method: "POST",
    body: JSON.stringify({ body: note })
  });
  return body.note;
}

export async function getAlertStats(): Promise<AlertStats> {
  const body = await request<{ stats: AlertStats }>("/api/v1/alerts/stats");
  return body.stats;
}

export async function listDetections(): Promise<DetectionRuleRow[]> {
  const body = await request<{ rules: DetectionRuleRow[] }>("/api/v1/detections");
  return body.rules;
}

export async function getDetection(id: string): Promise<DetectionRuleRow> {
  const body = await request<{ rule: DetectionRuleRow }>(`/api/v1/detections/${encodeURIComponent(id)}`);
  return body.rule;
}

export async function setDetectionEnabled(id: string, enabled: boolean): Promise<DetectionRuleRow> {
  const body = await request<{ rule: DetectionRuleRow }>(`/api/v1/detections/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify({ enabled })
  });
  return body.rule;
}

export async function listScheduledDetections(): Promise<ScheduledDetectionView[]> {
  const body = await request<{ scheduled: ScheduledDetectionView[] }>("/api/v1/detections/scheduled");
  return body.scheduled;
}

export async function listEnrichmentFeeds(): Promise<EnrichmentFeed[]> {
  const body = await request<{ feeds: EnrichmentFeed[] }>("/api/v1/enrichment/feeds");
  return body.feeds;
}

export async function listIocs(type?: IndicatorType): Promise<IocRecord[]> {
  const params = new URLSearchParams();
  if (type) params.set("type", type);
  const suffix = params.size > 0 ? `?${params}` : "";
  const body = await request<{ iocs: IocRecord[] }>(`/api/v1/enrichment/iocs${suffix}`);
  return body.iocs;
}

export async function addIoc(input: IocRecord): Promise<number> {
  const body = await request<{ written: number }>("/api/v1/enrichment/iocs", {
    method: "POST",
    body: JSON.stringify(input)
  });
  return body.written;
}

export async function importIocCsv(input: { csv: string; feed?: string; threatType?: string }): Promise<number> {
  const params = new URLSearchParams();
  if (input.feed) params.set("feed", input.feed);
  if (input.threatType) params.set("threat_type", input.threatType);
  const suffix = params.size > 0 ? `?${params}` : "";
  const body = await request<{ written: number }>(`/api/v1/enrichment/iocs/import${suffix}`, {
    method: "POST",
    headers: { "content-type": "text/csv" },
    body: input.csv
  });
  return body.written;
}

export async function deleteIoc(type: IndicatorType, indicator: string): Promise<void> {
  await request<{ deleted: boolean }>(`/api/v1/enrichment/iocs/${encodeURIComponent(type)}/${encodeURIComponent(indicator)}`, {
    method: "DELETE"
  });
}

export async function listSources(): Promise<SourceHealthRow[]> {
  const body = await request<{ sources: SourceHealthRow[] }>("/api/v1/sources");
  return body.sources;
}

export async function getSourceStatus(source: string, tenant?: string): Promise<SourceStatus> {
  const body = await request<{ status: SourceStatus }>(sourcePath(source, "status", tenant));
  return body.status;
}

export async function getSourceSchema(source: string): Promise<OcsfSourceSchema> {
  const body = await request<{ schema: OcsfSourceSchema }>(sourcePath(source, "schema"));
  return body.schema;
}

export async function getSourceSample(source: string): Promise<QueryJob> {
  const job = await request<QueryJob>(sourcePath(source, "sample"));
  return waitForQueryJob(job);
}

export async function getSourceHistory(source: string, tenant?: string, limit = 50): Promise<SourceHealthHistoryRow[]> {
  const body = await request<{ history: SourceHealthHistoryRow[] }>(sourcePath(source, "history", tenant, limit));
  return body.history;
}

export async function getSourceErrors(source: string, tenant?: string, limit = 20): Promise<SourceHealthHistoryRow[]> {
  const body = await request<{ errors: SourceHealthHistoryRow[] }>(sourcePath(source, "errors", tenant, limit));
  return body.errors;
}

export async function runSqlQuery(sql: string): Promise<QueryJob> {
  const job = await request<QueryJob>("/api/v1/query", {
    method: "POST",
    body: JSON.stringify({ sql })
  });
  return waitForQueryJob(job);
}

export async function runNaturalQuery(question: string): Promise<QueryJob> {
  const job = await request<QueryJob>("/api/v1/query/natural", {
    method: "POST",
    body: JSON.stringify({ question })
  });
  return waitForQueryJob(job);
}

export async function explainSqlQuery(sql: string): Promise<QueryExplain> {
  const body = await request<{ explain: QueryExplain }>("/api/v1/query/explain", {
    method: "POST",
    body: JSON.stringify({ sql })
  });
  return body.explain;
}

export async function saveSqlQuery(input: { name: string; description?: string; sql: string }): Promise<SavedQueryRow> {
  const body = await request<{ saved: SavedQueryRow }>("/api/v1/query/save", {
    method: "POST",
    body: JSON.stringify(input)
  });
  return body.saved;
}

export async function listSavedQueries(limit = 50): Promise<SavedQueryRow[]> {
  const body = await request<{ saved: SavedQueryRow[] }>(`/api/v1/query/saved?limit=${limit}`);
  return body.saved;
}

export async function listQueryHistory(limit = 50): Promise<QueryHistoryRow[]> {
  const body = await request<{ history: QueryHistoryRow[] }>(`/api/v1/query/history?limit=${limit}`);
  return body.history;
}

async function getQueryJob(id: string): Promise<QueryJob> {
  return request<QueryJob>(`/api/v1/query/${encodeURIComponent(id)}`);
}

async function waitForQueryJob(initial: QueryJob): Promise<QueryJob> {
  if (initial.status === "succeeded") return initial;
  if (initial.status === "failed") throw new Error(initial.error ?? "Query failed");

  const deadline = Date.now() + 5 * 60_000;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    const job = await getQueryJob(initial.id);
    if (job.status === "succeeded") {
      return { ...job, generated_sql: initial.generated_sql, rationale: initial.rationale };
    }
    if (job.status === "failed") throw new Error(job.error ?? "Query failed");
  }
  throw new Error("Query is still running after 5 minutes.");
}

function sourcePath(source: string, action: string, tenant?: string, limit?: number): string {
  const params = new URLSearchParams();
  if (tenant) params.set("tenant", tenant);
  if (limit !== undefined) params.set("limit", String(limit));
  const query = params.size > 0 ? `?${params}` : "";
  return `/api/v1/sources/${encodeURIComponent(source)}/${action}${query}`;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body !== undefined && !headers.has("content-type")) headers.set("content-type", "application/json");
  const response = await fetch(path, {
    ...init,
    headers,
    credentials: "same-origin"
  });
  const text = await response.text();
  const data = text ? safeJson(text) : null;

  if (!response.ok) {
    const message = data && typeof data === "object" && "error" in data ? String(data.error) : `HTTP ${response.status}`;
    throw new ApiError(message, response.status);
  }
  return data as T;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
