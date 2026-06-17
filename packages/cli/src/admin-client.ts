import type { QueryExplain, R2SqlResult } from "@picket/query";
import type { AlertDetail, AlertRow, AlertSeverity, AlertStats, AlertStatus, AlertWithHistory } from "@picket/core/alerts";
import type { SourceHealthRow } from "@picket/core/source-health";
import type { DashboardOverview } from "@picket/core/dashboard";
import type { OcsfSourceSchema, SourceStatus } from "@picket/core/sources";
import type { QueryHistoryRow, SavedQueryRow } from "@picket/core/saved-queries";
import type { DetectionHealthRow } from "@picket/core/detection-health";
import type { DetectionRuleRow } from "@picket/core/detection-rules";
import type { ScheduledDetectionView } from "@picket/core/scheduled-detection";
import type { IndicatorType, IocRecord } from "@picket/core/enrichment";

export interface AssetRecord {
  asset_uid: string;
  hostname?: string;
  ip?: string;
  owner?: string;
  department?: string;
  criticality?: string;
  active?: boolean;
}

export interface UserRecord {
  user_uid: string;
  user_name?: string;
  user_email?: string;
  department?: string;
  title?: string;
  criticality?: string;
  active?: boolean;
}

export interface AdminClientOptions {
  baseUrl: string;
  accessClientId?: string;
  accessClientSecret?: string;
  accessJwt?: string;
  // better-auth bearer token issued by the device-authorization flow. When
  // present, sent as `Authorization: Bearer <token>`; identifies the in-app
  // user for session-gated routes.
  bearerToken?: string;
  // Legacy: a raw `cookie:` header carrying a better-auth session cookie.
  // Kept for backward compat; prefer bearerToken from `picket login`.
  sessionCookie?: string;
  fetch?: typeof fetch;
  uuid?: () => string;
  sleep?: (ms: number) => Promise<void>;
  // Polling tuning. Defaults work for queries that finish in seconds; tests
  // override to keep the suite fast.
  pollInitialMs?: number;
  pollMaxMs?: number;
  pollBackoff?: number;
  pollDeadlineMs?: number;
}

export interface QueryRequestBody {
  preset?: string;
  sql?: string;
  hours?: number;
  limit?: number;
  table_suffix?: string;
  warehouse?: string;
}

export type QueryJobStatus = "pending" | "running" | "succeeded" | "failed";

export interface QueryJob {
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
  result?: R2SqlResult;
  error?: string;
  location?: string;
  idempotency_key?: string | null;
}

// A query job plus the NL-generated SQL (POST /api/v1/query/natural).
export interface NaturalQueryJob extends QueryJob {
  generated_sql?: string;
  rationale?: string | null;
}

export interface RunQueryOptions {
  idempotencyKey?: string;
}

export interface ListAlertsOptions {
  status?: AlertStatus;
  severity?: AlertSeverity;
  limit?: number;
}

export interface ListSourcesOptions {
  tenant?: string;
  source?: string;
}

export class AdminApiError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
    this.name = "AdminApiError";
  }
}

export class QueryJobFailedError extends Error {
  constructor(public readonly job: QueryJob) {
    super(job.error ?? `Query job ${job.id} failed`);
    this.name = "QueryJobFailedError";
  }
}

export class AdminClient {
  private readonly fetchImpl: typeof fetch;
  private readonly newUuid: () => string;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly pollInitialMs: number;
  private readonly pollMaxMs: number;
  private readonly pollBackoff: number;
  private readonly pollDeadlineMs: number;

  constructor(private readonly options: AdminClientOptions) {
    this.fetchImpl = options.fetch ?? fetch;
    this.newUuid = options.uuid ?? (() => crypto.randomUUID());
    this.sleep =
      options.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.pollInitialMs = options.pollInitialMs ?? 1_000;
    this.pollMaxMs = options.pollMaxMs ?? 5_000;
    this.pollBackoff = options.pollBackoff ?? 1.5;
    this.pollDeadlineMs = options.pollDeadlineMs ?? 5 * 60 * 1_000;
  }

  // Submit a query. Returns the job in whatever state the server returned:
  // - 200: long-poll caught it → status=succeeded with `result`
  // - 202: still running → status=pending|running, no `result` yet
  // Callers decide whether to poll (waitForJob) or stop here.
  async submitQuery(body: QueryRequestBody, opts: RunQueryOptions = {}): Promise<QueryJob> {
    const idempotencyKey = opts.idempotencyKey ?? this.newUuid();
    return this.request("POST", "/api/v1/query", body, { "idempotency-key": idempotencyKey });
  }

  async explainQuery(body: QueryRequestBody): Promise<QueryExplain> {
    const res = await this.requestJson("POST", "/api/v1/query/explain", body);
    return (res as { explain: QueryExplain }).explain;
  }

  async saveQuery(body: QueryRequestBody & { name: string; description?: string }): Promise<SavedQueryRow> {
    const res = await this.requestJson("POST", "/api/v1/query/save", body);
    return (res as { saved: SavedQueryRow }).saved;
  }

  async listSavedQueries(options: { owner?: string; limit?: number } = {}): Promise<SavedQueryRow[]> {
    const params = new URLSearchParams();
    if (options.owner) params.set("owner", options.owner);
    if (options.limit !== undefined) params.set("limit", String(options.limit));
    const suffix = params.size > 0 ? `?${params}` : "";
    const res = await this.requestJson("GET", `/api/v1/query/saved${suffix}`);
    return (res as { saved: SavedQueryRow[] }).saved;
  }

  async listQueryHistory(options: { owner?: string; limit?: number } = {}): Promise<QueryHistoryRow[]> {
    const params = new URLSearchParams();
    if (options.owner) params.set("owner", options.owner);
    if (options.limit !== undefined) params.set("limit", String(options.limit));
    const suffix = params.size > 0 ? `?${params}` : "";
    const res = await this.requestJson("GET", `/api/v1/query/history${suffix}`);
    return (res as { history: QueryHistoryRow[] }).history;
  }

  async naturalQuery(question: string): Promise<NaturalQueryJob> {
    return this.requestJson("POST", "/api/v1/query/natural", { question }) as Promise<NaturalQueryJob>;
  }

  async getJob(id: string): Promise<QueryJob> {
    return this.request("GET", `/api/v1/query/${encodeURIComponent(id)}`);
  }

  async waitForJob(id: string): Promise<QueryJob> {
    const deadline = Date.now() + this.pollDeadlineMs;
    let interval = this.pollInitialMs;
    for (;;) {
      const job = await this.getJob(id);
      if (job.status === "succeeded") return job;
      if (job.status === "failed") throw new QueryJobFailedError(job);
      if (Date.now() >= deadline) {
        throw new AdminApiError(`Query job ${id} did not complete within deadline`, 504);
      }
      await this.sleep(interval);
      interval = Math.min(this.pollMaxMs, Math.round(interval * this.pollBackoff));
    }
  }

  async runQuery(body: QueryRequestBody, opts: RunQueryOptions = {}): Promise<QueryJob> {
    const submitted = await this.submitQuery(body, opts);
    if (submitted.status === "succeeded") return submitted;
    if (submitted.status === "failed") throw new QueryJobFailedError(submitted);
    return this.waitForJob(submitted.id);
  }

  async listAlerts(options: ListAlertsOptions = {}): Promise<AlertRow[]> {
    const params = new URLSearchParams();
    if (options.status) params.set("status", options.status);
    if (options.severity) params.set("severity", options.severity);
    if (options.limit !== undefined) params.set("limit", String(options.limit));
    const suffix = params.size > 0 ? `?${params}` : "";
    const body = await this.requestJson("GET", `/api/v1/alerts${suffix}`);
    return (body as { alerts: AlertRow[] }).alerts;
  }

  async getAlertStats(): Promise<AlertStats> {
    const body = await this.requestJson("GET", "/api/v1/alerts/stats");
    return (body as { stats: AlertStats }).stats;
  }

  async getAlert(id: string): Promise<AlertWithHistory> {
    return this.requestJson("GET", `/api/v1/alerts/${encodeURIComponent(id)}`) as Promise<AlertWithHistory>;
  }

  async acknowledgeAlert(id: string, by?: string): Promise<{ alert: AlertRow; acknowledged_by: string }> {
    return this.requestJson("POST", `/api/v1/alerts/${encodeURIComponent(id)}/ack`, actorBody(by)) as Promise<{
      alert: AlertRow;
      acknowledged_by: string;
    }>;
  }

  async resolveAlert(id: string, by?: string): Promise<{ alert: AlertRow; resolved_by: string }> {
    return this.requestJson("POST", `/api/v1/alerts/${encodeURIComponent(id)}/resolve`, actorBody(by)) as Promise<{
      alert: AlertRow;
      resolved_by: string;
    }>;
  }

  async reopenAlert(id: string, by?: string): Promise<{ alert: AlertRow; reopened_by: string }> {
    return this.requestJson("POST", `/api/v1/alerts/${encodeURIComponent(id)}/reopen`, actorBody(by)) as Promise<{
      alert: AlertRow;
      reopened_by: string;
    }>;
  }

  async assignAlert(id: string, assignee: string | null, by?: string): Promise<{ alert: AlertDetail; updated_by: string }> {
    return this.requestJson("PATCH", `/api/v1/alerts/${encodeURIComponent(id)}`, {
      assignee,
      ...(by ? { by } : {})
    }) as Promise<{ alert: AlertDetail; updated_by: string }>;
  }

  async addAlertNote(id: string, body: string, by?: string): Promise<{ note: unknown; author: string }> {
    return this.requestJson("POST", `/api/v1/alerts/${encodeURIComponent(id)}/notes`, {
      body,
      ...(by ? { by } : {})
    }) as Promise<{ note: unknown; author: string }>;
  }

  async getDetectionHealth(): Promise<DetectionHealthRow | null> {
    const body = await this.requestJson("GET", "/api/v1/detections/health");
    return (body as { detection_health: DetectionHealthRow | null }).detection_health;
  }

  async listDetections(options: { enabled?: boolean; source?: string } = {}): Promise<DetectionRuleRow[]> {
    const params = new URLSearchParams();
    if (options.enabled !== undefined) params.set("enabled", String(options.enabled));
    if (options.source) params.set("source", options.source);
    const suffix = params.size > 0 ? `?${params}` : "";
    const body = await this.requestJson("GET", `/api/v1/detections${suffix}`);
    return (body as { rules: DetectionRuleRow[] }).rules;
  }

  async listScheduledDetections(): Promise<ScheduledDetectionView[]> {
    const body = await this.requestJson("GET", "/api/v1/detections/scheduled");
    return (body as { scheduled: ScheduledDetectionView[] }).scheduled;
  }

  async getDetection(id: string): Promise<DetectionRuleRow> {
    const body = await this.requestJson("GET", `/api/v1/detections/${encodeURIComponent(id)}`);
    return (body as { rule: DetectionRuleRow }).rule;
  }

  async setDetectionEnabled(id: string, enabled: boolean): Promise<DetectionRuleRow> {
    const body = await this.requestJson("PATCH", `/api/v1/detections/${encodeURIComponent(id)}`, { enabled });
    return (body as { rule: DetectionRuleRow }).rule;
  }

  async getDashboardOverview(options: { tenant?: string } = {}): Promise<DashboardOverview> {
    const params = new URLSearchParams();
    if (options.tenant) params.set("tenant", options.tenant);
    const suffix = params.size > 0 ? `?${params}` : "";
    const body = await this.requestJson("GET", `/api/v1/dashboard/overview${suffix}`);
    return (body as { overview: DashboardOverview }).overview;
  }

  async listSources(options: ListSourcesOptions = {}): Promise<SourceHealthRow[]> {
    const params = new URLSearchParams();
    if (options.tenant) params.set("tenant", options.tenant);
    if (options.source) params.set("source", options.source);
    const suffix = params.size > 0 ? `?${params}` : "";
    const body = await this.requestJson("GET", `/api/v1/sources${suffix}`);
    return (body as { sources: SourceHealthRow[] }).sources;
  }

  async getSourceStatus(id: string, tenant?: string): Promise<SourceStatus> {
    const params = new URLSearchParams();
    if (tenant) params.set("tenant", tenant);
    const suffix = params.size > 0 ? `?${params}` : "";
    const body = await this.requestJson("GET", `/api/v1/sources/${encodeURIComponent(id)}/status${suffix}`);
    return (body as { status: SourceStatus }).status;
  }

  async getSourceSchema(id: string): Promise<OcsfSourceSchema> {
    const body = await this.requestJson("GET", `/api/v1/sources/${encodeURIComponent(id)}/schema`);
    return (body as { schema: OcsfSourceSchema }).schema;
  }

  // Returns the query job for the source's recent-events sample. Mirrors the
  // submitQuery response: 200 → succeeded with `result`, 202 → still running.
  async sampleSource(id: string): Promise<QueryJob> {
    return this.request("GET", `/api/v1/sources/${encodeURIComponent(id)}/sample`);
  }

  async listIocs(options: { type?: IndicatorType; limit?: number } = {}): Promise<IocRecord[]> {
    const params = new URLSearchParams();
    if (options.type) params.set("type", options.type);
    if (options.limit !== undefined) params.set("limit", String(options.limit));
    const suffix = params.size > 0 ? `?${params}` : "";
    const body = await this.requestJson("GET", `/api/v1/enrichment/iocs${suffix}`);
    return (body as { iocs: IocRecord[] }).iocs;
  }

  async addIocs(iocs: IocRecord[]): Promise<number> {
    const body = await this.requestJson("POST", "/api/v1/enrichment/iocs", { iocs });
    return (body as { written: number }).written;
  }

  async importIocCsv(csv: string, options: { feed?: string; threatType?: string } = {}): Promise<number> {
    const params = new URLSearchParams();
    if (options.feed) params.set("feed", options.feed);
    if (options.threatType) params.set("threat_type", options.threatType);
    const suffix = params.size > 0 ? `?${params}` : "";
    const body = await this.requestRawJson("POST", `/api/v1/enrichment/iocs/import${suffix}`, csv, {
      "content-type": "text/csv"
    });
    return (body as { written: number }).written;
  }

  async loadAssets(assets: AssetRecord[]): Promise<number> {
    const body = await this.requestJson("POST", "/api/v1/enrichment/assets", { assets });
    return (body as { written: number }).written;
  }

  async loadUsers(users: UserRecord[]): Promise<number> {
    const body = await this.requestJson("POST", "/api/v1/enrichment/users", { users });
    return (body as { written: number }).written;
  }

  async deleteIoc(type: IndicatorType, indicator: string): Promise<void> {
    await this.requestJson(
      "DELETE",
      `/api/v1/enrichment/iocs/${encodeURIComponent(type)}/${encodeURIComponent(indicator)}`
    );
  }

  private async request(
    method: string,
    path: string,
    body?: unknown,
    extraHeaders: Record<string, string> = {}
  ): Promise<QueryJob> {
    return this.requestJson(method, path, body, extraHeaders) as Promise<QueryJob>;
  }

  private async requestJson(
    method: string,
    path: string,
    body?: unknown,
    extraHeaders: Record<string, string> = {}
  ): Promise<unknown> {
    return this.requestRawJson(
      method,
      path,
      body === undefined ? undefined : JSON.stringify(body),
      extraHeaders
    );
  }

  private async requestRawJson(
    method: string,
    path: string,
    body?: string,
    extraHeaders: Record<string, string> = {}
  ): Promise<unknown> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      ...extraHeaders
    };
    if (this.options.accessClientId && this.options.accessClientSecret) {
      headers["cf-access-client-id"] = this.options.accessClientId;
      headers["cf-access-client-secret"] = this.options.accessClientSecret;
    }
    if (this.options.accessJwt) {
      headers["cf-access-jwt-assertion"] = this.options.accessJwt;
    }
    if (this.options.bearerToken) {
      headers.authorization = `Bearer ${this.options.bearerToken}`;
    }
    if (this.options.sessionCookie) {
      headers.cookie = this.options.sessionCookie;
    }

    const res = await this.fetchImpl(`${this.options.baseUrl}${path}`, {
      method,
      headers,
      body
    });

    const text = await res.text();
    let parsed: unknown;
    try {
      parsed = text.length === 0 ? null : JSON.parse(text);
    } catch {
      throw new AdminApiError(
        `Non-JSON response from admin API (HTTP ${res.status}): ${text.slice(0, 200)}`,
        res.status
      );
    }

    if (!res.ok) {
      const msg =
        parsed && typeof parsed === "object" && "error" in parsed
          ? String((parsed as { error: unknown }).error)
          : `HTTP ${res.status}`;
      throw new AdminApiError(msg, res.status);
    }

    return parsed;
  }
}

function actorBody(by: string | undefined): { by: string } | undefined {
  return by ? { by } : undefined;
}

export type { R2SqlResult };
