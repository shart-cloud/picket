import type { AlertStateDb, AlertStateStatement } from "./alerts.js";

export interface FakeAlertRow {
  id: string;
  rule_id: string;
  title: string;
  severity: string;
  source: string;
  status: string;
  match_count: number;
  first_seen: string;
  last_seen: string;
  updated_at: string;
  acknowledged_at?: string | null;
  acknowledged_by?: string | null;
  resolved_at?: string | null;
  resolved_by?: string | null;
  assignee?: string | null;
  event_json?: string;
}

export interface FakeTimelineRow {
  id: string;
  alert_id: string;
  action: string;
  actor: string | null;
  body: string | null;
  metadata_json: string | null;
  created_at: string;
}

export interface FakeNoteRow {
  id: string;
  alert_id: string;
  body: string;
  author: string | null;
  created_at: string;
}

export interface FakeSourceHealthRow {
  source: string;
  tenant_id: string;
  last_event_at: string | null;
  last_event_count: number;
  total_events: number;
  total_batches: number;
  total_errors: number;
  last_error_at: string | null;
  last_error_message: string | null;
  updated_at: string;
}

export interface FakeSourceHealthHistoryRow {
  id: number;
  source: string;
  tenant_id: string;
  kind: "batch" | "error";
  event_count: number;
  last_event_at: string | null;
  error_message: string | null;
  recorded_at: string;
}

export interface FakeDetectionHealthRow {
  last_eval_at: string | null;
  total_events_evaluated: number;
  total_alerts_created: number;
  stateless_rule_count: number;
  stateful_rule_count: number;
  updated_at: string | null;
}

export interface FakeDetectionRuleRow {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  source: string;
  class_name: string | null;
  execution: string;
  tags_json: string;
  enabled: number;
  definition_json: string;
  match_count: number;
  last_triggered_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface FakeSavedQueryRow {
  id: string;
  owner: string;
  name: string;
  description: string | null;
  sql: string;
  preset: string | null;
  created_at: string;
  updated_at: string;
}

export interface FakeQueryHistoryRow {
  id: string;
  owner: string | null;
  sql: string;
  preset: string | null;
  job_id: string | null;
  created_at: string;
}

export interface FakeScheduledStateRow {
  rule_id: string;
  last_run_at: string | null;
  last_status: string | null;
  last_row_count: number | null;
  last_alert_count: number | null;
  last_error: string | null;
  updated_at: string;
}

export class FakeAlertDb implements AlertStateDb {
  readonly alerts: FakeAlertRow[];
  readonly timeline: FakeTimelineRow[] = [];
  readonly notes: FakeNoteRow[] = [];
  readonly sourceHealth: FakeSourceHealthRow[] = [];
  readonly sourceHealthHistory: FakeSourceHealthHistoryRow[] = [];
  readonly detectionRules: FakeDetectionRuleRow[] = [];
  readonly savedQueries: FakeSavedQueryRow[] = [];
  readonly queryHistory: FakeQueryHistoryRow[] = [];
  readonly scheduledState: FakeScheduledStateRow[] = [];
  detectionHealth: FakeDetectionHealthRow | null = null;
  private clock = 0;

  constructor(seed: FakeAlertRow[] = []) {
    this.alerts = [...seed];
  }

  nextTimestamp(): string {
    this.clock += 1;
    return `2026-05-26T20:00:${String(this.clock).padStart(2, "0")}.000Z`;
  }

  prepare(sql: string): AlertStateStatement {
    return new FakeStatement(this, sql, []);
  }
}

class FakeStatement implements AlertStateStatement {
  constructor(
    private readonly db: FakeAlertDb,
    private readonly sql: string,
    private readonly params: readonly unknown[]
  ) {}

  bind(...params: unknown[]): AlertStateStatement {
    return new FakeStatement(this.db, this.sql, params);
  }

  async first<T = unknown>(): Promise<T | null> {
    const results = this.exec<T>();
    return results[0] ?? null;
  }

  async all<T = unknown>(): Promise<{ results: T[] }> {
    return { results: this.exec<T>() };
  }

  async run(): Promise<unknown> {
    this.exec<unknown>();
    return { success: true };
  }

  private exec<T>(): T[] {
    const normalized = this.sql.trim().replace(/\s+/g, " ");

    if (normalized.startsWith("SELECT id FROM alerts WHERE id = ?")) {
      const [id] = this.params as [string];
      const row = this.db.alerts.find((alert) => alert.id === id);
      return row ? ([{ id: row.id }] as unknown as T[]) : [];
    }

    if (normalized.startsWith("SELECT status FROM alerts WHERE id = ?")) {
      const [id] = this.params as [string];
      const row = this.db.alerts.find((alert) => alert.id === id);
      return row ? ([{ status: row.status }] as unknown as T[]) : [];
    }

    if (normalized.startsWith("SELECT id, rule_id, title, severity, source, status, match_count, first_seen, last_seen, updated_at, acknowledged_at, acknowledged_by, resolved_at, resolved_by, assignee, event_json FROM alerts WHERE id = ?")) {
      const [id] = this.params as [string];
      const row = this.db.alerts.find((alert) => alert.id === id);
      return row ? ([projectAlertDetail(row)] as unknown as T[]) : [];
    }

    const groupCountMatch = normalized.match(
      /^SELECT (\w+) AS key, COUNT\(\*\) AS count FROM alerts GROUP BY \w+$/
    );
    if (groupCountMatch) {
      const column = groupCountMatch[1] as keyof FakeAlertRow;
      const counts = new Map<string, number>();
      for (const alert of this.db.alerts) {
        const key = String(alert[column]);
        counts.set(key, (counts.get(key) ?? 0) + 1);
      }
      return [...counts.entries()].map(([key, count]) => ({ key, count })) as unknown as T[];
    }

    if (normalized.startsWith("SELECT COUNT(*) AS count FROM alerts")) {
      const rows = filterAlertRows(this.db.alerts, normalized, [...this.params]);
      return [{ count: rows.length }] as unknown as T[];
    }

    if (normalized.startsWith("SELECT id, rule_id, title, severity, source, status, match_count, first_seen, last_seen, updated_at FROM alerts WHERE id = ?")) {
      const [id] = this.params as [string];
      const row = this.db.alerts.find((alert) => alert.id === id);
      return row ? ([projectAlert(row)] as unknown as T[]) : [];
    }

    if (normalized.startsWith("SELECT id, rule_id, title, severity, source, status, match_count, first_seen, last_seen, updated_at FROM alerts")) {
      const paramQueue = [...this.params];
      const rows = filterAlertRows(this.db.alerts, normalized, paramQueue);
      const limit = paramQueue.shift() as number;
      const offset = paramQueue.shift() as number;
      sortAlertRows(rows, normalized);
      return rows.slice(offset, offset + limit).map(projectAlert) as unknown as T[];
    }

    if (normalized.startsWith("SELECT id, action, actor, body, metadata_json, created_at FROM alert_timeline WHERE alert_id = ?")) {
      const [alertId] = this.params as [string];
      const rows = this.db.timeline
        .filter((entry) => entry.alert_id === alertId)
        .sort((left, right) => left.created_at.localeCompare(right.created_at))
        .map(({ id, action, actor, body, metadata_json, created_at }) => ({
          id,
          action,
          actor,
          body,
          metadata_json,
          created_at
        }));
      return rows as unknown as T[];
    }

    if (normalized.startsWith("SELECT id, body, author, created_at FROM alert_notes WHERE alert_id = ?")) {
      const [alertId] = this.params as [string];
      const rows = this.db.notes
        .filter((note) => note.alert_id === alertId)
        .sort((left, right) => left.created_at.localeCompare(right.created_at))
        .map(({ id, body, author, created_at }) => ({ id, body, author, created_at }));
      return rows as unknown as T[];
    }

    if (normalized.startsWith("SELECT id, body, author, created_at FROM alert_notes WHERE id = ?")) {
      const [noteId] = this.params as [string];
      const note = this.db.notes.find((entry) => entry.id === noteId);
      if (!note) return [];
      const { id, body, author, created_at } = note;
      return [{ id, body, author, created_at }] as unknown as T[];
    }

    if (normalized.startsWith("UPDATE alerts SET status = 'acknowledged'")) {
      const [acknowledgedAt, acknowledgedBy, updatedAt, id] = this.params as [string, string, string, string];
      const row = this.db.alerts.find((alert) => alert.id === id);
      if (row) {
        row.status = "acknowledged";
        row.acknowledged_at = acknowledgedAt;
        row.acknowledged_by = acknowledgedBy;
        row.updated_at = updatedAt;
      }
      return [];
    }

    if (normalized.startsWith("UPDATE alerts SET assignee = ?")) {
      const [assignee, updatedAt, id] = this.params as [string | null, string, string];
      const row = this.db.alerts.find((alert) => alert.id === id);
      if (row) {
        row.assignee = assignee;
        row.updated_at = updatedAt;
      }
      return [];
    }

    if (normalized.startsWith("UPDATE alerts SET status = 'open'")) {
      const [updatedAt, id] = this.params as [string, string];
      const row = this.db.alerts.find((alert) => alert.id === id);
      if (row) {
        row.status = "open";
        row.resolved_at = null;
        row.resolved_by = null;
        row.updated_at = updatedAt;
      }
      return [];
    }

    if (normalized.startsWith("UPDATE alerts SET status = 'resolved'")) {
      const [resolvedAt, resolvedBy, updatedAt, id] = this.params as [string, string, string, string];
      const row = this.db.alerts.find((alert) => alert.id === id);
      if (row) {
        row.status = "resolved";
        row.resolved_at = resolvedAt;
        row.resolved_by = resolvedBy;
        row.updated_at = updatedAt;
      }
      return [];
    }

    if (normalized.startsWith("INSERT INTO alert_timeline (id, alert_id, action, actor, body, metadata_json)")) {
      const action = extractQuoted(normalized, "VALUES (?, ?, '", "',");
      const [id, alertId, actor, body, metadataJson] = this.params as [
        string,
        string,
        string,
        string,
        string
      ];
      this.db.timeline.push({
        id,
        alert_id: alertId,
        action: action ?? "unknown",
        actor,
        body,
        metadata_json: metadataJson,
        created_at: this.db.nextTimestamp()
      });
      return [];
    }

    if (normalized.startsWith("INSERT INTO alert_timeline")) {
      const action = extractQuoted(normalized, "VALUES (?, ?, '", "',");
      const [id, alertId, actor, metadataJson] = this.params as [string, string, string, string];
      this.db.timeline.push({
        id,
        alert_id: alertId,
        action: action ?? "unknown",
        actor,
        body: null,
        metadata_json: metadataJson,
        created_at: this.db.nextTimestamp()
      });
      return [];
    }

    if (normalized.startsWith("SELECT source, tenant_id, last_event_at, last_event_count, total_events, total_batches, total_errors, last_error_at, last_error_message, updated_at FROM source_health")) {
      let rows = [...this.db.sourceHealth];
      const paramQueue = [...this.params];
      if (normalized.includes("source = ? AND tenant_id = ?")) {
        const source = paramQueue.shift() as string;
        const tenantId = paramQueue.shift() as string;
        rows = rows.filter((row) => row.source === source && row.tenant_id === tenantId);
      } else if (normalized.includes("source = ?")) {
        const source = paramQueue.shift() as string;
        rows = rows.filter((row) => row.source === source);
      } else if (normalized.includes("tenant_id = ?")) {
        const tenantId = paramQueue.shift() as string;
        rows = rows.filter((row) => row.tenant_id === tenantId);
      }
      rows.sort((left, right) => left.source.localeCompare(right.source));
      return rows.map(projectSourceHealth) as unknown as T[];
    }

    if (
      normalized.startsWith(
        "INSERT INTO source_health ( source, tenant_id, last_event_at, last_event_count, total_events, total_batches, total_errors, updated_at )"
      )
    ) {
      const [source, tenantId, lastEventAt, lastEventCount, totalEventsDelta, updatedAt] =
        this.params as [string, string, string | null, number, number, string];
      let row = this.db.sourceHealth.find(
        (entry) => entry.source === source && entry.tenant_id === tenantId
      );
      if (!row) {
        row = {
          source,
          tenant_id: tenantId,
          last_event_at: lastEventAt,
          last_event_count: lastEventCount,
          total_events: totalEventsDelta,
          total_batches: 1,
          total_errors: 0,
          last_error_at: null,
          last_error_message: null,
          updated_at: updatedAt
        };
        this.db.sourceHealth.push(row);
      } else {
        if (lastEventAt !== null) {
          if (row.last_event_at === null || lastEventAt >= row.last_event_at) {
            row.last_event_at = lastEventAt;
          }
        }
        row.last_event_count = lastEventCount;
        row.total_events += totalEventsDelta;
        row.total_batches += 1;
        row.updated_at = updatedAt;
      }
      return [];
    }

    if (
      normalized.startsWith(
        "INSERT INTO source_health ( source, tenant_id, total_errors, last_error_at, last_error_message, updated_at )"
      )
    ) {
      const [source, tenantId, lastErrorAt, lastErrorMessage, updatedAt] = this.params as [
        string,
        string,
        string,
        string,
        string
      ];
      let row = this.db.sourceHealth.find(
        (entry) => entry.source === source && entry.tenant_id === tenantId
      );
      if (!row) {
        row = {
          source,
          tenant_id: tenantId,
          last_event_at: null,
          last_event_count: 0,
          total_events: 0,
          total_batches: 0,
          total_errors: 1,
          last_error_at: lastErrorAt,
          last_error_message: lastErrorMessage,
          updated_at: updatedAt
        };
        this.db.sourceHealth.push(row);
      } else {
        row.total_errors += 1;
        row.last_error_at = lastErrorAt;
        row.last_error_message = lastErrorMessage;
        row.updated_at = updatedAt;
      }
      return [];
    }

    if (normalized.startsWith("INSERT INTO source_health_history")) {
      const [source, tenantId, kind, eventCount, lastEventAt, errorMessage, recordedAt] = this.params as [
        string,
        string,
        "batch" | "error",
        number,
        string | null,
        string | null,
        string
      ];
      this.db.sourceHealthHistory.push({
        id: this.db.sourceHealthHistory.length + 1,
        source,
        tenant_id: tenantId,
        kind,
        event_count: eventCount,
        last_event_at: lastEventAt,
        error_message: errorMessage,
        recorded_at: recordedAt
      });
      return [];
    }

    if (normalized.startsWith("SELECT id, source, tenant_id, kind, event_count, last_event_at, error_message, recorded_at FROM source_health_history")) {
      const params = [...this.params];
      const source = params.shift() as string;
      let rows = this.db.sourceHealthHistory.filter((row) => row.source === source);
      if (normalized.includes("tenant_id = ?")) {
        const tenantId = params.shift() as string;
        rows = rows.filter((row) => row.tenant_id === tenantId);
      }
      if (normalized.includes("kind = ?")) {
        const kind = params.shift() as "batch" | "error";
        rows = rows.filter((row) => row.kind === kind);
      }
      const limit = params.shift() as number;
      return rows
        .sort((left, right) => right.recorded_at.localeCompare(left.recorded_at) || right.id - left.id)
        .slice(0, limit)
        .map((row) => ({ ...row })) as unknown as T[];
    }

    if (normalized.startsWith("SELECT last_eval_at, total_events_evaluated, total_alerts_created, stateless_rule_count, stateful_rule_count, updated_at FROM detection_health WHERE id = 1")) {
      return this.db.detectionHealth ? ([{ ...this.db.detectionHealth }] as unknown as T[]) : [];
    }

    if (normalized.startsWith("INSERT INTO detection_health")) {
      const [lastEvalAt, events, alerts, statelessCount, statefulCount, updatedAt] = this.params as [
        string,
        number,
        number,
        number,
        number,
        string
      ];
      if (!this.db.detectionHealth) {
        this.db.detectionHealth = {
          last_eval_at: lastEvalAt,
          total_events_evaluated: events,
          total_alerts_created: alerts,
          stateless_rule_count: statelessCount,
          stateful_rule_count: statefulCount,
          updated_at: updatedAt
        };
      } else {
        this.db.detectionHealth.last_eval_at = lastEvalAt;
        this.db.detectionHealth.total_events_evaluated += events;
        this.db.detectionHealth.total_alerts_created += alerts;
        this.db.detectionHealth.stateless_rule_count = statelessCount;
        this.db.detectionHealth.stateful_rule_count = statefulCount;
        this.db.detectionHealth.updated_at = updatedAt;
      }
      return [];
    }

    if (normalized.startsWith("INSERT INTO detection_rules")) {
      const [id, title, description, severity, source, className, execution, tagsJson, enabled, definitionJson, updatedAt] =
        this.params as [string, string, string | null, string, string, string | null, string, string, number, string, string];
      const existing = this.db.detectionRules.find((rule) => rule.id === id);
      if (existing) {
        // Mirror real ON CONFLICT: refresh static fields, preserve enabled + stats.
        existing.title = title;
        existing.description = description;
        existing.severity = severity;
        existing.source = source;
        existing.class_name = className;
        existing.execution = execution;
        existing.tags_json = tagsJson;
        existing.definition_json = definitionJson;
        existing.updated_at = updatedAt;
      } else {
        this.db.detectionRules.push({
          id,
          title,
          description,
          severity,
          source,
          class_name: className,
          execution,
          tags_json: tagsJson,
          enabled,
          definition_json: definitionJson,
          match_count: 0,
          last_triggered_at: null,
          created_at: updatedAt,
          updated_at: updatedAt
        });
      }
      return [];
    }

    if (normalized.startsWith("SELECT id FROM detection_rules WHERE enabled = 0")) {
      return this.db.detectionRules.filter((rule) => rule.enabled === 0).map((rule) => ({ id: rule.id })) as unknown as T[];
    }

    if (normalized.startsWith("SELECT id FROM detection_rules WHERE id = ?")) {
      const [id] = this.params as [string];
      const row = this.db.detectionRules.find((rule) => rule.id === id);
      return row ? ([{ id: row.id }] as unknown as T[]) : [];
    }

    if (
      normalized.startsWith(
        "SELECT id, title, description, severity, source, class_name, execution, tags_json, enabled, definition_json, match_count, last_triggered_at, created_at, updated_at FROM detection_rules WHERE id = ?"
      )
    ) {
      const [id] = this.params as [string];
      const row = this.db.detectionRules.find((rule) => rule.id === id);
      return row ? ([{ ...row }] as unknown as T[]) : [];
    }

    if (
      normalized.startsWith(
        "SELECT id, title, description, severity, source, class_name, execution, tags_json, enabled, definition_json, match_count, last_triggered_at, created_at, updated_at FROM detection_rules"
      )
    ) {
      let rows = [...this.db.detectionRules];
      const paramQueue = [...this.params];
      if (normalized.includes("enabled = ?")) {
        const value = paramQueue.shift() as number;
        rows = rows.filter((rule) => rule.enabled === value);
      }
      if (normalized.includes("source = ?")) {
        const value = paramQueue.shift() as string;
        rows = rows.filter((rule) => rule.source === value);
      }
      rows.sort((left, right) => left.id.localeCompare(right.id));
      return rows.map((rule) => ({ ...rule })) as unknown as T[];
    }

    if (normalized.startsWith("UPDATE detection_rules SET enabled = ?")) {
      const [enabled, updatedAt, id] = this.params as [number, string, string];
      const row = this.db.detectionRules.find((rule) => rule.id === id);
      if (row) {
        row.enabled = enabled;
        row.updated_at = updatedAt;
      }
      return [];
    }

    if (normalized.startsWith("UPDATE detection_rules SET match_count = match_count + 1")) {
      const [lastTriggeredAt, updatedAt, id] = this.params as [string, string, string];
      const row = this.db.detectionRules.find((rule) => rule.id === id);
      if (row) {
        row.match_count += 1;
        row.last_triggered_at = lastTriggeredAt;
        row.updated_at = updatedAt;
      }
      return [];
    }

    if (normalized.startsWith("INSERT INTO saved_queries (id, owner, name, description, sql, preset, created_at, updated_at)")) {
      const [id, owner, name, description, sql, preset, createdAt, updatedAt] = this.params as [
        string,
        string,
        string,
        string | null,
        string,
        string | null,
        string,
        string
      ];
      const existing = this.db.savedQueries.find((row) => row.owner === owner && row.name === name);
      if (existing) {
        existing.description = description;
        existing.sql = sql;
        existing.preset = preset;
        existing.updated_at = updatedAt;
      } else {
        this.db.savedQueries.push({
          id,
          owner,
          name,
          description,
          sql,
          preset,
          created_at: createdAt,
          updated_at: updatedAt
        });
      }
      return [];
    }

    if (
      normalized.startsWith(
        "SELECT id, owner, name, description, sql, preset, created_at, updated_at FROM saved_queries WHERE owner = ? AND name = ?"
      )
    ) {
      const [owner, name] = this.params as [string, string];
      const row = this.db.savedQueries.find((entry) => entry.owner === owner && entry.name === name);
      return row ? ([{ ...row }] as unknown as T[]) : [];
    }

    if (
      normalized.startsWith(
        "SELECT id, owner, name, description, sql, preset, created_at, updated_at FROM saved_queries"
      )
    ) {
      let rows = [...this.db.savedQueries];
      const paramQueue = [...this.params];
      if (normalized.includes("WHERE owner = ?")) {
        const owner = paramQueue.shift() as string;
        rows = rows.filter((row) => row.owner === owner);
      }
      const limit = paramQueue.shift() as number;
      rows.sort((left, right) => right.updated_at.localeCompare(left.updated_at));
      return rows.slice(0, limit).map((row) => ({ ...row })) as unknown as T[];
    }

    if (normalized.startsWith("INSERT INTO query_history (id, owner, sql, preset, job_id, created_at)")) {
      const [id, owner, sql, preset, jobId, createdAt] = this.params as [
        string,
        string | null,
        string,
        string | null,
        string | null,
        string
      ];
      this.db.queryHistory.push({ id, owner, sql, preset, job_id: jobId, created_at: createdAt });
      return [];
    }

    if (normalized.startsWith("SELECT id, owner, sql, preset, job_id, created_at FROM query_history")) {
      let rows = [...this.db.queryHistory];
      const paramQueue = [...this.params];
      if (normalized.includes("WHERE owner = ?")) {
        const owner = paramQueue.shift() as string;
        rows = rows.filter((row) => row.owner === owner);
      }
      const limit = paramQueue.shift() as number;
      rows.sort((left, right) => right.created_at.localeCompare(left.created_at));
      return rows.slice(0, limit).map((row) => ({ ...row })) as unknown as T[];
    }

    if (normalized.startsWith("SELECT rule_id, last_run_at, last_status, last_row_count, last_alert_count, last_error, updated_at FROM scheduled_detection_state WHERE rule_id = ?")) {
      const [ruleId] = this.params as [string];
      const row = this.db.scheduledState.find((entry) => entry.rule_id === ruleId);
      return row ? ([{ ...row }] as unknown as T[]) : [];
    }

    if (normalized.startsWith("SELECT rule_id, last_run_at, last_status, last_row_count, last_alert_count, last_error, updated_at FROM scheduled_detection_state")) {
      return [...this.db.scheduledState]
        .sort((left, right) => left.rule_id.localeCompare(right.rule_id))
        .map((row) => ({ ...row })) as unknown as T[];
    }

    if (normalized.startsWith("INSERT INTO scheduled_detection_state")) {
      const [ruleId, lastRunAt, lastStatus, lastRowCount, lastAlertCount, lastError, updatedAt] = this.params as [
        string,
        string | null,
        string | null,
        number | null,
        number | null,
        string | null,
        string
      ];
      const existing = this.db.scheduledState.find((entry) => entry.rule_id === ruleId);
      if (existing) {
        existing.last_run_at = lastRunAt;
        existing.last_status = lastStatus;
        existing.last_row_count = lastRowCount;
        existing.last_alert_count = lastAlertCount;
        existing.last_error = lastError;
        existing.updated_at = updatedAt;
      } else {
        this.db.scheduledState.push({
          rule_id: ruleId,
          last_run_at: lastRunAt,
          last_status: lastStatus,
          last_row_count: lastRowCount,
          last_alert_count: lastAlertCount,
          last_error: lastError,
          updated_at: updatedAt
        });
      }
      return [];
    }

    if (normalized.startsWith("INSERT INTO alert_notes")) {
      const [id, alertId, body, author] = this.params as [string, string, string, string];
      this.db.notes.push({
        id,
        alert_id: alertId,
        body,
        author,
        created_at: this.db.nextTimestamp()
      });
      return [];
    }

    throw new Error(`FakeAlertDb: unsupported SQL: ${normalized}`);
  }
}

function filterAlertRows(rows: readonly FakeAlertRow[], normalized: string, paramQueue: unknown[]): FakeAlertRow[] {
  let filtered = [...rows];
  if (normalized.includes("status = ?")) {
    const value = paramQueue.shift() as string;
    filtered = filtered.filter((row) => row.status === value);
  }
  if (normalized.includes("severity = ?")) {
    const value = paramQueue.shift() as string;
    filtered = filtered.filter((row) => row.severity === value);
  }
  if (normalized.includes("rule_id = ?")) {
    const value = paramQueue.shift() as string;
    filtered = filtered.filter((row) => row.rule_id === value);
  }
  if (normalized.includes("source = ?")) {
    const value = paramQueue.shift() as string;
    filtered = filtered.filter((row) => row.source === value);
  }
  if (normalized.includes("last_seen >= ?")) {
    const value = paramQueue.shift() as string;
    filtered = filtered.filter((row) => row.last_seen >= value);
  }
  if (normalized.includes("first_seen <= ?")) {
    const value = paramQueue.shift() as string;
    filtered = filtered.filter((row) => row.first_seen <= value);
  }
  return filtered;
}

function sortAlertRows(rows: FakeAlertRow[], normalized: string): void {
  const ascending =
    normalized.includes("END ASC") ||
    normalized.includes("ORDER BY updated_at ASC") ||
    normalized.includes("ORDER BY last_seen ASC") ||
    normalized.includes("ORDER BY match_count ASC");
  const direction = ascending ? 1 : -1;
  const severityRank: Record<string, number> = { informational: 1, low: 2, medium: 3, high: 4, critical: 5 };

  rows.sort((left, right) => {
    let compared: number;
    if (normalized.includes("ORDER BY CASE severity")) {
      compared = (severityRank[left.severity] ?? 0) - (severityRank[right.severity] ?? 0);
    } else if (normalized.includes("ORDER BY match_count")) {
      compared = left.match_count - right.match_count;
    } else if (normalized.includes("ORDER BY updated_at")) {
      compared = left.updated_at.localeCompare(right.updated_at);
    } else {
      compared = left.last_seen.localeCompare(right.last_seen);
    }
    return compared * direction || left.id.localeCompare(right.id);
  });
}

function extractQuoted(source: string, prefix: string, suffix: string): string | undefined {
  const start = source.indexOf(prefix);
  if (start === -1) return undefined;
  const begin = start + prefix.length;
  const end = source.indexOf(suffix, begin);
  if (end === -1) return undefined;
  return source.slice(begin, end);
}

function projectAlert(row: FakeAlertRow): Record<string, unknown> {
  return {
    id: row.id,
    rule_id: row.rule_id,
    title: row.title,
    severity: row.severity,
    source: row.source,
    status: row.status,
    match_count: row.match_count,
    first_seen: row.first_seen,
    last_seen: row.last_seen,
    updated_at: row.updated_at
  };
}

function projectSourceHealth(row: FakeSourceHealthRow): Record<string, unknown> {
  return {
    source: row.source,
    tenant_id: row.tenant_id,
    last_event_at: row.last_event_at,
    last_event_count: row.last_event_count,
    total_events: row.total_events,
    total_batches: row.total_batches,
    total_errors: row.total_errors,
    last_error_at: row.last_error_at,
    last_error_message: row.last_error_message,
    updated_at: row.updated_at
  };
}

function projectAlertDetail(row: FakeAlertRow): Record<string, unknown> {
  return {
    ...projectAlert(row),
    acknowledged_at: row.acknowledged_at ?? null,
    acknowledged_by: row.acknowledged_by ?? null,
    resolved_at: row.resolved_at ?? null,
    resolved_by: row.resolved_by ?? null,
    assignee: row.assignee ?? null,
    event_json: row.event_json ?? "{}"
  };
}
