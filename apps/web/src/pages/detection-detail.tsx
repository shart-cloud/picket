import { useMemo } from "react";
import { Link, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { AlertRow } from "@picket/core/alerts";

import {
  getDetection,
  listAlerts,
  listScheduledDetections,
  setDetectionEnabled,
  type ScheduledDetectionView
} from "../api";
import { EmptyState, ErrorState, LoadingState, StatCard } from "../ui";

export function DetectionDetailPage() {
  const { ruleId } = useParams({ from: "/detections/$ruleId" });
  const queryClient = useQueryClient();
  const rule = useQuery({ queryKey: ["detections", ruleId], queryFn: () => getDetection(ruleId) });
  const scheduled = useQuery({
    queryKey: ["detections", "scheduled"],
    queryFn: listScheduledDetections
  });
  const recentMatches = useQuery({
    queryKey: ["alerts", { ruleId, limit: 10, sort: "last_seen", direction: "desc" }],
    queryFn: () => listAlerts({ ruleId, limit: 10, sort: "last_seen", direction: "desc" })
  });
  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => setDetectionEnabled(id, enabled),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["detections"] }),
        queryClient.invalidateQueries({ queryKey: ["detections", ruleId] }),
        queryClient.invalidateQueries({ queryKey: ["detections", "scheduled"] }),
        queryClient.invalidateQueries({ queryKey: ["dashboard", "overview"] })
      ]);
    }
  });

  const schedule = useMemo(
    () => scheduled.data?.find((entry) => entry.id === ruleId) ?? null,
    [ruleId, scheduled.data]
  );

  if (rule.isLoading) return <LoadingState label="Loading detection" />;
  if (rule.isError) return <ErrorState error={rule.error} />;
  if (!rule.data) return <EmptyState title="Detection rule not found" />;

  const definition = describeDefinition(rule.data.definition);

  return (
    <section className="page-stack">
      <Link className="back-link" to="/detections">Back to detections</Link>

      <article className="panel detection-hero">
        <div>
          <p className="eyebrow">{rule.data.id}</p>
          <h2>{rule.data.title}</h2>
          {rule.data.description ? <p>{rule.data.description}</p> : null}
          <div className="chip-row">
            <span className={`severity ${rule.data.severity}`}>{rule.data.severity}</span>
            <span>{rule.data.source}</span>
            <span>{rule.data.execution}</span>
            <span>{rule.data.enabled ? "Enabled" : "Disabled"}</span>
          </div>
        </div>
        <button
          className={rule.data.enabled ? "button secondary" : "button"}
          disabled={toggle.isPending}
          onClick={() => toggle.mutate({ id: rule.data.id, enabled: !rule.data.enabled })}
          type="button"
        >
          {rule.data.enabled ? "Disable rule" : "Enable rule"}
        </button>
      </article>

      {toggle.isError ? <ErrorState error={toggle.error} /> : null}

      <div className="metric-grid">
        <StatCard label="Matches" value={rule.data.match_count.toLocaleString()} tone={rule.data.match_count > 0 ? "hot" : undefined} />
        <StatCard label="Last triggered" value={formatTimestamp(rule.data.last_triggered_at)} />
        <StatCard label="Class" value={rule.data.class_name ?? "-"} />
        <StatCard label="Updated" value={formatTimestamp(rule.data.updated_at)} />
      </div>

      <div className="panel-grid detail-grid">
        <RuleDefinitionPanel summary={definition} tags={rule.data.tags} />
        <SchedulePanel loading={scheduled.isLoading} error={scheduled.error} schedule={schedule} execution={rule.data.execution} />
      </div>

      <RecentMatchesPanel loading={recentMatches.isLoading} error={recentMatches.error} rows={recentMatches.data?.alerts ?? []} />
    </section>
  );
}

function RuleDefinitionPanel(props: { summary: DefinitionSummary; tags: string[] }) {
  return (
    <article className="panel">
      <div className="panel-header">
        <h2>Rule Definition</h2>
        <span>{props.summary.kind}</span>
      </div>
      {props.tags.length > 0 ? (
        <div className="chip-row detection-tags">
          {props.tags.map((tag) => <span key={tag}>{tag}</span>)}
        </div>
      ) : null}
      {props.summary.sql ? (
        <div className="definition-block">
          <h3>SQL</h3>
          <pre>{props.summary.sql.query}</pre>
          <dl className="source-detail-list">
            <dt>Interval</dt><dd>{props.summary.sql.interval ?? "-"}</dd>
            <dt>Threshold</dt><dd>{props.summary.sql.threshold ?? "-"}</dd>
            <dt>Count field</dt><dd>{props.summary.sql.countField ?? "-"}</dd>
            <dt>Group by</dt><dd>{props.summary.sql.groupBy ?? "-"}</dd>
          </dl>
        </div>
      ) : (
        <pre>{props.summary.raw}</pre>
      )}
    </article>
  );
}

function SchedulePanel(props: {
  loading: boolean;
  error: unknown;
  schedule: ScheduledDetectionView | null;
  execution: string;
}) {
  return (
    <article className="panel">
      <div className="panel-header">
        <h2>Run Health</h2>
        <span>{props.execution === "sql" ? "Scheduled SQL" : "Realtime"}</span>
      </div>
      {props.execution !== "sql" ? <div className="empty-table">Realtime rules update match counters when events trigger them.</div> : null}
      {props.execution === "sql" && props.loading ? <LoadingState label="Loading run health" /> : null}
      {props.execution === "sql" && props.error ? <ErrorState error={props.error} /> : null}
      {props.execution === "sql" && !props.loading && !props.error && !props.schedule ? <div className="empty-table">No run state recorded yet.</div> : null}
      {props.schedule ? (
        <dl className="source-detail-list">
          <dt>Interval</dt><dd>{props.schedule.interval ?? "-"}</dd>
          <dt>Due</dt><dd>{props.schedule.due ? "Yes" : "No"}</dd>
          <dt>Last run</dt><dd>{formatTimestamp(props.schedule.last_run_at)}</dd>
          <dt>Status</dt><dd>{props.schedule.last_status ?? "-"}</dd>
          <dt>Rows</dt><dd>{props.schedule.last_row_count ?? "-"}</dd>
          <dt>Alerts</dt><dd>{props.schedule.last_alert_count ?? "-"}</dd>
          <dt>Last error</dt><dd>{props.schedule.last_error ?? "-"}</dd>
        </dl>
      ) : null}
    </article>
  );
}

function RecentMatchesPanel(props: { loading: boolean; error: unknown; rows: AlertRow[] }) {
  return (
    <article className="panel">
      <div className="panel-header">
        <h2>Recent Matches</h2>
        <span>{props.rows.length} shown</span>
      </div>
      {props.loading ? <LoadingState label="Loading recent matches" /> : null}
      {props.error ? <ErrorState error={props.error} /> : null}
      {!props.loading && !props.error && props.rows.length === 0 ? <div className="empty-table">No alerts have matched this rule yet.</div> : null}
      {props.rows.length > 0 ? (
        <div className="table-scroll">
          <table className="data-table">
            <thead><tr><th>Severity</th><th>Status</th><th>Alert</th><th>Matches</th><th>Last seen</th></tr></thead>
            <tbody>{props.rows.map((alert) => (
              <tr key={alert.id}>
                <td><span className={`severity ${alert.severity}`}>{alert.severity}</span></td>
                <td><span className="status-pill">{alert.status}</span></td>
                <td><Link className="table-link" to="/alerts/$alertId" params={{ alertId: alert.id }}>{alert.title}</Link></td>
                <td>{alert.match_count}</td>
                <td>{formatTimestamp(alert.last_seen)}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      ) : null}
    </article>
  );
}

interface DefinitionSummary {
  kind: string;
  raw: string;
  sql: {
    query: string;
    interval: string | null;
    threshold: string | null;
    countField: string | null;
    groupBy: string | null;
  } | null;
}

function describeDefinition(value: unknown): DefinitionSummary {
  const record = asRecord(value);
  const sqlRecord = asRecord(record?.sql);
  const query = typeof sqlRecord?.query === "string" ? sqlRecord.query : null;
  if (sqlRecord && query) {
    return {
      kind: "SQL",
      raw: formatJson(value),
      sql: {
        query,
        interval: stringValue(sqlRecord.interval),
        threshold: numberValue(sqlRecord.threshold),
        countField: stringValue(sqlRecord.count_field),
        groupBy: Array.isArray(sqlRecord.group_by)
          ? sqlRecord.group_by.filter((entry): entry is string => typeof entry === "string").join(", ")
          : stringValue(sqlRecord.group_by)
      }
    };
  }

  return {
    kind: typeof record?.execution === "string" ? record.execution.toUpperCase() : "Rule",
    raw: formatJson(value),
    sql: null
  };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function numberValue(value: unknown): string | null {
  return typeof value === "number" ? String(value) : stringValue(value);
}

function formatJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function formatTimestamp(value: string | null): string {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
