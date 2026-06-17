import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearch } from "@tanstack/react-router";

import {
  getSourceErrors,
  getSourceHistory,
  getSourceSample,
  getSourceSchema,
  getSourceStatus
} from "../api";
import { asQueryResult, formatQueryCell } from "../query-utils";
import { ErrorState, LoadingState, StatCard } from "../ui";

export function SourceDetailPage() {
  const { sourceId } = useParams({ from: "/sources/$sourceId" });
  const { tenant } = useSearch({ from: "/sources/$sourceId" });
  const status = useQuery({
    queryKey: ["sources", sourceId, tenant, "status"],
    queryFn: () => getSourceStatus(sourceId, tenant)
  });
  const schema = useQuery({
    queryKey: ["sources", sourceId, "schema"],
    queryFn: () => getSourceSchema(sourceId)
  });
  const sample = useQuery({
    queryKey: ["sources", sourceId, "sample"],
    queryFn: () => getSourceSample(sourceId),
    staleTime: 60_000
  });
  const history = useQuery({
    queryKey: ["sources", sourceId, tenant, "history"],
    queryFn: () => getSourceHistory(sourceId, tenant)
  });
  const errors = useQuery({
    queryKey: ["sources", sourceId, tenant, "errors"],
    queryFn: () => getSourceErrors(sourceId, tenant)
  });

  if (status.isLoading) return <LoadingState label="Loading source status" />;
  if (status.isError) return <ErrorState error={status.error} />;
  if (!status.data) return null;

  const source = status.data;
  return (
    <section className="page-stack">
      <Link className="back-link" to="/sources">Back to sources</Link>

      <article className="panel source-detail-hero">
        <div>
          <p className="eyebrow">Log source</p>
          <h2>{source.source}</h2>
          <span>{source.tenant_id}</span>
        </div>
        <span className={`status source-health-badge ${source.health}`}>{source.health}</span>
      </article>

      <div className="metric-grid">
        <StatCard label="Total events" value={source.total_events.toLocaleString()} />
        <StatCard label="Batches" value={source.total_batches.toLocaleString()} />
        <StatCard label="Errors" value={source.total_errors.toLocaleString()} tone={source.total_errors > 0 ? "hot" : undefined} />
        <StatCard label="Last batch size" value={source.last_event_count.toLocaleString()} />
      </div>

      <div className="panel-grid source-overview-grid">
        <article className="panel">
          <div className="panel-header"><h2>Current Status</h2><span>Updated {formatTimestamp(source.updated_at)}</span></div>
          <dl className="source-detail-list">
            <dt>Last event</dt><dd>{formatTimestamp(source.last_event_at)}</dd>
            <dt>Last error</dt><dd>{formatTimestamp(source.last_error_at)}</dd>
            <dt>Error message</dt><dd>{source.last_error_message ?? "No recorded errors"}</dd>
          </dl>
        </article>
        <HistoryPanel loading={history.isLoading} error={history.error} rows={history.data ?? []} />
      </div>

      <SamplePanel loading={sample.isLoading} error={sample.error} result={asQueryResult(sample.data?.result)} />

      <div className="panel-grid source-overview-grid">
        <SchemaPanel loading={schema.isLoading} error={schema.error} schema={schema.data} />
        <ErrorsPanel loading={errors.isLoading} error={errors.error} rows={errors.data ?? []} />
      </div>
    </section>
  );
}

function SamplePanel(props: { loading: boolean; error: unknown; result: ReturnType<typeof asQueryResult> }) {
  return (
    <article className="panel">
      <div className="panel-header"><h2>Sample Events</h2><span>10 most recent</span></div>
      {props.loading ? <LoadingState label="Loading sample events" /> : null}
      {props.error ? <ErrorState error={props.error} /> : null}
      {!props.loading && !props.error && (!props.result || props.result.rows.length === 0) ? <div className="empty-table">No sample events returned.</div> : null}
      {props.result && props.result.rows.length > 0 ? (
        <div className="table-scroll">
          <table className="data-table source-sample-table">
            <thead><tr><th>Time</th><th>Activity</th><th>Status</th><th>Actor</th><th>Source IP</th><th>Event</th></tr></thead>
            <tbody>{props.result.rows.map((row, index) => (
              <tr key={index}>
                <td>{formatTimestamp(asString(row.time))}</td>
                <td>{cell(row.activity_name)}</td>
                <td>{cell(row.status)}</td>
                <td>{cell(row.actor_user_email ?? row.actor_user_name ?? row.actor_user_uid)}</td>
                <td>{cell(row.src_endpoint_ip)}</td>
                <td><details className="event-details"><summary>View JSON</summary><pre>{JSON.stringify(row, null, 2)}</pre></details></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      ) : null}
    </article>
  );
}

function SchemaPanel(props: { loading: boolean; error: unknown; schema: Awaited<ReturnType<typeof getSourceSchema>> | undefined }) {
  const groups = useMemo(() => {
    const grouped = new Map<string, Array<{ name: string; type: string; group: string }>>();
    for (const field of props.schema?.fields ?? []) {
      const fields = grouped.get(field.group) ?? [];
      grouped.set(field.group, [...fields, field]);
    }
    return [...grouped.entries()];
  }, [props.schema]);

  return (
    <article className="panel">
      <div className="panel-header"><h2>OCSF Schema</h2><span>{props.schema?.field_count ?? 0} fields</span></div>
      {props.loading ? <LoadingState label="Loading schema" /> : null}
      {props.error ? <ErrorState error={props.error} /> : null}
      <div className="schema-groups">{groups.map(([group, fields]) => (
        <details key={group} open={group === "base"}>
          <summary>{group} <span>{fields.length}</span></summary>
          <div className="schema-fields">{fields.map((field) => <div key={field.name}><code>{field.name}</code><span>{field.type}</span></div>)}</div>
        </details>
      ))}</div>
    </article>
  );
}

function HistoryPanel(props: { loading: boolean; error: unknown; rows: Awaited<ReturnType<typeof getSourceHistory>> }) {
  return (
    <article className="panel">
      <div className="panel-header"><h2>Ingestion History</h2><span>{props.rows.length} entries</span></div>
      {props.loading ? <LoadingState label="Loading ingestion history" /> : null}
      {props.error ? <ErrorState error={props.error} /> : null}
      {!props.loading && !props.error && props.rows.length === 0 ? <div className="empty-table">No history recorded since migration 0008.</div> : null}
      <div className="source-timeline">{props.rows.map((row) => (
        <div className={`source-timeline-entry ${row.kind}`} key={row.id}>
          <span className="timeline-marker" />
          <div><strong>{row.kind === "batch" ? `${row.event_count} events ingested` : "Ingestion error"}</strong><small>{formatTimestamp(row.recorded_at)}</small>{row.error_message ? <p>{row.error_message}</p> : null}</div>
        </div>
      ))}</div>
    </article>
  );
}

function ErrorsPanel(props: { loading: boolean; error: unknown; rows: Awaited<ReturnType<typeof getSourceErrors>> }) {
  return (
    <article className="panel">
      <div className="panel-header"><h2>Recent Errors</h2><span>{props.rows.length} shown</span></div>
      {props.loading ? <LoadingState label="Loading recent errors" /> : null}
      {props.error ? <ErrorState error={props.error} /> : null}
      {!props.loading && !props.error && props.rows.length === 0 ? <div className="empty-table">No recent ingestion errors.</div> : null}
      <div className="list-stack">{props.rows.map((row) => <div className="source-error-card" key={row.id}><strong>{row.error_message ?? "Unknown error"}</strong><small>{formatTimestamp(row.recorded_at)}</small></div>)}</div>
    </article>
  );
}

function cell(value: unknown) {
  const formatted = formatQueryCell(value);
  return value === null || value === undefined || formatted === "" ? <span className="null-cell">-</span> : formatted;
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function formatTimestamp(value: string | null): string {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
