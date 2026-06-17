import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { getDashboardOverview } from "../api";
import { EmptyState, ErrorState, LoadingState, StatCard } from "../ui";

export function DashboardPage() {
  const overview = useQuery({ queryKey: ["dashboard", "overview"], queryFn: getDashboardOverview });

  if (overview.isLoading) return <LoadingState label="Loading dashboard" />;
  if (overview.isError) return <ErrorState error={overview.error} />;
  if (!overview.data) return <EmptyState title="No dashboard data" />;

  const data = overview.data;

  return (
    <section className="page-stack">
      <div className="metric-grid">
        <StatCard label="Total alerts" value={data.alerts.total} tone="hot" />
        <StatCard label="Healthy sources" value={`${data.sources.healthy}/${data.sources.total}`} />
        <StatCard label="Detection engine" value={data.detection.status} />
        <StatCard label="Enabled rules" value={`${data.detection.rules.enabled}/${data.detection.rules.total}`} />
      </div>

      <div className="panel-grid">
        <article className="panel">
          <div className="panel-header">
            <h2>Sources</h2>
            <span>{data.sources.stale} stale</span>
          </div>
          <div className="list-stack">
            {data.sources.items.map((source) => (
              <div className="row-card" key={`${source.tenant_id}:${source.source}`}>
                <div>
                  <Link className="table-link" to="/sources/$sourceId" params={{ sourceId: source.source }} search={{ tenant: source.tenant_id }}>
                    {source.source}
                  </Link>
                  <small>{source.last_event_at ?? "No recent events"}</small>
                </div>
                <span className={`status ${source.health}`}>{source.health}</span>
              </div>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="panel-header">
            <h2>Alert Severity</h2>
          </div>
          <div className="bar-list">
            {data.alerts.by_severity.map((entry) => (
              <div className="bar-row" key={entry.key}>
                <span>{entry.key}</span>
                <meter value={entry.count} max={Math.max(1, data.alerts.total)} />
                <strong>{entry.count}</strong>
              </div>
            ))}
          </div>
        </article>
      </div>
    </section>
  );
}
