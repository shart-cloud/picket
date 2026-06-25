import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { getDashboardOverview, listAlerts } from "../api";
import { EmptyState, ErrorState, LoadingState, StatCard } from "../ui";

export function DashboardPage() {
  const overview = useQuery({
    queryKey: ["dashboard", "overview"],
    queryFn: getDashboardOverview,
    refetchInterval: 60_000
  });
  const recentAlerts = useQuery({
    queryKey: ["alerts", "recent-dashboard"],
    queryFn: () => listAlerts({ limit: 10, sort: "last_seen", direction: "desc" }),
    refetchInterval: 60_000
  });

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
                <a className="table-link" href={`/alerts?severity=${encodeURIComponent(entry.key)}`}>{entry.key}</a>
                <meter value={entry.count} max={Math.max(1, data.alerts.total)} />
                <strong>{entry.count}</strong>
              </div>
            ))}
          </div>
        </article>
      </div>

      <article className="panel">
        <div className="panel-header">
          <div>
            <h2>Recent Alerts</h2>
            <span>Auto-refreshes every minute</span>
          </div>
          <Link className="table-link" to="/alerts">View queue</Link>
        </div>
        {recentAlerts.isLoading ? <LoadingState label="Loading recent alerts" /> : null}
        {recentAlerts.isError ? <ErrorState error={recentAlerts.error} /> : null}
        {!recentAlerts.isLoading && !recentAlerts.isError && (recentAlerts.data?.alerts.length ?? 0) === 0 ? (
          <div className="empty-table">No alerts have been recorded yet.</div>
        ) : null}
        <div className="list-stack">
          {recentAlerts.data?.alerts.map((alert) => (
            <div className="row-card recent-alert-row" key={alert.id}>
              <div>
                <Link className="table-link" to="/alerts/$alertId" params={{ alertId: alert.id }}>
                  {alert.title}
                </Link>
                <small>{alert.rule_id} · {alert.source} · {formatTimestamp(alert.last_seen)}</small>
              </div>
              <div className="chip-row">
                <span className={`severity ${alert.severity}`}>{alert.severity}</span>
                <span className="status-pill">{alert.status}</span>
              </div>
            </div>
          ))}
        </div>
      </article>
    </section>
  );
}

function formatTimestamp(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}
