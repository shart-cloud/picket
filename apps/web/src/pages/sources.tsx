import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { listSources } from "../api";
import { EmptyState, ErrorState, LoadingState } from "../ui";

export function SourcesPage() {
  const sources = useQuery({ queryKey: ["sources"], queryFn: listSources });

  if (sources.isLoading) return <LoadingState label="Loading sources" />;
  if (sources.isError) return <ErrorState error={sources.error} />;
  if (!sources.data || sources.data.length === 0) return <EmptyState title="No sources have reported yet" />;

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Sources</h2>
        <span>{sources.data.length} reporting</span>
      </div>
      <div className="source-grid">
        {sources.data.map((source) => (
          <article className="source-card" key={`${source.tenant_id}:${source.source}`}>
            <Link className="table-link" to="/sources/$sourceId" params={{ sourceId: source.source }} search={{ tenant: source.tenant_id }}>
              {source.source}
            </Link>
            <dl>
              <dt>Tenant</dt><dd>{source.tenant_id}</dd>
              <dt>Events</dt><dd>{source.total_events}</dd>
              <dt>Batches</dt><dd>{source.total_batches}</dd>
              <dt>Errors</dt><dd>{source.total_errors}</dd>
              <dt>Last event</dt><dd>{source.last_event_at ?? "-"}</dd>
            </dl>
          </article>
        ))}
      </div>
    </section>
  );
}
