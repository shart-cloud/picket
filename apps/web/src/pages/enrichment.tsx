import { useMemo, useState } from "react";
import type { FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  addIoc,
  deleteIoc,
  importIocCsv,
  listEnrichmentFeeds,
  listIocs,
  type IndicatorType,
  type IocRecord
} from "../api";
import { EmptyState, ErrorState, LoadingState, StatCard } from "../ui";

const INDICATOR_TYPES: IndicatorType[] = ["ipv4", "ipv6", "domain", "url", "sha256"];

export function EnrichmentPage() {
  const queryClient = useQueryClient();
  const [typeFilter, setTypeFilter] = useState<IndicatorType | "">("");
  const [iocForm, setIocForm] = useState<IocRecord>({ indicator: "", indicator_type: "ipv4", feed_name: "", threat_type: "" });
  const [csvFeed, setCsvFeed] = useState("");
  const [csvThreatType, setCsvThreatType] = useState("");
  const [csv, setCsv] = useState("indicator,indicator_type,feed_name,threat_type\n203.0.113.10,ipv4,manual,scanner");

  const feeds = useQuery({ queryKey: ["enrichment", "feeds"], queryFn: listEnrichmentFeeds });
  const iocs = useQuery({ queryKey: ["enrichment", "iocs", typeFilter], queryFn: () => listIocs(typeFilter || undefined) });

  const invalidate = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["enrichment"] }),
      queryClient.invalidateQueries({ queryKey: ["dashboard", "overview"] })
    ]);
  };
  const add = useMutation({
    mutationFn: () => addIoc(cleanIoc(iocForm)),
    onSuccess: async () => {
      setIocForm({ indicator: "", indicator_type: "ipv4", feed_name: "", threat_type: "" });
      await invalidate();
    }
  });
  const importCsv = useMutation({
    mutationFn: () => importIocCsv({ csv, feed: csvFeed.trim() || undefined, threatType: csvThreatType.trim() || undefined }),
    onSuccess: invalidate
  });
  const remove = useMutation({
    mutationFn: ({ indicator_type, indicator }: IocRecord) => deleteIoc(indicator_type, indicator),
    onSuccess: invalidate
  });

  const rows = iocs.data ?? [];
  const feedRows = feeds.data ?? [];
  const byType = useMemo(
    () => INDICATOR_TYPES.map((type) => ({ type, count: rows.filter((ioc) => ioc.indicator_type === type).length })),
    [rows]
  );

  function submitIoc(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (iocForm.indicator.trim()) add.mutate();
  }

  function submitCsv(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (csv.trim()) importCsv.mutate();
  }

  if (feeds.isLoading || iocs.isLoading) return <LoadingState label="Loading enrichment" />;
  if (feeds.isError) return <ErrorState error={feeds.error} />;
  if (iocs.isError) return <ErrorState error={iocs.error} />;

  return (
    <section className="page-stack">
      <div className="metric-grid">
        <StatCard label="Feeds" value={feedRows.length} />
        <StatCard label="Indicators" value={rows.length} />
        <StatCard label="IP indicators" value={byType.filter((entry) => entry.type === "ipv4" || entry.type === "ipv6").reduce((sum, entry) => sum + entry.count, 0)} />
        <StatCard label="Hash indicators" value={byType.find((entry) => entry.type === "sha256")?.count ?? 0} />
      </div>

      <div className="panel-grid enrichment-grid">
        <article className="panel">
          <div className="panel-header">
            <h2>Feeds</h2>
            <span>{feedRows.length} configured</span>
          </div>
          {feedRows.length === 0 ? <EmptyState title="No feeds loaded" /> : null}
          <div className="list-stack">
            {feedRows.map((feed) => (
              <div className="row-card" key={feed.name}>
                <div>
                  <strong>{feed.name}</strong>
                  <small>{feed.type} · {formatTimestamp(feed.last_updated)}</small>
                </div>
                <span className="status-pill">{feed.indicator_count} IOCs</span>
              </div>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="panel-header">
            <h2>Add IOC</h2>
          </div>
          <form className="ioc-form" onSubmit={submitIoc}>
            <label>Indicator<input value={iocForm.indicator} onChange={(event) => setIocForm((current) => ({ ...current, indicator: event.target.value }))} placeholder="203.0.113.10" /></label>
            <label>Type<select value={iocForm.indicator_type} onChange={(event) => setIocForm((current) => ({ ...current, indicator_type: event.target.value as IndicatorType }))}>{INDICATOR_TYPES.map((type) => <option key={type} value={type}>{type}</option>)}</select></label>
            <label>Feed<input value={iocForm.feed_name ?? ""} onChange={(event) => setIocForm((current) => ({ ...current, feed_name: event.target.value }))} placeholder="manual" /></label>
            <label>Threat<input value={iocForm.threat_type ?? ""} onChange={(event) => setIocForm((current) => ({ ...current, threat_type: event.target.value }))} placeholder="scanner" /></label>
            <button className="button" disabled={add.isPending || iocForm.indicator.trim().length === 0} type="submit">{add.isPending ? "Adding" : "Add IOC"}</button>
          </form>
          {add.isError ? <ErrorState error={add.error} /> : null}
        </article>
      </div>

      <article className="panel">
        <div className="panel-header">
          <h2>CSV Import</h2>
          <span>indicator, indicator_type, feed_name, threat_type</span>
        </div>
        <form className="csv-import-form" onSubmit={submitCsv}>
          <div className="csv-import-fields">
            <label>Feed<input value={csvFeed} onChange={(event) => setCsvFeed(event.target.value)} placeholder="feed name" /></label>
            <label>Threat<input value={csvThreatType} onChange={(event) => setCsvThreatType(event.target.value)} placeholder="default threat type" /></label>
          </div>
          <textarea value={csv} onChange={(event) => setCsv(event.target.value)} spellCheck={false} />
          <button className="button" disabled={importCsv.isPending || csv.trim().length === 0} type="submit">{importCsv.isPending ? "Importing" : "Import CSV"}</button>
        </form>
        {importCsv.isError ? <ErrorState error={importCsv.error} /> : null}
      </article>

      <article className="panel">
        <div className="panel-header">
          <div>
            <h2>Indicators</h2>
            <span>{rows.length} shown</span>
          </div>
          <select className="standalone-select" value={typeFilter} onChange={(event) => setTypeFilter(event.target.value as IndicatorType | "")}>
            <option value="">All types</option>
            {INDICATOR_TYPES.map((type) => <option key={type} value={type}>{type}</option>)}
          </select>
        </div>
        {rows.length === 0 ? <div className="empty-table">No indicators match this filter.</div> : (
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Indicator</th><th>Type</th><th>Feed</th><th>Threat</th><th>Added</th><th /></tr></thead>
              <tbody>{rows.map((ioc) => (
                <tr key={`${ioc.indicator_type}:${ioc.indicator}`}>
                  <td><code>{ioc.indicator}</code></td>
                  <td>{ioc.indicator_type}</td>
                  <td>{ioc.feed_name ?? "-"}</td>
                  <td>{ioc.threat_type ?? "-"}</td>
                  <td>{formatTimestamp(ioc.added_at ?? null)}</td>
                  <td><button className="button secondary" disabled={remove.isPending} onClick={() => remove.mutate(ioc)} type="button">Delete</button></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
        {remove.isError ? <ErrorState error={remove.error} /> : null}
      </article>
    </section>
  );
}

function cleanIoc(input: IocRecord): IocRecord {
  return {
    indicator: input.indicator.trim(),
    indicator_type: input.indicator_type,
    ...(input.feed_name?.trim() ? { feed_name: input.feed_name.trim() } : {}),
    ...(input.threat_type?.trim() ? { threat_type: input.threat_type.trim() } : {})
  };
}

function formatTimestamp(value: string | null): string {
  if (!value) return "-";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}
