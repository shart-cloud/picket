import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { createColumnHelper, flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import type { AlertRow, AlertSeverity, AlertStatus } from "@picket/core/alerts";

import { bulkUpdateAlertStatus, listAlerts, type ListAlertsOptions } from "../api";
import { SessionRequiredNotice, useSession } from "../session";
import { ErrorState, LoadingState } from "../ui";

const PAGE_SIZE = 25;
const columnHelper = createColumnHelper<AlertRow>();
type SortField = NonNullable<ListAlertsOptions["sort"]>;

interface AlertFilters {
  status: AlertStatus | "";
  severity: AlertSeverity | "";
  ruleId: string;
  source: string;
  startTime: string;
  endTime: string;
  sort: SortField;
  direction: "asc" | "desc";
  page: number;
}

export function AlertsPage() {
  const queryClient = useQueryClient();
  const session = useSession();
  const canMutate = Boolean(session.data?.user);
  const [filters, setFilters] = useState<AlertFilters>(readUrlFilters);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());

  const options: ListAlertsOptions = {
    status: filters.status || undefined,
    severity: filters.severity || undefined,
    ruleId: filters.ruleId.trim() || undefined,
    source: filters.source.trim() || undefined,
    startTime: toIso(filters.startTime),
    endTime: toIso(filters.endTime),
    sort: filters.sort,
    direction: filters.direction,
    limit: PAGE_SIZE,
    offset: filters.page * PAGE_SIZE
  };
  const alerts = useQuery({ queryKey: ["alerts", options], queryFn: () => listAlerts(options) });
  const rows = alerts.data?.alerts ?? [];

  useEffect(() => {
    const params = new URLSearchParams();
    if (filters.status) params.set("status", filters.status);
    if (filters.severity) params.set("severity", filters.severity);
    if (filters.ruleId) params.set("rule", filters.ruleId);
    if (filters.source) params.set("source", filters.source);
    if (filters.startTime) params.set("from", filters.startTime);
    if (filters.endTime) params.set("to", filters.endTime);
    params.set("sort", filters.sort);
    params.set("direction", filters.direction);
    if (filters.page > 0) params.set("page", String(filters.page + 1));
    const query = params.toString();
    window.history.replaceState(null, "", `${window.location.pathname}${query ? `?${query}` : ""}`);
  }, [filters]);

  useEffect(() => setSelected(new Set()), [
    filters.status,
    filters.severity,
    filters.ruleId,
    filters.source,
    filters.startTime,
    filters.endTime,
    filters.sort,
    filters.direction,
    filters.page
  ]);

  const bulkMutation = useMutation({
    mutationFn: (status: "acknowledged" | "resolved") => bulkUpdateAlertStatus([...selected], status),
    onSuccess: async () => {
      setSelected(new Set());
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["alerts"] }),
        queryClient.invalidateQueries({ queryKey: ["dashboard", "overview"] })
      ]);
    }
  });

  function updateFilter<K extends keyof AlertFilters>(key: K, value: AlertFilters[K]) {
    setFilters((current) => ({ ...current, [key]: value, page: key === "page" ? Number(value) : 0 }));
  }

  function toggleSort(field: SortField) {
    setFilters((current) => ({
      ...current,
      sort: field,
      direction: current.sort === field && current.direction === "desc" ? "asc" : "desc",
      page: 0
    }));
  }

  function toggleSelected(id: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function togglePage() {
    const allSelected = rows.length > 0 && rows.every((row) => selected.has(row.id));
    setSelected(allSelected ? new Set() : new Set(rows.map((row) => row.id)));
  }

  const columns = useMemo(
    () => [
      columnHelper.display({
        id: "select",
        header: () => (
          <input
            aria-label="Select page"
            checked={rows.length > 0 && rows.every((row) => selected.has(row.id))}
            onChange={togglePage}
            type="checkbox"
          />
        ),
        cell: (info) => (
          <input
            aria-label={`Select ${info.row.original.title}`}
            checked={selected.has(info.row.original.id)}
            onChange={() => toggleSelected(info.row.original.id)}
            type="checkbox"
          />
        )
      }),
      columnHelper.accessor("severity", {
        header: () => <SortButton active={filters.sort === "severity"} direction={filters.direction} label="Severity" onClick={() => toggleSort("severity")} />,
        cell: (info) => <span className={`severity ${info.getValue()}`}>{info.getValue()}</span>
      }),
      columnHelper.accessor("status", { header: "Status", cell: (info) => <span className="status-pill">{info.getValue()}</span> }),
      columnHelper.accessor("title", {
        header: "Title",
        cell: (info) => (
          <Link className="table-link" to="/alerts/$alertId" params={{ alertId: info.row.original.id }}>
            {info.getValue()}
          </Link>
        )
      }),
      columnHelper.accessor("source", { header: "Source" }),
      columnHelper.accessor("match_count", {
        header: () => <SortButton active={filters.sort === "match_count"} direction={filters.direction} label="Matches" onClick={() => toggleSort("match_count")} />
      }),
      columnHelper.accessor("last_seen", {
        header: () => <SortButton active={filters.sort === "last_seen"} direction={filters.direction} label="Last match" onClick={() => toggleSort("last_seen")} />,
        cell: (info) => formatTimestamp(info.getValue())
      })
    ],
    [filters.direction, filters.sort, rows, selected]
  );
  const table = useReactTable({ data: rows, columns, getCoreRowModel: getCoreRowModel() });

  if (alerts.isLoading) return <LoadingState label="Loading alerts" />;
  if (alerts.isError) return <ErrorState error={alerts.error} />;

  const total = alerts.data?.total ?? 0;
  const first = total === 0 ? 0 : filters.page * PAGE_SIZE + 1;
  const last = Math.min(total, filters.page * PAGE_SIZE + rows.length);

  return (
    <section className="page-stack">
      <SessionRequiredNotice />
      <article className="panel">
        <div className="panel-header">
          <div>
            <h2>Alert Queue</h2>
            <span>{total === 0 ? "No matches" : `${first}-${last} of ${total}`}</span>
          </div>
          <div className="button-row">
            <button className="button secondary" disabled={!canMutate || selected.size === 0 || bulkMutation.isPending} onClick={() => bulkMutation.mutate("acknowledged")} type="button">
              Acknowledge selected
            </button>
            <button className="button secondary" disabled={!canMutate || selected.size === 0 || bulkMutation.isPending} onClick={() => bulkMutation.mutate("resolved")} type="button">
              Resolve selected
            </button>
          </div>
        </div>

        <div className="filter-grid">
          <label>Status<select value={filters.status} onChange={(event) => updateFilter("status", event.target.value as AlertFilters["status"])}><option value="">All</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="resolved">Resolved</option></select></label>
          <label>Severity<select value={filters.severity} onChange={(event) => updateFilter("severity", event.target.value as AlertFilters["severity"])}><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="informational">Informational</option></select></label>
          <label>Source<input value={filters.source} onChange={(event) => updateFilter("source", event.target.value)} placeholder="aws_cloudtrail" /></label>
          <label>Rule<input value={filters.ruleId} onChange={(event) => updateFilter("ruleId", event.target.value)} placeholder="rule id" /></label>
          <label>From<input type="datetime-local" value={filters.startTime} onChange={(event) => updateFilter("startTime", event.target.value)} /></label>
          <label>To<input type="datetime-local" value={filters.endTime} onChange={(event) => updateFilter("endTime", event.target.value)} /></label>
          <button className="button secondary filter-clear" onClick={() => setFilters(defaultFilters())} type="button">Clear filters</button>
        </div>

        {bulkMutation.isError ? <div className="error-box">{bulkMutation.error.message}</div> : null}
        {rows.length === 0 ? <div className="empty-table">No alerts match these filters.</div> : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>{table.getHeaderGroups().map((group) => <tr key={group.id}>{group.headers.map((header) => <th key={header.id}>{flexRender(header.column.columnDef.header, header.getContext())}</th>)}</tr>)}</thead>
              <tbody>{table.getRowModel().rows.map((row) => <tr key={row.id}>{row.getVisibleCells().map((cell) => <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>)}</tr>)}</tbody>
            </table>
          </div>
        )}

        <div className="pagination-row">
          <button className="button secondary" disabled={filters.page === 0} onClick={() => updateFilter("page", filters.page - 1)} type="button">Previous</button>
          <span>Page {filters.page + 1}</span>
          <button className="button secondary" disabled={last >= total} onClick={() => updateFilter("page", filters.page + 1)} type="button">Next</button>
        </div>
      </article>
    </section>
  );
}

function SortButton(props: { active: boolean; direction: "asc" | "desc"; label: string; onClick: () => void }) {
  return <button className="sort-button" onClick={props.onClick} type="button">{props.label}{props.active ? (props.direction === "asc" ? " ↑" : " ↓") : ""}</button>;
}

function defaultFilters(): AlertFilters {
  return { status: "", severity: "", ruleId: "", source: "", startTime: "", endTime: "", sort: "last_seen", direction: "desc", page: 0 };
}

function readUrlFilters(): AlertFilters {
  const defaults = defaultFilters();
  const params = new URLSearchParams(window.location.search);
  const status = params.get("status");
  const severity = params.get("severity");
  const sort = params.get("sort");
  const direction = params.get("direction");
  const page = Number(params.get("page") ?? "1");
  return {
    ...defaults,
    status: status === "open" || status === "acknowledged" || status === "resolved" ? status : "",
    severity: severity === "critical" || severity === "high" || severity === "medium" || severity === "low" || severity === "informational" ? severity : "",
    ruleId: params.get("rule") ?? "",
    source: params.get("source") ?? "",
    startTime: params.get("from") ?? "",
    endTime: params.get("to") ?? "",
    sort: sort === "severity" || sort === "match_count" || sort === "last_seen" ? sort : defaults.sort,
    direction: direction === "asc" ? "asc" : "desc",
    page: Number.isInteger(page) && page > 0 ? page - 1 : 0
  };
}

function toIso(value: string): string | undefined {
  if (!value) return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

function formatTimestamp(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}
