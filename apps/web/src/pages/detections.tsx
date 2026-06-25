import { useMemo, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { DetectionRuleRow } from "@picket/core/detection-rules";

import { listDetections, listScheduledDetections, setDetectionEnabled, type ScheduledDetectionView } from "../api";
import { EmptyState, ErrorState, LoadingState, StatCard } from "../ui";

interface DetectionFilters {
  enabled: "" | "enabled" | "disabled";
  severity: string;
  source: string;
  execution: string;
  tag: string;
}

export function DetectionsPage() {
  const queryClient = useQueryClient();
  const [filters, setFilters] = useState<DetectionFilters>({
    enabled: "",
    severity: "",
    source: "",
    execution: "",
    tag: ""
  });
  const detections = useQuery({ queryKey: ["detections"], queryFn: listDetections });
  const scheduled = useQuery({ queryKey: ["detections", "scheduled"], queryFn: listScheduledDetections });
  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => setDetectionEnabled(id, enabled),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["detections"] }),
        queryClient.invalidateQueries({ queryKey: ["detections", "scheduled"] }),
        queryClient.invalidateQueries({ queryKey: ["dashboard", "overview"] })
      ]);
    }
  });

  const rules = detections.data ?? [];
  const schedules = scheduled.data ?? [];
  const scheduleById = useMemo(() => new Map(schedules.map((entry) => [entry.id, entry])), [schedules]);
  const sources = useMemo(() => unique(rules.map((rule) => rule.source)), [rules]);
  const severities = useMemo(() => unique(rules.map((rule) => rule.severity)), [rules]);
  const executions = useMemo(() => unique(rules.map((rule) => rule.execution)), [rules]);
  const tags = useMemo(() => unique(rules.flatMap((rule) => rule.tags)), [rules]);
  const filtered = useMemo(
    () => rules.filter((rule) => matchesFilters(rule, filters)),
    [filters, rules]
  );

  if (detections.isLoading) return <LoadingState label="Loading detections" />;
  if (detections.isError) return <ErrorState error={detections.error} />;
  if (rules.length === 0) return <EmptyState title="No detection rules found" />;

  const enabledCount = rules.filter((rule) => rule.enabled).length;
  const sqlCount = rules.filter((rule) => rule.execution === "sql").length;
  const dueCount = schedules.filter((entry) => entry.due && entry.enabled).length;
  const errorCount = schedules.filter((entry) => entry.last_status === "error").length;

  return (
    <section className="page-stack">
      <div className="metric-grid">
        <StatCard label="Rules" value={rules.length} />
        <StatCard label="Enabled" value={`${enabledCount}/${rules.length}`} />
        <StatCard label="Scheduled" value={sqlCount} />
        <StatCard label="Run errors" value={errorCount} tone={errorCount > 0 ? "hot" : undefined} />
      </div>

      <article className="panel">
        <div className="panel-header">
          <div>
            <h2>Detection Rules</h2>
            <span>{filtered.length} shown · {dueCount} scheduled due</span>
          </div>
        </div>

        <div className="filter-grid detection-filter-grid">
          <label>Status<select value={filters.enabled} onChange={(event) => updateFilter(setFilters, "enabled", event.target.value as DetectionFilters["enabled"])}><option value="">All</option><option value="enabled">Enabled</option><option value="disabled">Disabled</option></select></label>
          <label>Severity<select value={filters.severity} onChange={(event) => updateFilter(setFilters, "severity", event.target.value)}><option value="">All</option>{severities.map((severity) => <option value={severity} key={severity}>{severity}</option>)}</select></label>
          <label>Source<select value={filters.source} onChange={(event) => updateFilter(setFilters, "source", event.target.value)}><option value="">All</option>{sources.map((source) => <option value={source} key={source}>{source}</option>)}</select></label>
          <label>Execution<select value={filters.execution} onChange={(event) => updateFilter(setFilters, "execution", event.target.value)}><option value="">All</option>{executions.map((execution) => <option value={execution} key={execution}>{execution}</option>)}</select></label>
          <label>Tag<select value={filters.tag} onChange={(event) => updateFilter(setFilters, "tag", event.target.value)}><option value="">All</option>{tags.map((tag) => <option value={tag} key={tag}>{tag}</option>)}</select></label>
          <button className="button secondary filter-clear" onClick={() => setFilters({ enabled: "", severity: "", source: "", execution: "", tag: "" })} type="button">Clear filters</button>
        </div>

        {scheduled.isError ? <div className="error-box">{scheduled.error.message}</div> : null}
        {toggle.isError ? <div className="error-box">{toggle.error.message}</div> : null}

        {filtered.length === 0 ? <div className="empty-table">No rules match these filters.</div> : (
          <div className="list-stack">
            {filtered.map((rule) => (
              <RuleCard
                key={rule.id}
                rule={rule}
                schedule={scheduleById.get(rule.id) ?? null}
                togglePending={toggle.isPending}
                onToggle={() => toggle.mutate({ id: rule.id, enabled: !rule.enabled })}
              />
            ))}
          </div>
        )}
      </article>
    </section>
  );
}

function RuleCard(props: {
  rule: DetectionRuleRow;
  schedule: ScheduledDetectionView | null;
  togglePending: boolean;
  onToggle: () => void;
}) {
  return (
    <div className="rule-card detection-rule-card">
      <div className="rule-card-main">
        <Link className="table-link" to="/detections/$ruleId" params={{ ruleId: props.rule.id }}>
          {props.rule.title}
        </Link>
        <small>{props.rule.source} · {props.rule.execution} · {props.rule.class_name ?? "unclassified"}</small>
        <div className="chip-row rule-meta-row">
          <span className={`severity ${props.rule.severity}`}>{props.rule.severity}</span>
          <span>{props.rule.enabled ? "Enabled" : "Disabled"}</span>
          <span>{props.rule.match_count} matches</span>
          <span>Last triggered {formatTimestamp(props.rule.last_triggered_at)}</span>
          {props.schedule ? <span className={`run-status ${runStatusClass(props.schedule)}`}>{runStatusLabel(props.schedule)}</span> : null}
        </div>
      </div>
      <button
        className={props.rule.enabled ? "button secondary" : "button"}
        disabled={props.togglePending}
        onClick={props.onToggle}
        type="button"
      >
        {props.rule.enabled ? "Disable" : "Enable"}
      </button>
    </div>
  );
}

function matchesFilters(rule: DetectionRuleRow, filters: DetectionFilters): boolean {
  if (filters.enabled === "enabled" && !rule.enabled) return false;
  if (filters.enabled === "disabled" && rule.enabled) return false;
  if (filters.severity && rule.severity !== filters.severity) return false;
  if (filters.source && rule.source !== filters.source) return false;
  if (filters.execution && rule.execution !== filters.execution) return false;
  if (filters.tag && !rule.tags.includes(filters.tag)) return false;
  return true;
}

function updateFilter<K extends keyof DetectionFilters>(
  setFilters: Dispatch<SetStateAction<DetectionFilters>>,
  key: K,
  value: DetectionFilters[K]
) {
  setFilters((current) => ({ ...current, [key]: value }));
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort((left, right) => left.localeCompare(right));
}

function runStatusClass(schedule: ScheduledDetectionView): string {
  if (schedule.last_status === "error") return "error";
  if (schedule.due && schedule.enabled) return "due";
  if (schedule.last_status === "ok") return "ok";
  return "idle";
}

function runStatusLabel(schedule: ScheduledDetectionView): string {
  if (schedule.last_status === "error") return "Run error";
  if (schedule.due && schedule.enabled) return "Due";
  if (schedule.last_status === "ok") return "Last run ok";
  if (schedule.last_status === "skipped") return "Skipped";
  return "No run yet";
}

function formatTimestamp(value: string | null): string {
  if (!value) return "never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
