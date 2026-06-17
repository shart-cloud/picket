import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { AlertStatus } from "@picket/core/alerts";

import { addAlertNote, assignAlert, getAlert, updateAlertStatus } from "../api";
import { parseAlertEvent, summarizeAlertEvent } from "../alert-utils";
import { useSession, SessionRequiredNotice } from "../session";
import { EmptyState, ErrorState, LoadingState } from "../ui";

const STATUS_TRANSITIONS: readonly AlertStatus[] = ["open", "acknowledged", "resolved"];

export function AlertDetailPage() {
  const { alertId } = useParams({ from: "/alerts/$alertId" });
  const queryClient = useQueryClient();
  const session = useSession();
  const canMutate = Boolean(session.data?.user);
  const [assignee, setAssignee] = useState("");
  const [note, setNote] = useState("");

  const detail = useQuery({ queryKey: ["alerts", alertId], queryFn: () => getAlert(alertId) });

  const invalidateAlertState = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["alerts"] }),
      queryClient.invalidateQueries({ queryKey: ["dashboard", "overview"] })
    ]);
  };

  const statusMutation = useMutation({
    mutationFn: (status: AlertStatus) => updateAlertStatus(alertId, status),
    onSuccess: invalidateAlertState
  });
  const assignMutation = useMutation({
    mutationFn: (nextAssignee: string | null) => assignAlert(alertId, nextAssignee),
    onSuccess: invalidateAlertState
  });
  const noteMutation = useMutation({
    mutationFn: (body: string) => addAlertNote(alertId, body),
    onSuccess: async () => {
      setNote("");
      await invalidateAlertState();
    }
  });

  function onAssign(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = assignee.trim();
    assignMutation.mutate(trimmed.length > 0 ? trimmed : null);
  }

  function onAddNote(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = note.trim();
    if (trimmed.length > 0) noteMutation.mutate(trimmed);
  }

  if (detail.isLoading) return <LoadingState label="Loading alert" />;
  if (detail.isError) return <ErrorState error={detail.error} />;
  if (!detail.data) return <EmptyState title="Alert not found" />;

  const { alert, timeline, notes } = detail.data;
  const event = parseAlertEvent(alert.event_json);
  const summary = event ? summarizeAlertEvent(event) : null;
  const rawEvent = formatJson(alert.event_json);
  const busy = statusMutation.isPending || assignMutation.isPending || noteMutation.isPending;

  return (
    <section className="page-stack">
      <Link className="back-link" to="/alerts">Back to alerts</Link>
      <SessionRequiredNotice />

      <article className="panel alert-hero">
        <div>
          <p className="eyebrow">{alert.rule_id}</p>
          <h2>{alert.title}</h2>
          <div className="chip-row">
            <span className={`severity ${alert.severity}`}>{alert.severity}</span>
            <span className="status-pill">{alert.status}</span>
            <span>{alert.source}</span>
            <span>{alert.match_count} matches</span>
          </div>
        </div>
        <div className="detail-meta">
          <span>First seen: {alert.first_seen}</span>
          <span>Last seen: {alert.last_seen}</span>
          <span>Assignee: {alert.assignee ?? "Unassigned"}</span>
        </div>
      </article>

      {summary ? (
        <article className="panel">
          <div className="panel-header">
            <h2>Event Context</h2>
            <span>{event?.class_name}</span>
          </div>
          <div className="event-summary-grid">
            <SummaryField label="Activity" value={summary.activity} />
            <SummaryField label="Outcome" value={summary.outcome} />
            <SummaryField label="User" value={summary.user} />
            <SummaryField label="Source IP" value={summary.sourceIp} />
            <SummaryField label="Destination" value={summary.destination} />
            <SummaryField label="Operation" value={summary.operation} />
            <SummaryField label="Cloud" value={summary.cloud} />
          </div>
          {summary.threat ? (
            <div className="threat-match-card">
              <strong>Threat intelligence match</strong>
              <span>{summary.threat.indicator} ({summary.threat.type})</span>
              <span>Matched field: {summary.threat.field}</span>
              {summary.threat.feed ? <span>Feed: {summary.threat.feed}</span> : null}
              {summary.threat.threatType ? <span>Threat type: {summary.threat.threatType}</span> : null}
            </div>
          ) : null}
        </article>
      ) : null}

      <div className="panel-grid detail-grid">
        <article className="panel">
          <div className="panel-header">
            <h2>Actions</h2>
          </div>
          <div className="action-stack">
            <div className="button-row">
              {STATUS_TRANSITIONS.map((status) => (
                <button
                  className={alert.status === status ? "button secondary" : "button"}
                  disabled={!canMutate || busy || alert.status === status}
                  key={status}
                  onClick={() => statusMutation.mutate(status)}
                  type="button"
                >
                  Mark {status}
                </button>
              ))}
            </div>
            <form className="inline-form" onSubmit={onAssign}>
              <input
                disabled={!canMutate || busy}
                onChange={(event) => setAssignee(event.target.value)}
                placeholder={alert.assignee ?? "Assignee email"}
                value={assignee}
              />
              <button className="button" disabled={!canMutate || busy} type="submit">Assign</button>
            </form>
            {statusMutation.isError || assignMutation.isError ? (
              <div className="error-box">{(statusMutation.error ?? assignMutation.error)?.message}</div>
            ) : null}
          </div>
        </article>

        <article className="panel">
          <div className="panel-header">
            <h2>Notes</h2>
            <span>{notes.length}</span>
          </div>
          <form className="note-form" onSubmit={onAddNote}>
            <textarea
              disabled={!canMutate || busy}
              onChange={(event) => setNote(event.target.value)}
              placeholder="Add analyst note"
              value={note}
            />
            <button className="button" disabled={!canMutate || busy || note.trim().length === 0} type="submit">Add note</button>
          </form>
          {noteMutation.isError ? <div className="error-box">{noteMutation.error.message}</div> : null}
          <div className="list-stack">
            {notes.map((entry) => (
              <div className="timeline-entry" key={entry.id}>
                <strong>{entry.author ?? "unknown"}</strong>
                <p>{entry.body}</p>
                <small>{entry.created_at}</small>
              </div>
            ))}
          </div>
        </article>
      </div>

      <div className="panel-grid detail-grid">
        <article className="panel">
          <div className="panel-header">
            <h2>Timeline</h2>
            <span>{timeline.length}</span>
          </div>
          <div className="list-stack">
            {timeline.map((entry) => (
              <div className="timeline-entry" key={entry.id}>
                <strong>{entry.action}</strong>
                <small>{entry.actor ?? "system"} · {entry.created_at}</small>
                {entry.body ? <p>{entry.body}</p> : null}
              </div>
            ))}
          </div>
        </article>

        <article className="panel raw-panel">
          <div className="panel-header">
            <h2>Raw Event</h2>
          </div>
          <pre>{rawEvent}</pre>
        </article>
      </div>
    </section>
  );
}

function SummaryField({ label, value }: { label: string; value?: string }) {
  if (!value) return null;
  return (
    <div className="summary-field">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function formatJson(value: string): string {
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}
