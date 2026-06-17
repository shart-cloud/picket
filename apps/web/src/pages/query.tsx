import { useMemo, useState } from "react";
import type { FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { QueryHistoryRow, SavedQueryRow } from "@picket/core/saved-queries";

import {
  explainSqlQuery,
  listQueryHistory,
  listSavedQueries,
  runNaturalQuery,
  runSqlQuery,
  saveSqlQuery,
  type QueryJob
} from "../api";
import {
  asQueryResult,
  formatQueryCell,
  queryResultToCsv,
  queryResultToJson,
  sortQueryRows,
  type SortDirection
} from "../query-utils";
import { ErrorState, LoadingState } from "../ui";

type QueryMode = "sql" | "natural";

const DEFAULT_SQL = `SELECT time, source, activity_name, status, src_endpoint_ip
FROM aws_cloudtrail
ORDER BY time DESC
LIMIT 100`;

export function QueryPage() {
  const queryClient = useQueryClient();
  const [mode, setMode] = useState<QueryMode>("sql");
  const [sql, setSql] = useState(DEFAULT_SQL);
  const [question, setQuestion] = useState("Show me critical alerts from the last 24 hours");
  const [saveOpen, setSaveOpen] = useState(false);
  const [saveName, setSaveName] = useState("");
  const [saveDescription, setSaveDescription] = useState("");
  const [sort, setSort] = useState<{ column: string; direction: SortDirection } | null>(null);

  const saved = useQuery({ queryKey: ["query", "saved"], queryFn: () => listSavedQueries(25) });
  const history = useQuery({ queryKey: ["query", "history"], queryFn: () => listQueryHistory(25) });
  const execute = useMutation({
    mutationFn: () => (mode === "sql" ? runSqlQuery(sql) : runNaturalQuery(question)),
    onSuccess: async () => {
      setSort(null);
      await queryClient.invalidateQueries({ queryKey: ["query", "history"] });
    }
  });
  const explain = useMutation({ mutationFn: () => explainSqlQuery(sql) });
  const save = useMutation({
    mutationFn: () => saveSqlQuery({ name: saveName, description: saveDescription || undefined, sql }),
    onSuccess: async () => {
      setSaveOpen(false);
      setSaveName("");
      setSaveDescription("");
      await queryClient.invalidateQueries({ queryKey: ["query", "saved"] });
    }
  });

  const result = asQueryResult(execute.data?.result);
  const rows = useMemo(
    () => (result && sort ? sortQueryRows(result.rows, sort.column, sort.direction) : result?.rows ?? []),
    [result, sort]
  );

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    execute.mutate();
  }

  function loadSql(nextSql: string) {
    setSql(nextSql);
    setMode("sql");
    execute.reset();
    explain.reset();
  }

  function toggleSort(column: string) {
    setSort((current) => ({
      column,
      direction: current?.column === column && current.direction === "asc" ? "desc" : "asc"
    }));
  }

  return (
    <section className="page-stack">
      <article className="panel query-panel">
        <div className="panel-header query-heading">
          <div>
            <h2>Query Explorer</h2>
            <span>Hunt across normalized event tables with R2 SQL</span>
          </div>
          <div className="mode-toggle" aria-label="Query mode">
            <button className={mode === "sql" ? "active" : ""} onClick={() => setMode("sql")} type="button">SQL</button>
            <button className={mode === "natural" ? "active" : ""} onClick={() => setMode("natural")} type="button">Natural language</button>
          </div>
        </div>

        <form className="query-form" onSubmit={submit}>
          {mode === "sql" ? (
            <textarea aria-label="SQL query" className="sql-editor" spellCheck={false} value={sql} onChange={(event) => setSql(event.target.value)} />
          ) : (
            <textarea aria-label="Natural language query" value={question} onChange={(event) => setQuestion(event.target.value)} />
          )}
          <div className="button-row">
            <button className="button" disabled={execute.isPending || (mode === "sql" ? sql.trim().length === 0 : question.trim().length === 0)} type="submit">
              {execute.isPending ? "Running query" : "Run query"}
            </button>
            {mode === "sql" ? (
              <>
                <button className="button secondary" disabled={explain.isPending || sql.trim().length === 0} onClick={() => explain.mutate()} type="button">
                  {explain.isPending ? "Checking" : "Explain"}
                </button>
                <button className="button secondary" disabled={sql.trim().length === 0} onClick={() => setSaveOpen((open) => !open)} type="button">Save</button>
              </>
            ) : null}
          </div>
        </form>

        {saveOpen ? (
          <div className="save-query-form">
            <input aria-label="Saved query name" placeholder="Query name" value={saveName} onChange={(event) => setSaveName(event.target.value)} />
            <input aria-label="Saved query description" placeholder="Description (optional)" value={saveDescription} onChange={(event) => setSaveDescription(event.target.value)} />
            <button className="button secondary" disabled={save.isPending || saveName.trim().length === 0} onClick={() => save.mutate()} type="button">
              {save.isPending ? "Saving" : "Save query"}
            </button>
          </div>
        ) : null}

        {execute.isError ? <ErrorState error={execute.error} /> : null}
        {explain.isError ? <ErrorState error={explain.error} /> : null}
        {save.isError ? <ErrorState error={save.error} /> : null}
        {explain.data ? <ExplainPanel explain={explain.data} /> : null}
        {execute.data ? (
          <QueryResults
            job={execute.data}
            result={result}
            rows={rows}
            sort={sort}
            onEditGenerated={() => execute.data?.generated_sql && loadSql(execute.data.generated_sql)}
            onSort={toggleSort}
          />
        ) : null}
      </article>

      <div className="panel-grid query-library-grid">
        <QueryLibrary title="Saved Queries" loading={saved.isLoading} error={saved.error} rows={saved.data ?? []} onLoad={loadSql} />
        <QueryLibrary title="Recent History" loading={history.isLoading} error={history.error} rows={history.data ?? []} onLoad={loadSql} />
      </div>
    </section>
  );
}

function ExplainPanel({ explain }: { explain: Awaited<ReturnType<typeof explainSqlQuery>> }) {
  return (
    <div className={`query-explain ${explain.valid ? "valid" : "invalid"}`}>
      <strong>{explain.valid ? "Query is valid" : "Query has errors"}</strong>
      <span>Tables: {explain.plan.tables.join(", ") || "none"}</span>
      <span>{explain.plan.has_time_filter ? "Time filter present" : "No time filter"}</span>
      <span>{explain.plan.has_limit ? "LIMIT present" : "No LIMIT"}</span>
      {[...explain.errors, ...explain.warnings].map((message) => <p key={message}>{message}</p>)}
    </div>
  );
}

function QueryResults(props: {
  job: QueryJob;
  result: ReturnType<typeof asQueryResult>;
  rows: Record<string, unknown>[];
  sort: { column: string; direction: SortDirection } | null;
  onEditGenerated: () => void;
  onSort: (column: string) => void;
}) {
  return (
    <div className="query-results">
      {props.job.generated_sql ? (
        <div className="generated-query">
          <div className="panel-header">
            <div><strong>Generated SQL</strong>{props.job.rationale ? <span>{props.job.rationale}</span> : null}</div>
            <button className="button secondary" onClick={props.onEditGenerated} type="button">Edit as SQL</button>
          </div>
          <pre>{props.job.generated_sql}</pre>
        </div>
      ) : null}

      <div className="panel-header result-header">
        <div>
          <h2>Results</h2>
          <span>{props.job.row_count ?? props.rows.length} rows</span>
        </div>
        {props.result ? (
          <div className="button-row">
            <button className="button secondary" onClick={() => downloadResult("csv", queryResultToCsv(props.result!))} type="button">Export CSV</button>
            <button className="button secondary" onClick={() => downloadResult("json", queryResultToJson(props.result!))} type="button">Export JSON</button>
          </div>
        ) : null}
      </div>

      {!props.result || props.result.columns.length === 0 ? <div className="empty-table">The query returned no tabular results.</div> : (
        <div className="table-scroll query-table-scroll">
          <table className="data-table query-result-table">
            <thead><tr>{props.result.columns.map((column) => (
              <th key={column}><button className="sort-button" onClick={() => props.onSort(column)} type="button">{column}{props.sort?.column === column ? (props.sort.direction === "asc" ? " ↑" : " ↓") : ""}</button></th>
            ))}</tr></thead>
            <tbody>{props.rows.map((row, rowIndex) => <tr key={rowIndex}>{props.result!.columns.map((column) => {
              const value = row[column];
              const formatted = formatQueryCell(value);
              return <td key={column} title={formatted}>{value === null || value === undefined ? <span className="null-cell">null</span> : formatted}</td>;
            })}</tr>)}</tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function QueryLibrary(props: {
  title: string;
  loading: boolean;
  error: unknown;
  rows: Array<SavedQueryRow | QueryHistoryRow>;
  onLoad: (sql: string) => void;
}) {
  return (
    <article className="panel query-library">
      <div className="panel-header"><h2>{props.title}</h2><span>{props.rows.length} shown</span></div>
      {props.loading ? <LoadingState label={`Loading ${props.title.toLowerCase()}`} /> : null}
      {props.error ? <ErrorState error={props.error} /> : null}
      {!props.loading && !props.error && props.rows.length === 0 ? <div className="empty-table">Nothing here yet.</div> : null}
      <div className="query-library-list">
        {props.rows.map((row) => (
          <button className="query-library-item" key={row.id} onClick={() => props.onLoad(row.sql)} type="button">
            <strong>{"name" in row ? row.name : formatTimestamp(row.created_at)}</strong>
            <span>{oneLine(row.sql)}</span>
            {"description" in row && row.description ? <small>{row.description}</small> : null}
          </button>
        ))}
      </div>
    </article>
  );
}

function downloadResult(extension: "csv" | "json", content: string) {
  const mime = extension === "csv" ? "text/csv;charset=utf-8" : "application/json;charset=utf-8";
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `picket-query-${new Date().toISOString().replaceAll(":", "-")}.${extension}`;
  link.click();
  URL.revokeObjectURL(url);
}

function oneLine(sql: string): string {
  const value = sql.replace(/\s+/g, " ").trim();
  return value.length > 120 ? `${value.slice(0, 119)}…` : value;
}

function formatTimestamp(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
