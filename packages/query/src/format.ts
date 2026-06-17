import type { R2SqlResult, R2SqlRow } from "./executor.js";

export type QueryOutputFormat = "table" | "json" | "csv";

export function formatRows(result: R2SqlResult, format: QueryOutputFormat): string {
  switch (format) {
    case "json":
      return JSON.stringify(result.rows, null, 2);
    case "csv":
      return formatCsv(result);
    case "table":
      return formatTable(result);
  }
}

function formatTable(result: R2SqlResult): string {
  if (result.rows.length === 0) return "(0 rows)";

  const columns = result.columns.length > 0 ? result.columns : Array.from(collectColumns(result.rows));
  const cells = result.rows.map((row) => columns.map((c) => stringify(row[c])));
  const widths = columns.map((header, i) =>
    Math.max(header.length, ...cells.map((row) => (row[i] ?? "").length))
  );

  const headerLine = columns.map((c, i) => c.padEnd(widths[i] ?? 0)).join("  ");
  const separator = widths.map((w) => "-".repeat(w)).join("  ");
  const body = cells.map((row) => row.map((cell, i) => cell.padEnd(widths[i] ?? 0)).join("  "));

  return [headerLine, separator, ...body].join("\n");
}

function formatCsv(result: R2SqlResult): string {
  const columns = result.columns.length > 0 ? result.columns : Array.from(collectColumns(result.rows));
  const lines = [columns.map(csvEscape).join(",")];
  for (const row of result.rows) {
    lines.push(columns.map((c) => csvEscape(stringify(row[c]))).join(","));
  }
  return lines.join("\n");
}

function csvEscape(value: string): string {
  if (/[",\n\r]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function stringify(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function collectColumns(rows: R2SqlRow[]): Set<string> {
  const seen = new Set<string>();
  for (const row of rows) {
    for (const key of Object.keys(row)) seen.add(key);
  }
  return seen;
}
