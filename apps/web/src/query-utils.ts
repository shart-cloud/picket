import type { QueryResult } from "./api";

export type SortDirection = "asc" | "desc";

export function asQueryResult(value: unknown): QueryResult | null {
  if (!isObject(value) || !Array.isArray(value.rows)) return null;
  const rows = value.rows.filter(isObject);
  const declaredColumns = Array.isArray(value.columns)
    ? value.columns.filter((column): column is string => typeof column === "string")
    : [];
  const columns = declaredColumns.length > 0 ? declaredColumns : collectColumns(rows);
  return { columns, rows };
}

export function sortQueryRows(
  rows: readonly Record<string, unknown>[],
  column: string,
  direction: SortDirection
): Record<string, unknown>[] {
  const multiplier = direction === "asc" ? 1 : -1;
  return [...rows].sort((left, right) => compareValues(left[column], right[column]) * multiplier);
}

export function formatQueryCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

export function queryResultToCsv(result: QueryResult): string {
  const lines = [result.columns.map(csvCell).join(",")];
  for (const row of result.rows) {
    lines.push(result.columns.map((column) => csvCell(formatQueryCell(row[column]))).join(","));
  }
  return lines.join("\n");
}

export function queryResultToJson(result: QueryResult): string {
  return JSON.stringify(result.rows, null, 2);
}

function collectColumns(rows: readonly Record<string, unknown>[]): string[] {
  const columns = new Set<string>();
  for (const row of rows) {
    for (const key of Object.keys(row)) columns.add(key);
  }
  return [...columns];
}

function compareValues(left: unknown, right: unknown): number {
  if (left === right) return 0;
  if (left === null || left === undefined) return 1;
  if (right === null || right === undefined) return -1;
  if (typeof left === "number" && typeof right === "number") return left - right;
  return formatQueryCell(left).localeCompare(formatQueryCell(right), undefined, { numeric: true });
}

function csvCell(value: unknown): string {
  const text = formatQueryCell(value);
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
