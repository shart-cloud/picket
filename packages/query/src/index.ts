export {
  createR2SqlHttpExecutor,
  R2SqlAuthError,
  R2SqlQueryError,
  type R2SqlExecutor,
  type R2SqlHttpOptions,
  type R2SqlResult,
  type R2SqlRow
} from "./executor.js";
export { formatRows, type QueryOutputFormat } from "./format.js";
export {
  buildNlSqlSystem,
  createAnthropicNlSqlClient,
  DEFAULT_NL_QUERY_MODEL,
  naturalLanguageToSql,
  NlSqlError,
  type AnthropicNlSqlOptions,
  type BuildNlSqlSystemInput,
  type NlSqlClient,
  type NlSqlField,
  type NlSqlGeneration,
  type NlSqlGenerateInput
} from "./natural.js";

export const PRESET_QUERY_NAMES: readonly PresetQueryName[] = [
  "failed-logins",
  "iam-changes",
  "okta-to-aws-sensitive-actions",
  "threat-intel-ip-matches"
];

export interface R2SqlCapabilities {
  joins: boolean;
  subqueries: boolean;
  commonTableExpressions: boolean;
  scalarFunctionCount: number;
  aggregateFunctionCount: number;
  readOnly: boolean;
  unsupportedFeatures: string[];
}

export const R2_SQL_CAPABILITIES: R2SqlCapabilities = {
  joins: true,
  subqueries: true,
  commonTableExpressions: true,
  scalarFunctionCount: 173,
  aggregateFunctionCount: 33,
  readOnly: true,
  unsupportedFeatures: [
    "window functions",
    "select distinct",
    "union",
    "intersect",
    "except",
    "offset",
    "array_agg",
    "string_agg",
    "insert",
    "update",
    "delete",
    "ddl"
  ]
};

export type PresetQueryName = "failed-logins" | "iam-changes" | "okta-to-aws-sensitive-actions" | "threat-intel-ip-matches";

export interface PresetQueryOptions {
  hours?: number;
  limit?: number;
  /**
   * Suffix appended to every table name in the preset (`aws_cloudtrail` →
   * `aws_cloudtrail_<suffix>`). The terraform module mints a random suffix
   * to dodge a Pipelines open-beta cache bug (`1012: writing to existing
   * Catalog tables is not yet supported`); pass `r2_catalog_table_suffix`
   * from terraform output here so the queries hit the right tables.
   */
  tableSuffix?: string;
}

export interface QueryValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

const MUTATING_SQL = /\b(insert|update|delete|merge|create|alter|drop|truncate|grant|revoke)\b/i;
const UNSUPPORTED_SQL = [
  { name: "window functions", pattern: /\bover\s*\(/i },
  { name: "select distinct", pattern: /\bselect\s+distinct\b/i },
  { name: "union", pattern: /\bunion\b/i },
  { name: "intersect", pattern: /\bintersect\b/i },
  { name: "except", pattern: /\bexcept\b/i },
  { name: "offset", pattern: /\boffset\b/i },
  { name: "array_agg", pattern: /\barray_agg\s*\(/i },
  { name: "string_agg", pattern: /\bstring_agg\s*\(/i }
];

export function validateR2Sql(sql: string): QueryValidationResult {
  const normalized = stripSqlComments(sql).trim();
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!normalized) {
    errors.push("SQL query cannot be empty.");
    return { valid: false, errors, warnings };
  }

  if (!startsWithReadOnlyStatement(normalized)) {
    errors.push("R2 SQL queries must start with SELECT or WITH.");
  }

  if (MUTATING_SQL.test(normalized)) {
    errors.push("R2 SQL is read-only; mutating and DDL statements are not supported.");
  }

  for (const unsupported of UNSUPPORTED_SQL) {
    if (unsupported.pattern.test(normalized)) {
      errors.push(`R2 SQL does not currently support ${unsupported.name}.`);
    }
  }

  if (!hasTimeRangeFilter(normalized)) {
    warnings.push("Add a time-range WHERE filter to control scan cost and JOIN selectivity.");
  }

  if (/\bcross\s+join\b/i.test(normalized)) {
    warnings.push("Avoid CROSS JOINs on large event tables unless the join inputs are tightly filtered.");
  }

  if (/\bjoin\b/i.test(normalized) && !/\bwhere\b/i.test(normalized)) {
    warnings.push("JOIN queries should include WHERE filters, preferably on event time and join keys.");
  }

  return { valid: errors.length === 0, errors, warnings };
}

export interface QueryPlan {
  // Tables referenced in FROM / JOIN clauses, in first-seen order.
  tables: string[];
  has_time_filter: boolean;
  has_join: boolean;
  has_limit: boolean;
  read_only: boolean;
}

export interface QueryExplain {
  sql: string;
  valid: boolean;
  errors: string[];
  warnings: string[];
  plan: QueryPlan;
}

// Static, no-execution "plan" for a query: validation result plus a structural
// read of the SQL (referenced tables, presence of a time filter / join / limit).
// Backs POST /api/v1/query/explain — real EXPLAIN would require running it.
export function explainQuery(sql: string): QueryExplain {
  const validation = validateR2Sql(sql);
  return {
    sql,
    valid: validation.valid,
    errors: validation.errors,
    warnings: validation.warnings,
    plan: planR2Sql(sql)
  };
}

export function planR2Sql(sql: string): QueryPlan {
  const normalized = stripSqlComments(sql);
  const tables: string[] = [];
  const tablePattern = /\b(?:from|join)\s+([a-zA-Z_][\w]*)/gi;
  let match: RegExpExecArray | null;
  while ((match = tablePattern.exec(normalized)) !== null) {
    const table = match[1];
    if (table && !tables.includes(table)) tables.push(table);
  }
  return {
    tables,
    has_time_filter: hasTimeRangeFilter(normalized),
    has_join: /\bjoin\b/i.test(normalized),
    has_limit: /\blimit\b/i.test(normalized),
    read_only: startsWithReadOnlyStatement(normalized) && !MUTATING_SQL.test(normalized)
  };
}

export function presetQuery(name: PresetQueryName, options: PresetQueryOptions = {}): string {
  const hours = positiveInteger(options.hours, 24);
  const limit = positiveInteger(options.limit, 100);
  const sfx = options.tableSuffix ? `_${options.tableSuffix}` : "";
  const okta_auth = `okta_auth${sfx}`;
  const aws_cloudtrail = `aws_cloudtrail${sfx}`;
  const threat_intel = `threat_intel${sfx}`;

  switch (name) {
    case "failed-logins":
      return `SELECT time, actor_user_uid, actor_user_email, src_endpoint_ip, status
FROM ${okta_auth}
WHERE time > now() - interval '${hours}' hour
  AND status = 'failure'
ORDER BY time DESC
LIMIT ${limit}`;

    case "iam-changes":
      return `SELECT time, actor_user_uid, src_endpoint_ip, api_operation, status
FROM ${aws_cloudtrail}
WHERE time > now() - interval '${hours}' hour
  AND api_operation IN ('AttachUserPolicy', 'PutUserPolicy', 'CreateAccessKey', 'UpdateAssumeRolePolicy')
ORDER BY time DESC
LIMIT ${limit}`;

    case "okta-to-aws-sensitive-actions":
      return `SELECT o.actor_user_uid, o.time AS okta_time, ct.time AS aws_time, ct.api_operation, ct.src_endpoint_ip
FROM ${okta_auth} o
JOIN ${aws_cloudtrail} ct
  ON o.actor_user_uid = ct.actor_user_uid
WHERE o.time > now() - interval '${hours}' hour
  AND ct.time BETWEEN o.time AND o.time + interval '5' minute
  AND ct.api_operation IN ('AssumeRole', 'CreateAccessKey')
LIMIT ${limit}`;

    case "threat-intel-ip-matches":
      return `SELECT e.time, e.actor_user_uid, e.src_endpoint_ip, e.api_operation, ti.feed_name, ti.threat_type
FROM ${aws_cloudtrail} e
JOIN ${threat_intel} ti
  ON e.src_endpoint_ip = ti.indicator
WHERE e.time > now() - interval '${hours}' hour
  AND ti.indicator_type = 'ipv4'
LIMIT ${limit}`;
  }
}

function stripSqlComments(sql: string): string {
  return sql.replace(/--.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
}

function startsWithReadOnlyStatement(sql: string): boolean {
  return /^\s*(select|with)\b/i.test(sql);
}

function hasTimeRangeFilter(sql: string): boolean {
  return /\bwhere\b[\s\S]*\btime\b\s*(>|>=|between)\b/i.test(sql);
}

function positiveInteger(value: number | undefined, fallback: number): number {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : fallback;
}
