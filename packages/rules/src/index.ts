import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type { AlertSeverity, OcsfClass, SourceId } from "@picket/core";
import type {
  RuleExecutionKind,
  ScheduledSqlConfig,
  SigmaDetection,
  SigmaRule,
  StatefulConfig
} from "@picket/sigma-engine";
import { parse } from "yaml";

export type { RuleExecutionKind, SigmaRule } from "@picket/sigma-engine";

export interface RuleMetadata {
  id: string;
  title: string;
  description: string;
  severity: AlertSeverity;
  source: SourceId;
  enabled: boolean;
  execution: RuleExecutionKind;
  tags: string[];
}

const SEVERITIES = new Set<AlertSeverity>(["critical", "high", "medium", "low", "informational"]);
const SOURCES = new Set<SourceId>([
  "aws_cloudtrail",
  "aws_vpc_flow",
  "aws_guardduty",
  "gcp_cloud_audit",
  "azure_activity",
  "azure_ad_signin",
  "github_audit",
  "m365_management",
  "okta_auth",
  "cloudflare_audit",
  "kubernetes_audit"
]);
const CLASSES = new Set<OcsfClass>([
  "authentication",
  "api_activity",
  "account_change",
  "network_activity",
  "detection_finding"
]);
const EXECUTIONS = new Set<RuleExecutionKind>(["sigma", "sql", "stateful"]);

export function loadSigmaRule(yamlString: string): SigmaRule {
  const document = parse(yamlString) as unknown;
  if (!isRecord(document)) throw new Error("Sigma rule must be a YAML object");

  const id = requiredString(document, "id");
  const title = requiredString(document, "title");
  const description = requiredString(document, "description");
  const severity = enumValue(document, "severity", SEVERITIES);
  const execution =
    optionalEnumValue(document, "execution", EXECUTIONS) ??
    (isRecord(document.sql) ? "sql" : isRecord(document.stateful) ? "stateful" : "sigma");
  const logsource = parseLogsource(document.logsource);
  const tags = optionalStringArray(document, "tags");

  // SQL rules carry a `sql` block and no sigma `detection`; every other kind
  // requires a detection.
  if (execution === "sql") {
    if (!isRecord(document.sql)) throw new Error("Sigma rule with execution: sql requires a sql block");
  } else if (!isRecord(document.detection)) {
    throw new Error("Sigma rule requires detection");
  }

  return {
    id,
    title,
    description,
    status: optionalString(document, "status"),
    severity,
    tags,
    enabled: optionalBoolean(document, "enabled") ?? true,
    execution,
    logsource,
    detection: isRecord(document.detection) ? parseDetection(document.detection) : undefined,
    dedupe_key: optionalString(document, "dedupe_key"),
    dedupe_prefix: optionalString(document, "dedupe_prefix"),
    stateful: isRecord(document.stateful) ? parseStateful(document.stateful) : undefined,
    sql: isRecord(document.sql) ? parseScheduledSql(document.sql) : undefined
  };
}

function parseScheduledSql(value: Record<string, unknown>): ScheduledSqlConfig {
  const query = requiredString(value, "query");
  const interval = durationString(value, "interval");
  const threshold = value.threshold === undefined ? undefined : requiredNumber(value, "threshold");
  const countField = optionalString(value, "count_field");
  const groupBy = optionalString(value, "group_by");
  return {
    query,
    interval,
    ...(threshold !== undefined ? { threshold } : {}),
    ...(countField ? { count_field: countField } : {}),
    ...(groupBy ? { group_by: groupBy } : {})
  };
}

export function loadSigmaRulesFromDir(dirPath: string): SigmaRule[] {
  return readdirSync(dirPath)
    .filter((file) => file.endsWith(".yml") || file.endsWith(".yaml"))
    .sort()
    .map((file) => loadSigmaRule(readFileSync(join(dirPath, file), "utf8")));
}

export function toRuleMetadata(rule: SigmaRule): RuleMetadata {
  return {
    id: rule.id,
    title: rule.title,
    description: rule.description,
    severity: rule.severity,
    source: rule.logsource.source,
    enabled: rule.enabled,
    execution: rule.execution,
    tags: rule.tags
  };
}

function parseLogsource(value: unknown): SigmaRule["logsource"] {
  if (!isRecord(value)) throw new Error("Sigma rule requires logsource");
  const source = enumValue(value, "source", SOURCES);
  const className = optionalEnumValue(value, "class_name", CLASSES);
  return className ? { source, class_name: className } : { source };
}

function parseDetection(value: unknown): SigmaDetection {
  if (!isRecord(value)) throw new Error("Sigma rule requires detection");
  const condition = requiredString(value, "condition");
  const detection: SigmaDetection = { condition };

  for (const [name, selection] of Object.entries(value)) {
    if (name === "condition") continue;
    if (!isRecord(selection)) throw new Error(`Detection selection ${name} must be an object`);
    detection[name] = parseSelection(name, selection);
  }

  return detection;
}

function parseStateful(value: Record<string, unknown>): StatefulConfig {
  const type = requiredString(value, "type");
  if (type === "threshold") {
    const groupBy = optionalString(value, "group_by");
    const field = optionalString(value, "field");
    if (!groupBy && !field) throw new Error("Stateful threshold rule requires group_by or field");

    return {
      type,
      ...(groupBy ? { group_by: groupBy } : {}),
      ...(field ? { field } : {}),
      threshold: requiredNumber(value, "threshold"),
      window: durationString(value, "window"),
      ...(value.suppress_for === undefined ? {} : { suppress_for: durationString(value, "suppress_for") })
    };
  }

  if (type === "geo_velocity") {
    return {
      type,
      field: requiredString(value, "field"),
      location_field: requiredString(value, "location_field"),
      max_speed_kmh: requiredNumber(value, "max_speed_kmh"),
      window: durationString(value, "window")
    };
  }

  throw new Error(`Stateful rule type has unsupported value: ${type}`);
}

function parseSelection(name: string, value: Record<string, unknown>): Record<string, string | number | boolean | (string | number | boolean)[]> {
  const selection: Record<string, string | number | boolean | (string | number | boolean)[]> = {};

  for (const [field, rawValue] of Object.entries(value)) {
    if (typeof rawValue === "string" || typeof rawValue === "number" || typeof rawValue === "boolean") {
      selection[field] = rawValue;
      continue;
    }

    if (Array.isArray(rawValue) && rawValue.every((item) => typeof item === "string" || typeof item === "number" || typeof item === "boolean")) {
      selection[field] = rawValue;
      continue;
    }

    throw new Error(`Detection selection ${name}.${field} must be a scalar or scalar list`);
  }

  return selection;
}

function requiredString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string" || value.length === 0) throw new Error(`Sigma rule requires ${key}`);
  return value;
}

function requiredNumber(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`Sigma rule requires numeric ${key}`);
  return value;
}

function durationString(record: Record<string, unknown>, key: string): string {
  const value = requiredString(record, key);
  if (!/^\d+[smhd]$/.test(value)) throw new Error(`Sigma rule ${key} must be a duration like 15m`);
  return value;
}

function optionalString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new Error(`Sigma rule ${key} must be a string`);
  return value;
}

function optionalBoolean(record: Record<string, unknown>, key: string): boolean | undefined {
  const value = record[key];
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") throw new Error(`Sigma rule ${key} must be a boolean`);
  return value;
}

function optionalStringArray(record: Record<string, unknown>, key: string): string[] {
  const value = record[key];
  if (value === undefined) return [];
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error(`Sigma rule ${key} must be a string array`);
  }
  return value;
}

function enumValue<T extends string>(record: Record<string, unknown>, key: string, allowed: Set<T>): T {
  const value = requiredString(record, key);
  if (!allowed.has(value as T)) throw new Error(`Sigma rule ${key} has unsupported value: ${value}`);
  return value as T;
}

function optionalEnumValue<T extends string>(record: Record<string, unknown>, key: string, allowed: Set<T>): T | undefined {
  const value = optionalString(record, key);
  if (value === undefined) return undefined;
  if (!allowed.has(value as T)) throw new Error(`Sigma rule ${key} has unsupported value: ${value}`);
  return value as T;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
