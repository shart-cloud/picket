import type { AlertStateDb } from "./alerts.js";

// Detection rule registry (Milestone 1). The detection worker owns the bundle of
// rules; this mirror in D1 lets the API list/show/toggle them and surfaces match
// stats. Static metadata is seeded idempotently from the bundle; `enabled` is an
// operator-owned runtime override; match_count / last_triggered_at are updated by
// the worker when a rule fires.

export interface DetectionRuleRow {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  source: string;
  class_name: string | null;
  execution: string;
  tags: string[];
  enabled: boolean;
  definition: unknown;
  match_count: number;
  last_triggered_at: string | null;
  created_at: string;
  updated_at: string;
}

// Raw shape as stored in D1 (JSON columns + 0/1 booleans).
interface DetectionRuleDbRow {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  source: string;
  class_name: string | null;
  execution: string;
  tags_json: string;
  enabled: number;
  definition_json: string;
  match_count: number;
  last_triggered_at: string | null;
  created_at: string;
  updated_at: string;
}

// The static, build-time facts about a rule, derived from the bundle.
export interface DetectionRuleSeed {
  id: string;
  title: string;
  description?: string | null;
  severity: string;
  source: string;
  class_name?: string | null;
  execution: string;
  tags: string[];
  enabled: boolean;
  definition: unknown;
}

export interface ListDetectionRulesFilters {
  enabled?: boolean;
  source?: string;
}

export class DetectionRuleNotFoundError extends Error {
  constructor(public readonly ruleId: string) {
    super(`Detection rule not found: ${ruleId}`);
    this.name = "DetectionRuleNotFoundError";
  }
}

const RULE_COLUMNS =
  "id, title, description, severity, source, class_name, execution, tags_json, enabled, definition_json, match_count, last_triggered_at, created_at, updated_at";

function hydrate(row: DetectionRuleDbRow): DetectionRuleRow {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    severity: row.severity,
    source: row.source,
    class_name: row.class_name,
    execution: row.execution,
    tags: safeJsonArray(row.tags_json),
    enabled: row.enabled !== 0,
    definition: safeJson(row.definition_json),
    match_count: row.match_count,
    last_triggered_at: row.last_triggered_at,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

// Idempotent upsert of the static metadata. Preserves the operator's `enabled`
// override and the accumulated stats (match_count, last_triggered_at) — only the
// build-time facts are refreshed so a redeploy can't silently re-enable a rule an
// operator disabled, or reset its counters.
export async function seedDetectionRules(db: AlertStateDb, rules: readonly DetectionRuleSeed[]): Promise<void> {
  const now = new Date().toISOString();
  for (const rule of rules) {
    await db
      .prepare(
        `INSERT INTO detection_rules (
           id, title, description, severity, source, class_name, execution,
           tags_json, enabled, definition_json, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           title = excluded.title,
           description = excluded.description,
           severity = excluded.severity,
           source = excluded.source,
           class_name = excluded.class_name,
           execution = excluded.execution,
           tags_json = excluded.tags_json,
           definition_json = excluded.definition_json,
           updated_at = excluded.updated_at`
      )
      .bind(
        rule.id,
        rule.title,
        rule.description ?? null,
        rule.severity,
        rule.source,
        rule.class_name ?? null,
        rule.execution,
        JSON.stringify(rule.tags),
        rule.enabled ? 1 : 0,
        JSON.stringify(rule.definition),
        now
      )
      .run();
  }
}

export async function listDetectionRules(
  db: AlertStateDb,
  filters: ListDetectionRulesFilters = {}
): Promise<DetectionRuleRow[]> {
  const conditions: string[] = [];
  const params: unknown[] = [];
  if (filters.enabled !== undefined) {
    conditions.push("enabled = ?");
    params.push(filters.enabled ? 1 : 0);
  }
  if (filters.source) {
    conditions.push("source = ?");
    params.push(filters.source);
  }
  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const sql = `SELECT ${RULE_COLUMNS} FROM detection_rules ${where} ORDER BY id ASC`;
  const result = await db.prepare(sql).bind(...params).all<DetectionRuleDbRow>();
  return result.results.map(hydrate);
}

export async function getDetectionRule(db: AlertStateDb, id: string): Promise<DetectionRuleRow | null> {
  const row = await db
    .prepare(`SELECT ${RULE_COLUMNS} FROM detection_rules WHERE id = ?`)
    .bind(id)
    .first<DetectionRuleDbRow>();
  return row ? hydrate(row) : null;
}

export async function setDetectionRuleEnabled(
  db: AlertStateDb,
  id: string,
  enabled: boolean
): Promise<DetectionRuleRow> {
  const existing = await db.prepare("SELECT id FROM detection_rules WHERE id = ?").bind(id).first<{ id: string }>();
  if (!existing) throw new DetectionRuleNotFoundError(id);

  const now = new Date().toISOString();
  await db
    .prepare("UPDATE detection_rules SET enabled = ?, updated_at = ? WHERE id = ?")
    .bind(enabled ? 1 : 0, now, id)
    .run();

  const updated = await getDetectionRule(db, id);
  if (!updated) throw new DetectionRuleNotFoundError(id);
  return updated;
}

// Increment match_count and bump last_triggered_at for each rule that fired.
export async function recordRuleTriggers(db: AlertStateDb, ruleIds: readonly string[]): Promise<void> {
  if (ruleIds.length === 0) return;
  const now = new Date().toISOString();
  for (const id of ruleIds) {
    await db
      .prepare(
        "UPDATE detection_rules SET match_count = match_count + 1, last_triggered_at = ?, updated_at = ? WHERE id = ?"
      )
      .bind(now, now, id)
      .run();
  }
}

// Rule IDs an operator has disabled at runtime — read by the worker to skip them.
export async function getDisabledRuleIds(db: AlertStateDb): Promise<string[]> {
  const result = await db
    .prepare("SELECT id FROM detection_rules WHERE enabled = 0")
    .all<{ id: string }>();
  return result.results.map((row) => row.id);
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function safeJsonArray(text: string): string[] {
  const parsed = safeJson(text);
  return Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === "string") : [];
}
