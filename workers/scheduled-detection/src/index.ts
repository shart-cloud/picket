import type { Alert, OcsfEvent } from "@picket/core";
import {
  enqueueAlerts,
  persistAlerts,
  writeAlertsToPipeline,
  type PicketPipeline
} from "@picket/core/alert-emit";
import {
  getDisabledRuleIds,
  recordRuleTriggers,
  seedDetectionRules,
  type DetectionRuleSeed
} from "@picket/core/detection-rules";
import {
  getScheduledState,
  isScheduledRuleDue,
  parseDurationMs,
  recordScheduledRun
} from "@picket/core/scheduled-detection";
import { applyTableSuffix } from "@picket/core/sources";
import { createR2SqlHttpExecutor, type R2SqlExecutor, type R2SqlRow } from "@picket/query";
import type { ScheduledSqlConfig, SigmaRule } from "@picket/sigma-engine";

import { SQL_RULES } from "./generated-rules";

export interface ScheduledDetectionEnv {
  ALERT_STATE_DB: D1Database;
  R2_SQL_TOKEN?: string;
  PICKET_R2_WAREHOUSE?: string;
  PICKET_TABLE_SUFFIX?: string;
  ALERTS_PIPELINE?: PicketPipeline;
  ALERT_QUEUE?: Queue<Alert>;
}

export interface ScheduledRunnerHooks {
  now?: () => Date;
  uuid?: () => string;
  executorFactory?: (warehouse: string, token: string) => R2SqlExecutor;
  /** Override the bundled rule set (tests). */
  rules?: SigmaRule[];
}

export interface RuleRunResult {
  rule_id: string;
  status: "ok" | "error" | "skipped";
  row_count: number;
  alert_count: number;
  error?: string;
}

export function createScheduledRunner(hooks: ScheduledRunnerHooks = {}) {
  const now = hooks.now ?? (() => new Date());
  const newId = hooks.uuid ?? (() => crypto.randomUUID());
  const buildExecutor =
    hooks.executorFactory ?? ((warehouse: string, token: string) => createR2SqlHttpExecutor({ warehouse, token }));
  const rules = hooks.rules ?? SQL_RULES;

  // Seed the SQL rules into the detection_rules registry so they show up in
  // `picket detections list` alongside the realtime rules. Best-effort.
  async function seedRules(env: ScheduledDetectionEnv): Promise<void> {
    try {
      await seedDetectionRules(env.ALERT_STATE_DB, rules.map(toSeed));
    } catch (error) {
      console.error(JSON.stringify({ worker: "picket-scheduled-detection", message: "rule seed failed", error: msg(error) }));
    }
  }

  async function loadDisabled(env: ScheduledDetectionEnv): Promise<Set<string>> {
    try {
      return new Set(await getDisabledRuleIds(env.ALERT_STATE_DB));
    } catch {
      return new Set();
    }
  }

  async function runRule(rule: SigmaRule, env: ScheduledDetectionEnv): Promise<RuleRunResult> {
    const config = rule.sql;
    if (!config) return { rule_id: rule.id, status: "skipped", row_count: 0, alert_count: 0 };

    const warehouse = env.PICKET_R2_WAREHOUSE;
    if (!warehouse || !env.R2_SQL_TOKEN) {
      const error = !warehouse ? "PICKET_R2_WAREHOUSE not configured" : "R2_SQL_TOKEN not configured";
      await recordScheduledRun(env.ALERT_STATE_DB, { rule_id: rule.id, status: "error", error, now: now().toISOString() });
      return { rule_id: rule.id, status: "error", row_count: 0, alert_count: 0, error };
    }

    try {
      const sql = applyTableSuffix(config.query, env.PICKET_TABLE_SUFFIX);
      const executor = buildExecutor(warehouse, env.R2_SQL_TOKEN);
      const result = await executor.execute(sql);

      const matched = result.rows.filter((row) => rowMeetsThreshold(row, config));
      const alerts = matched.map((row) => synthesizeAlert(rule, config, row, now().toISOString(), newId()));

      const persisted = await persistAlerts(env.ALERT_STATE_DB, alerts);
      if (env.ALERTS_PIPELINE) await writeAlertsToPipeline(env.ALERTS_PIPELINE, alerts);
      if (env.ALERT_QUEUE) {
        await enqueueAlerts(env.ALERT_QUEUE, persisted.filter((p) => p.isNew).map((p) => p.alert));
      }
      if (alerts.length > 0) await recordRuleTriggers(env.ALERT_STATE_DB, [rule.id]);

      await recordScheduledRun(env.ALERT_STATE_DB, {
        rule_id: rule.id,
        status: "ok",
        row_count: result.rows.length,
        alert_count: alerts.length,
        now: now().toISOString()
      });
      return { rule_id: rule.id, status: "ok", row_count: result.rows.length, alert_count: alerts.length };
    } catch (error) {
      await recordScheduledRun(env.ALERT_STATE_DB, { rule_id: rule.id, status: "error", error: msg(error), now: now().toISOString() });
      return { rule_id: rule.id, status: "error", row_count: 0, alert_count: 0, error: msg(error) };
    }
  }

  // Run every enabled, non-disabled, due SQL rule. Returns per-rule results for
  // logging/tests.
  async function runDueRules(env: ScheduledDetectionEnv): Promise<RuleRunResult[]> {
    await seedRules(env);
    const disabled = await loadDisabled(env);
    const results: RuleRunResult[] = [];

    for (const rule of rules) {
      if (!rule.enabled || disabled.has(rule.id) || !rule.sql) continue;

      let intervalMs: number;
      try {
        intervalMs = parseDurationMs(rule.sql.interval);
      } catch (error) {
        console.error(JSON.stringify({ worker: "picket-scheduled-detection", message: "bad interval", rule_id: rule.id, error: msg(error) }));
        continue;
      }

      const state = await getScheduledState(env.ALERT_STATE_DB, rule.id);
      if (!isScheduledRuleDue(state, intervalMs, now())) continue;

      results.push(await runRule(rule, env));
    }
    return results;
  }

  return {
    async scheduled(_event: ScheduledController, env: ScheduledDetectionEnv): Promise<void> {
      const results = await runDueRules(env);
      console.log(
        JSON.stringify({
          worker: "picket-scheduled-detection",
          message: "scheduled run complete",
          rules_run: results.length,
          alerts_created: results.reduce((sum, r) => sum + r.alert_count, 0),
          errors: results.filter((r) => r.status === "error").map((r) => r.rule_id)
        })
      );
    },
    runDueRules,
    runRule
  };
}

function rowMeetsThreshold(row: R2SqlRow, config: ScheduledSqlConfig): boolean {
  if (!config.count_field) return true; // SQL itself is the filter
  const value = Number(row[config.count_field]);
  if (!Number.isFinite(value)) return false;
  return value >= (config.threshold ?? 1);
}

function synthesizeAlert(
  rule: SigmaRule,
  config: ScheduledSqlConfig,
  row: R2SqlRow,
  nowIso: string,
  id: string
): Alert {
  const groupKey = buildGroupKey(config.group_by, row) ?? rule.id;
  const dedupeKey = rule.dedupe_prefix ? `${rule.dedupe_prefix}:${groupKey}` : groupKey;

  const event: OcsfEvent = {
    time: nowIso,
    source: rule.logsource.source,
    category: "identity_access",
    class_name: rule.logsource.class_name ?? "api_activity",
    activity_name: "ScheduledDetection",
    status: "unknown",
    message: `${rule.title} (${groupKey})`,
    metadata: {
      product_name: "picket-scheduled-detection",
      raw_event: row
    }
  };

  return {
    id,
    rule_id: rule.id,
    title: rule.title,
    severity: rule.severity,
    source: rule.logsource.source,
    status: "open",
    dedupe_key: dedupeKey,
    match_count: 1,
    first_seen: nowIso,
    last_seen: nowIso,
    event
  };
}

function buildGroupKey(groupBy: string | undefined, row: R2SqlRow): string | undefined {
  if (!groupBy) return undefined;
  const parts = groupBy.split(",").map((column) => String(row[column.trim()] ?? ""));
  return parts.join(":");
}

function toSeed(rule: SigmaRule): DetectionRuleSeed {
  return {
    id: rule.id,
    title: rule.title,
    description: rule.description ?? null,
    severity: rule.severity,
    source: rule.logsource.source,
    class_name: rule.logsource.class_name ?? null,
    execution: rule.execution,
    tags: rule.tags ?? [],
    enabled: rule.enabled,
    definition: rule
  };
}

function msg(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const runner = createScheduledRunner();

export default {
  scheduled: runner.scheduled
} satisfies ExportedHandler<ScheduledDetectionEnv>;
