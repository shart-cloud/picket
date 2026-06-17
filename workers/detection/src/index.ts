import { type Alert, type OcsfEvent } from "@picket/core";
import { DurableObject } from "cloudflare:workers";
import {
  DEFAULT_DEDUPE_WINDOW_MS,
  enqueueAlerts as enqueueAlertsCore,
  persistAlerts as persistAlertsCore,
  writeAlertsToPipeline as writeAlertsToPipelineCore,
  type PersistedAlert,
  type PicketPipeline
} from "@picket/core/alert-emit";
import { recordDetectionEval } from "@picket/core/detection-health";
import {
  getDisabledRuleIds,
  recordRuleTriggers,
  seedDetectionRules,
  type DetectionRuleSeed
} from "@picket/core/detection-rules";
import { evaluateSigmaRules, resolveFieldPath, type SigmaMatch, type SigmaRule } from "@picket/sigma-engine";
import { createAlert, evaluateEvent } from "./evaluator";
import { SIGMA_RULES, STATEFUL_RULES } from "./generated-rules";

const MAX_JSON_BYTES = 1_000_000;

export interface DetectionEnv {
  ALERT_QUEUE?: Queue<Alert>;
  STATEFUL_DETECTION?: DurableObjectNamespace<StatefulDetectionObject>;
  ALERTS_PIPELINE?: PicketPipeline;
  ALERT_STATE_DB?: D1Database;
}

export type { PicketPipeline, PersistedAlert };
export { evaluateEvent } from "./evaluator";

export default {
  async fetch(request: Request, env: DetectionEnv): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return json({ ok: true, worker: "picket-detection" });
    }

    if (request.method !== "POST" || url.pathname !== "/events") {
      return json({ error: "Not found" }, 404);
    }

    const contentLength = request.headers.get("content-length");
    if (contentLength && Number(contentLength) > MAX_JSON_BYTES) {
      return json({ error: "Request body too large" }, 413);
    }

    let event: OcsfEvent;
    try {
      event = await request.json<OcsfEvent>();
    } catch (error) {
      return json({ error: "Invalid JSON", detail: errorMessage(error) }, 400);
    }

    await seedRegistryOnce(env);
    const disabled = await loadDisabledRuleIds(env);
    const alerts = await evaluateEventWithStateful(event, env, disabled);
    const persistedAlerts = await persistAlerts(alerts, env);
    await writeAlertsToPipeline(alerts, env);
    await enqueueAlerts(persistedAlerts.filter((result) => result.isNew).map((result) => result.alert), env);
    await recordDetectionHeartbeat(alerts.length, env);
    await recordRuleTriggersForAlerts(alerts, env);

    console.log(
      JSON.stringify({
        message: "event evaluated",
        source: event.source,
        activity_name: event.activity_name,
        alert_count: alerts.length,
        queued_alert_count: persistedAlerts.filter((result) => result.isNew).length
      })
    );

    return json({ accepted: true, alert_count: alerts.length, queued_alert_count: persistedAlerts.filter((result) => result.isNew).length, alerts }, 202);
  }
} satisfies ExportedHandler<DetectionEnv>;

export async function evaluateEventWithStateful(
  event: OcsfEvent,
  env: DetectionEnv,
  disabled: ReadonlySet<string> = new Set()
): Promise<Alert[]> {
  const alerts = evaluateEvent(event).filter((alert) => !disabled.has(alert.rule_id));
  if (!env.STATEFUL_DETECTION) return alerts;

  for (const rule of STATEFUL_RULES) {
    if (!rule.enabled || disabled.has(rule.id)) continue;
    if (rule.stateful?.type !== "threshold") {
      // Only threshold rules run in the realtime engine today. geo_velocity and
      // future stateful types land with the M3 scheduled-detection path. Warn
      // (instead of silently skipping) so an enabled-but-unsupported rule is
      // visible rather than a quiet no-op.
      console.warn(
        JSON.stringify({ message: "skipped unsupported stateful rule type", rule_id: rule.id, type: rule.stateful?.type })
      );
      continue;
    }
    if (evaluateSigmaRules(event, [{ ...rule, execution: "sigma" }]).length === 0) continue;

    const groupField = rule.stateful.group_by ?? rule.stateful.field;
    if (!groupField) continue;

    const groupValue = resolveFieldPath(event, groupField);
    if (groupValue === undefined || groupValue === null || groupValue === "") continue;

    const objectName = `${rule.id}:${String(groupValue)}`;
    const object = env.STATEFUL_DETECTION.getByName(objectName);
    const match = await object.evaluate(rule, event);
    if (match) alerts.push(createAlert(match, event));
  }

  return alerts;
}

// Thin env-aware wrappers over the shared @picket/core/alert-emit helpers. The
// no-binding short-circuits keep detection (and ingestion) working when the
// optional alert bindings aren't configured.
export async function enqueueAlerts(alerts: Alert[], env: DetectionEnv): Promise<void> {
  if (!env.ALERT_QUEUE || alerts.length === 0) return;
  await enqueueAlertsCore(env.ALERT_QUEUE, alerts);
}

export async function writeAlertsToPipeline(alerts: Alert[], env: DetectionEnv): Promise<void> {
  if (!env.ALERTS_PIPELINE || alerts.length === 0) return;
  await writeAlertsToPipelineCore(env.ALERTS_PIPELINE, alerts);
}

// --- Detection rule registry (Milestone 1) ---
//
// The bundle is the source of truth for which rules exist; D1 mirrors them so the
// API can list/toggle them. The worker seeds metadata once per isolate, honors
// operator disable-overrides (TTL-cached so we don't read D1 per event), and bumps
// match stats when a rule fires. All best-effort: registry problems never block
// detection or ingestion.

const DISABLED_CACHE_TTL_MS = 30_000;
let registrySeeded = false;
let disabledCache: { ids: Set<string>; loadedAt: number } | null = null;

// Test-only: reset module-level caches between cases.
export function _resetDetectionRegistryCaches(): void {
  registrySeeded = false;
  disabledCache = null;
}

function ruleSeeds(): DetectionRuleSeed[] {
  return [...SIGMA_RULES, ...STATEFUL_RULES].map((rule) => ({
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
  }));
}

async function seedRegistryOnce(env: DetectionEnv): Promise<void> {
  if (registrySeeded || !env.ALERT_STATE_DB) return;
  try {
    await seedDetectionRules(env.ALERT_STATE_DB, ruleSeeds());
    registrySeeded = true;
  } catch (error) {
    console.error(JSON.stringify({ message: "detection registry seed failed", error: errorMessage(error) }));
  }
}

async function loadDisabledRuleIds(env: DetectionEnv): Promise<Set<string>> {
  if (!env.ALERT_STATE_DB) return new Set();
  const now = Date.now();
  if (disabledCache && now - disabledCache.loadedAt < DISABLED_CACHE_TTL_MS) return disabledCache.ids;
  try {
    const ids = await getDisabledRuleIds(env.ALERT_STATE_DB);
    disabledCache = { ids: new Set(ids), loadedAt: now };
    return disabledCache.ids;
  } catch (error) {
    console.error(JSON.stringify({ message: "detection disabled-rule load failed", error: errorMessage(error) }));
    return disabledCache?.ids ?? new Set();
  }
}

async function recordRuleTriggersForAlerts(alerts: Alert[], env: DetectionEnv): Promise<void> {
  if (!env.ALERT_STATE_DB || alerts.length === 0) return;
  const ruleIds = [...new Set(alerts.map((alert) => alert.rule_id))];
  try {
    await recordRuleTriggers(env.ALERT_STATE_DB, ruleIds);
  } catch (error) {
    console.error(JSON.stringify({ message: "detection rule-trigger record failed", error: errorMessage(error) }));
  }
}

// Best-effort detection heartbeat. Records one evaluation so `picket status` and
// the API can report liveness + rule coverage. Never blocks or fails detection.
async function recordDetectionHeartbeat(alertsCreated: number, env: DetectionEnv): Promise<void> {
  if (!env.ALERT_STATE_DB) return;
  try {
    await recordDetectionEval(env.ALERT_STATE_DB, {
      events_evaluated: 1,
      alerts_created: alertsCreated,
      stateless_rule_count: SIGMA_RULES.length,
      stateful_rule_count: STATEFUL_RULES.length
    });
  } catch (error) {
    console.error(JSON.stringify({ message: "detection heartbeat failed", error: errorMessage(error) }));
  }
}

export async function persistAlerts(alerts: Alert[], env: DetectionEnv): Promise<PersistedAlert[]> {
  if (!env.ALERT_STATE_DB || alerts.length === 0) return alerts.map((alert) => ({ alert, isNew: true }));
  return persistAlertsCore(env.ALERT_STATE_DB, alerts, DEFAULT_DEDUPE_WINDOW_MS);
}

export class StatefulDetectionObject extends DurableObject<DetectionEnv> {
  constructor(ctx: DurableObjectState, env: DetectionEnv) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          rule_id TEXT NOT NULL,
          group_key TEXT NOT NULL,
          event_time INTEGER NOT NULL,
          event_json TEXT NOT NULL
        )
      `);
      this.ctx.storage.sql.exec(`
        CREATE INDEX IF NOT EXISTS events_window_idx
        ON events (rule_id, group_key, event_time)
      `);
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS alert_suppressions (
          rule_id TEXT NOT NULL,
          group_key TEXT NOT NULL,
          suppressed_until INTEGER NOT NULL,
          PRIMARY KEY (rule_id, group_key)
        )
      `);
    });
  }

  async evaluate(rule: SigmaRule, event: OcsfEvent): Promise<SigmaMatch | undefined> {
    if (rule.stateful?.type !== "threshold") return undefined;

    const groupField = rule.stateful.group_by ?? rule.stateful.field;
    if (!groupField) return undefined;

    const groupValue = resolveFieldPath(event, groupField);
    if (groupValue === undefined || groupValue === null || groupValue === "") return undefined;

    const groupKey = String(groupValue);
    const eventTime = eventTimeMs(event);
    const windowMs = durationMs(rule.stateful.window);
    const cutoff = eventTime - windowMs;

    this.ctx.storage.sql.exec("DELETE FROM events WHERE rule_id = ? AND group_key = ? AND event_time < ?", rule.id, groupKey, cutoff);
    this.ctx.storage.sql.exec(
      "INSERT INTO events (rule_id, group_key, event_time, event_json) VALUES (?, ?, ?, ?)",
      rule.id,
      groupKey,
      eventTime,
      JSON.stringify(event)
    );

    const activeSuppression = this.ctx.storage.sql
      .exec<{ suppressed_until: number }>(
        "SELECT suppressed_until FROM alert_suppressions WHERE rule_id = ? AND group_key = ? AND suppressed_until > ? LIMIT 1",
        rule.id,
        groupKey,
        eventTime
      )
      .toArray();
    if (activeSuppression.length > 0) return undefined;

    const count = this.ctx.storage.sql
      .exec<{ count: number }>(
        "SELECT COUNT(*) AS count FROM events WHERE rule_id = ? AND group_key = ? AND event_time >= ? AND event_time <= ?",
        rule.id,
        groupKey,
        cutoff,
        eventTime
      )
      .one().count;
    if (count < rule.stateful.threshold) return undefined;

    if (rule.stateful.suppress_for) {
      const suppressedUntil = eventTime + durationMs(rule.stateful.suppress_for);
      this.ctx.storage.sql.exec(
        `INSERT INTO alert_suppressions (rule_id, group_key, suppressed_until)
         VALUES (?, ?, ?)
         ON CONFLICT(rule_id, group_key) DO UPDATE SET suppressed_until = excluded.suppressed_until`,
        rule.id,
        groupKey,
        suppressedUntil
      );
    }

    return {
      rule_id: rule.id,
      title: rule.title,
      severity: rule.severity,
      dedupe_key: rule.dedupe_prefix ? `${rule.dedupe_prefix}:${groupKey}` : groupKey
    };
  }
}

function eventTimeMs(event: OcsfEvent): number {
  const parsed = event.time ? Date.parse(event.time) : NaN;
  return Number.isFinite(parsed) ? parsed : Date.now();
}

function durationMs(value: string): number {
  const match = /^(\d+)([smhd])$/.exec(value);
  if (!match) throw new Error(`Invalid duration: ${value}`);

  const amount = Number(match[1]);
  const unit = match[2];
  if (unit === "s") return amount * 1_000;
  if (unit === "m") return amount * 60_000;
  if (unit === "h") return amount * 3_600_000;
  return amount * 86_400_000;
}

function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      "Cache-Control": "no-store"
    }
  });
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
