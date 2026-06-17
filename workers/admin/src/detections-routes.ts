import type { Hono } from "hono";

import type { OcsfEvent } from "@picket/core";
import { getDetectionHealth } from "@picket/core/detection-health";
import {
  DetectionRuleNotFoundError,
  getDetectionRule,
  listDetectionRules,
  setDetectionRuleEnabled
} from "@picket/core/detection-rules";
import { listScheduledDetections } from "@picket/core/scheduled-detection";
import { evaluateSigmaRules, type SigmaRule } from "@picket/sigma-engine";

import type { AdminEnv } from "./index";

// Detection routes (Milestone 1): rule registry list/detail/toggle plus the
// engine heartbeat from Milestone 0.4.
export function registerDetectionsRoutes(app: Hono<{ Bindings: AdminEnv }>): void {
  app.get("/api/v1/detections/health", async (c) => {
    const health = await getDetectionHealth(c.env.ALERT_STATE_DB);
    return c.json({ detection_health: health });
  });

  // Scheduled SQL detections (Milestone 3) joined with their run state. Registered
  // before `/:id` so "scheduled" isn't captured as a rule id.
  app.get("/api/v1/detections/scheduled", async (c) => {
    const scheduled = await listScheduledDetections(c.env.ALERT_STATE_DB, new Date());
    return c.json({ scheduled });
  });

  // Stateless dry-run against a supplied normalized OCSF event. This does not
  // persist alerts or touch runtime counters; historical lake backtesting remains
  // a separate SQL/query-runner workflow.
  app.post("/api/v1/detections/test", async (c) => {
    const body = await readTestBody(c.req.raw.clone());
    if (!body || typeof body.rule_id !== "string" || !isRecord(body.event)) {
      return c.json({ error: "Request body must include `rule_id` and normalized OCSF `event`." }, 400);
    }

    const rule = await getDetectionRule(c.env.ALERT_STATE_DB, body.rule_id);
    if (!rule) return c.json({ error: `Detection rule not found: ${body.rule_id}` }, 404);
    if (rule.execution !== "sigma") {
      return c.json({ error: `Only stateless sigma rules can be dry-run via this endpoint. Rule ${rule.id} uses ${rule.execution}.` }, 400);
    }
    if (!isSigmaRule(rule.definition)) {
      return c.json({ error: `Detection rule ${rule.id} does not have a runnable Sigma definition.` }, 400);
    }

    const matches = evaluateSigmaRules(body.event as unknown as OcsfEvent, [{ ...rule.definition, enabled: true }]);
    return c.json({ matched: matches.length > 0, matches });
  });

  app.get("/api/v1/detections", async (c) => {
    const url = new URL(c.req.url);
    const enabledParam = url.searchParams.get("enabled");
    const source = url.searchParams.get("source") ?? undefined;

    if (enabledParam !== null && enabledParam !== "true" && enabledParam !== "false") {
      return c.json({ error: "Invalid enabled filter. Must be true or false." }, 400);
    }

    const rules = await listDetectionRules(c.env.ALERT_STATE_DB, {
      enabled: enabledParam === null ? undefined : enabledParam === "true",
      source
    });
    return c.json({ rules });
  });

  app.get("/api/v1/detections/:id", async (c) => {
    const rule = await getDetectionRule(c.env.ALERT_STATE_DB, c.req.param("id"));
    if (!rule) return c.json({ error: `Detection rule not found: ${c.req.param("id")}` }, 404);
    return c.json({ rule });
  });

  app.patch("/api/v1/detections/:id", async (c) => {
    const body = await readJsonBody(c.req.raw.clone());
    if (typeof body.enabled !== "boolean") {
      return c.json({ error: "Request body must include a boolean `enabled`." }, 400);
    }
    try {
      const rule = await setDetectionRuleEnabled(c.env.ALERT_STATE_DB, c.req.param("id"), body.enabled);
      return c.json({ rule });
    } catch (error) {
      if (error instanceof DetectionRuleNotFoundError) return c.json({ error: error.message }, 404);
      throw error;
    }
  });
}

async function readJsonBody(request: Request): Promise<{ enabled?: unknown }> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) return {};
  try {
    const parsed = (await request.json()) as unknown;
    if (parsed && typeof parsed === "object") return parsed as { enabled?: unknown };
    return {};
  } catch {
    return {};
  }
}

async function readTestBody(request: Request): Promise<{ rule_id?: unknown; event?: unknown } | null> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) return null;
  try {
    const parsed = (await request.json()) as unknown;
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function isSigmaRule(value: unknown): value is SigmaRule {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    typeof value.title === "string" &&
    typeof value.severity === "string" &&
    typeof value.enabled === "boolean" &&
    value.execution === "sigma" &&
    isRecord(value.logsource) &&
    isRecord(value.detection)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
