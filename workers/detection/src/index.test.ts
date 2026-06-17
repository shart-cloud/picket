import { describe, expect, it, vi } from "vitest";
import { env } from "cloudflare:test";

import type { Alert } from "@picket/core";
import cloudTrailFixture from "../../../fixtures/cloudtrail/root-console-login.json";
import iamPolicyAttachedFixture from "../../../fixtures/cloudtrail/iam-policy-attached-to-user.json";
import iamUserWithoutMfaFixture from "../../../fixtures/cloudtrail/iam-user-console-login-without-mfa.json";
import oktaFailedLoginFixture from "../../../fixtures/okta/failed-login.json";
import k8sAnonymousFixture from "../../../fixtures/k8s-audit/eks-anonymous-success.json";
import { normalizeCloudTrail, normalizeK8sAudit, normalizeOkta } from "@picket/normalize";
import type { SigmaRule, ThresholdStatefulConfig } from "@picket/sigma-engine";
import { SIGMA_RULES, STATEFUL_RULES } from "./generated-rules";
import worker, { _resetDetectionRegistryCaches, enqueueAlerts, evaluateEvent, evaluateEventWithStateful, persistAlerts, writeAlertsToPipeline } from "./index";

describe("evaluateEvent", () => {
  it("creates an alert for AWS root console login", () => {
    const event = normalizeCloudTrail(cloudTrailFixture);
    const alerts = evaluateEvent(event);

    expect(alerts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          rule_id: "aws-root-account-usage",
          title: "AWS root account console login",
          severity: "high",
          dedupe_key: "aws-root:123456789012"
        })
      ])
    );
  });

  it("creates an alert for console login without MFA", () => {
    const event = normalizeCloudTrail(iamUserWithoutMfaFixture);
    const alerts = evaluateEvent(event);

    expect(alerts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          rule_id: "aws-console-login-without-mfa",
          title: "AWS console login without MFA",
          severity: "medium",
          dedupe_key: "aws-console-no-mfa:AIDAEXAMPLE"
        })
      ])
    );
  });

  it("does not alert for console login with MFA", () => {
    const event = normalizeCloudTrail({
      ...iamUserWithoutMfaFixture,
      additionalEventData: {
        MFAUsed: "Yes"
      }
    });

    expect(evaluateEvent(event)).toEqual([]);
  });

  it("creates an alert when an IAM policy is attached to a user", () => {
    const event = normalizeCloudTrail(iamPolicyAttachedFixture);
    const alerts = evaluateEvent(event);

    expect(alerts).toEqual([
      expect.objectContaining({
        rule_id: "aws-iam-policy-attached-to-user",
        title: "IAM policy attached to user",
        severity: "high",
        dedupe_key: "aws-iam-user-policy:alice"
      })
    ]);
  });

  it("does not alert for unrelated IAM API events", () => {
    const event = normalizeCloudTrail({
      ...iamPolicyAttachedFixture,
      eventName: "GetUser"
    });

    expect(evaluateEvent(event)).toEqual([]);
  });

  it("creates an alert for anonymous Kubernetes API success", () => {
    const event = normalizeK8sAudit(k8sAnonymousFixture, { flavor: "eks" });
    const alerts = evaluateEvent(event);

    expect(alerts).toEqual([
      expect.objectContaining({
        rule_id: "k8s-anonymous-api-request-succeeded",
        title: "Kubernetes anonymous API request succeeded",
        severity: "high",
        dedupe_key: "k8s-anonymous-api:203.0.113.42"
      })
    ]);
  });
});

describe("Detection Worker", () => {
  it("accepts normalized events over HTTP", async () => {
    const event = normalizeCloudTrail(cloudTrailFixture);
    const response = await worker.fetch(
      new Request("https://detection.local/events", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(event)
      }),
      {}
    );

    expect(response.status).toBe(202);
    await expect(response.json()).resolves.toMatchObject({
      accepted: true,
      alert_count: 2,
      alerts: [
        expect.objectContaining({
          rule_id: "aws-root-account-usage",
          source: "aws_cloudtrail",
          status: "open"
        }),
        expect.objectContaining({
          rule_id: "aws-console-login-without-mfa",
          source: "aws_cloudtrail",
          status: "open"
        })
      ]
    });
  });

  it("returns health status", async () => {
    const response = await worker.fetch(new Request("https://detection.local/health"), {});

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ ok: true, worker: "picket-detection" });
  });

  it("records a detection heartbeat when ALERT_STATE_DB is bound", async () => {
    _resetDetectionRegistryCaches();
    const db = new FakeD1Database();
    const event = normalizeCloudTrail(cloudTrailFixture);
    const response = await worker.fetch(
      new Request("https://detection.local/events", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(event)
      }),
      { ALERT_STATE_DB: db.database }
    );

    expect(response.status).toBe(202);
    expect(db.detectionHealth?.total_events_evaluated).toBe(1);
    expect(db.detectionHealth?.total_alerts_created).toBe(2);
    expect(db.detectionHealth?.stateless_rule_count).toBe(SIGMA_RULES.length);
    expect(db.detectionHealth?.stateful_rule_count).toBe(STATEFUL_RULES.length);
    expect(db.detectionHealth?.last_eval_at).toBeTruthy();
  });

  it("skips a rule an operator disabled in the registry", async () => {
    _resetDetectionRegistryCaches();
    const db = new FakeD1Database();
    db.detectionRules.push({ id: "aws-root-account-usage", enabled: 0, match_count: 0, last_triggered_at: null });
    const event = normalizeCloudTrail(cloudTrailFixture);

    const response = await worker.fetch(
      new Request("https://detection.local/events", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(event)
      }),
      { ALERT_STATE_DB: db.database }
    );

    expect(response.status).toBe(202);
    const body = (await response.json()) as { alerts: { rule_id: string }[] };
    const ruleIds = body.alerts.map((alert) => alert.rule_id);
    expect(ruleIds).not.toContain("aws-root-account-usage");
    expect(ruleIds).toContain("aws-console-login-without-mfa");
  });

  it("records per-rule match stats when rules fire", async () => {
    _resetDetectionRegistryCaches();
    const db = new FakeD1Database();
    const event = normalizeCloudTrail(cloudTrailFixture);

    await worker.fetch(
      new Request("https://detection.local/events", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(event)
      }),
      { ALERT_STATE_DB: db.database }
    );

    const root = db.detectionRules.find((rule) => rule.id === "aws-root-account-usage");
    expect(root?.match_count).toBe(1);
    expect(root?.last_triggered_at).toBeTruthy();
  });
});

describe("stateful threshold detection", () => {
  it("alerts on the 10th failed Kubernetes API auth response inside 5 minutes", async () => {
    const events = k8sFailedAuthEvents([0, 10, 20, 30, 40, 50, 60, 70, 80, 90]);

    for (const event of events.slice(0, 9)) {
      await expect(evaluateEventWithStateful(event, env)).resolves.toEqual([]);
    }

    await expect(evaluateEventWithStateful(events[9]!, env)).resolves.toEqual([
      expect.objectContaining({
        rule_id: "k8s-excessive-failed-auth",
        title: "Excessive failed Kubernetes API authentication",
        severity: "medium",
        dedupe_key: "k8s-failed-auth:198.51.100.44"
      })
    ]);
  });

  it("fires a threshold alert once the count is reached inside the window", async () => {
    const rule = thresholdRule();
    const object = statefulObject("threshold-reached");
    const events = oktaEvents([0, 1, 2, 3, 4]);

    for (const event of events.slice(0, 4)) {
      await expect(object.evaluate(rule, event)).resolves.toBeUndefined();
    }

    await expect(object.evaluate(rule, events[4]!)).resolves.toEqual(
      expect.objectContaining({
        rule_id: "okta-brute-force",
        title: "Okta brute force authentication failures",
        severity: "medium",
        dedupe_key: "okta-brute-force:198.51.100.23"
      })
    );
  });

  it("does not alert when failures are spread outside the threshold window", async () => {
    const rule = thresholdRule();
    const object = statefulObject("outside-window");
    const events = oktaEvents([0, 16, 32, 48, 64]);

    for (const event of events) {
      await expect(object.evaluate(rule, event)).resolves.toBeUndefined();
    }
  });

  it("suppresses repeated threshold alerts while suppress_for is active", async () => {
    const rule = thresholdRule({ suppress_for: "30m" });
    const object = statefulObject("suppression");
    const events = oktaEvents([0, 1, 2, 3, 4, 5]);

    for (const event of events.slice(0, 4)) {
      await expect(object.evaluate(rule, event)).resolves.toBeUndefined();
    }

    await expect(object.evaluate(rule, events[4]!)).resolves.toEqual(
      expect.objectContaining({ rule_id: "okta-brute-force", dedupe_key: "okta-brute-force:198.51.100.23" })
    );
    await expect(object.evaluate(rule, events[5]!)).resolves.toBeUndefined();
  });
});

describe("enqueueAlerts", () => {
  it("sends alerts to the configured queue", async () => {
    const event = normalizeCloudTrail(cloudTrailFixture);
    const alerts = evaluateEvent(event);
    const send = vi.fn<Queue<unknown>["send"]>().mockResolvedValue({} as QueueSendResponse);

    await enqueueAlerts(alerts, { ALERT_QUEUE: { send } as unknown as Queue<Alert> });

    expect(send).toHaveBeenCalledTimes(2);
    expect(send).toHaveBeenCalledWith(expect.objectContaining({ rule_id: "aws-root-account-usage" }));
  });
});

describe("writeAlertsToPipeline", () => {
  it("sends alert records to the configured alerts pipeline", async () => {
    const event = normalizeCloudTrail(cloudTrailFixture);
    const alerts = evaluateEvent(event);
    const send = vi.fn<(records: Record<string, unknown>[]) => Promise<void>>().mockResolvedValue(undefined);

    await writeAlertsToPipeline(alerts, { ALERTS_PIPELINE: { send } });

    expect(send).toHaveBeenCalledWith(alerts.map((alert) => expect.objectContaining({ id: alert.id, rule_id: alert.rule_id })));
  });
});

describe("persistAlerts", () => {
  it("treats alerts as new when D1 is not configured", async () => {
    const [alert] = evaluateEvent(normalizeCloudTrail(iamPolicyAttachedFixture));
    if (!alert) throw new Error("Expected IAM alert");

    await expect(persistAlerts([alert], {})).resolves.toEqual([{ alert, isNew: true }]);
  });

  it("inserts new alert state and timeline rows", async () => {
    const db = new FakeD1Database();
    const [alert] = evaluateEvent(normalizeCloudTrail(iamPolicyAttachedFixture));
    if (!alert) throw new Error("Expected IAM alert");

    await expect(persistAlerts([alert], { ALERT_STATE_DB: db.database })).resolves.toEqual([{ alert, isNew: true }]);

    expect(db.alerts).toEqual([
      expect.objectContaining({
        id: alert.id,
        rule_id: "aws-iam-policy-attached-to-user",
        dedupe_key: "aws-iam-user-policy:alice",
        match_count: 1,
        status: "open"
      })
    ]);
    expect(db.timeline).toEqual([expect.objectContaining({ alert_id: alert.id, action: "created" })]);
  });

  it("deduplicates alerts inside the 15 minute window", async () => {
    const db = new FakeD1Database();
    const event = normalizeCloudTrail(iamPolicyAttachedFixture);
    const [firstAlert] = evaluateEvent(event);
    const [secondAlert] = evaluateEvent({ ...event, time: new Date(Date.parse(event.time) + 60_000).toISOString() });
    if (!firstAlert || !secondAlert) throw new Error("Expected IAM alerts");

    await expect(persistAlerts([firstAlert], { ALERT_STATE_DB: db.database })).resolves.toEqual([{ alert: firstAlert, isNew: true }]);
    const [deduped] = await persistAlerts([secondAlert], { ALERT_STATE_DB: db.database });

    expect(deduped).toEqual({
      alert: expect.objectContaining({
        id: firstAlert.id,
        rule_id: firstAlert.rule_id,
        match_count: 2,
        first_seen: firstAlert.first_seen,
        last_seen: secondAlert.last_seen
      }),
      isNew: false
    });
    expect(db.alerts).toHaveLength(1);
    expect(db.alerts[0]).toEqual(expect.objectContaining({ id: firstAlert.id, match_count: 2, last_seen: secondAlert.last_seen }));
    expect(db.timeline.map((entry) => entry.action)).toEqual(["created", "matched"]);
  });

  it("creates a new alert outside the 15 minute dedupe window", async () => {
    const db = new FakeD1Database();
    const event = normalizeCloudTrail(iamPolicyAttachedFixture);
    const [firstAlert] = evaluateEvent(event);
    const [secondAlert] = evaluateEvent({ ...event, time: new Date(Date.parse(event.time) + 16 * 60_000).toISOString() });
    if (!firstAlert || !secondAlert) throw new Error("Expected IAM alerts");

    await persistAlerts([firstAlert], { ALERT_STATE_DB: db.database });
    await expect(persistAlerts([secondAlert], { ALERT_STATE_DB: db.database })).resolves.toEqual([{ alert: secondAlert, isNew: true }]);

    expect(db.alerts.map((alert) => alert.id)).toEqual([firstAlert.id, secondAlert.id]);
    expect(db.timeline.map((entry) => entry.action)).toEqual(["created", "created"]);
  });
});

function oktaEvents(minuteOffsets: number[]) {
  const base = Date.parse("2026-05-26T12:00:00.000Z");
  return minuteOffsets.map((offset) =>
    normalizeOkta({
      ...oktaFailedLoginFixture,
      uuid: `22222222-2222-4222-8222-2222222222${String(offset).padStart(2, "0")}`,
      published: new Date(base + offset * 60_000).toISOString()
    })
  );
}

function k8sFailedAuthEvents(secondOffsets: number[]) {
  const base = Date.parse("2026-05-26T12:00:00.000Z");
  return secondOffsets.map((offset) =>
    normalizeK8sAudit(
      {
        ...k8sAnonymousFixture,
        auditID: `b2c3d4e5-0000-4000-8000-0000000001${String(offset).padStart(2, "0")}`,
        sourceIPs: ["198.51.100.44"],
        responseStatus: { code: 403 },
        requestReceivedTimestamp: new Date(base + offset * 1_000).toISOString(),
        stageTimestamp: new Date(base + offset * 1_000 + 45).toISOString()
      },
      { flavor: "eks" }
    )
  );
}

// Synthetic threshold rule used to exercise the generic StatefulDetectionObject
// machinery (counting, window expiry, suppression) independently of which rules
// the build happens to bundle. Mirrors the shape of a threshold Sigma rule.
function thresholdRule(overrides: Partial<Omit<ThresholdStatefulConfig, "type">> = {}): SigmaRule {
  return {
    id: "okta-brute-force",
    title: "Okta brute force authentication failures",
    description: "Synthetic threshold rule for stateful-detection unit tests.",
    severity: "medium",
    tags: [],
    enabled: true,
    execution: "stateful",
    logsource: { source: "okta_auth", class_name: "authentication" },
    detection: { selection: { status: "failure" }, condition: "selection" },
    dedupe_key: "src_endpoint.ip",
    dedupe_prefix: "okta-brute-force",
    stateful: { type: "threshold", field: "src_endpoint.ip", threshold: 5, window: "15m", ...overrides }
  };
}

function statefulObject(name: string) {
  if (!env.STATEFUL_DETECTION) throw new Error("STATEFUL_DETECTION binding is required");
  return env.STATEFUL_DETECTION.getByName(name);
}

interface FakeAlertRow {
  id: string;
  rule_id: string;
  title: string;
  severity: string;
  source: string;
  status: string;
  dedupe_key: string | null;
  match_count: number;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  event_json: string;
}

interface FakeTimelineRow {
  id: string;
  alert_id: string;
  action: string;
  metadata_json: string;
}

interface FakeDetectionHealth {
  last_eval_at: string;
  total_events_evaluated: number;
  total_alerts_created: number;
  stateless_rule_count: number;
  stateful_rule_count: number;
}

interface FakeRegistryRule {
  id: string;
  enabled: number;
  match_count: number;
  last_triggered_at: string | null;
}

class FakeD1Database {
  readonly alerts: FakeAlertRow[] = [];
  readonly timeline: FakeTimelineRow[] = [];
  readonly detectionRules: FakeRegistryRule[] = [];
  detectionHealth: FakeDetectionHealth | null = null;

  readonly database = {
    prepare: (query: string) => new FakeD1PreparedStatement(this, query)
  } as unknown as D1Database;
}

class FakeD1PreparedStatement {
  private params: unknown[] = [];

  constructor(
    private readonly db: FakeD1Database,
    private readonly query: string
  ) {}

  bind(...params: unknown[]) {
    this.params = params;
    return this;
  }

  async all<T = unknown>(): Promise<{ results: T[] }> {
    const normalized = this.query.trim().replace(/\s+/g, " ");
    if (normalized.startsWith("SELECT id FROM detection_rules WHERE enabled = 0")) {
      return { results: this.db.detectionRules.filter((rule) => rule.enabled === 0).map((rule) => ({ id: rule.id })) as unknown as T[] };
    }
    return { results: [] };
  }

  async first<T = unknown>(): Promise<T | null> {
    const normalized = this.query.trim().replace(/\s+/g, " ");
    if (normalized.startsWith("SELECT id, match_count, first_seen FROM alerts")) {
      const [ruleId, dedupeKey, cutoff] = this.params as [string, string, string];
      const row = this.db.alerts
        .filter(
          (alert) =>
            alert.rule_id === ruleId &&
            alert.dedupe_key === dedupeKey &&
            (alert.status === "open" || alert.status === "acknowledged") &&
            alert.last_seen >= cutoff
        )
        .sort((left, right) => right.last_seen.localeCompare(left.last_seen))[0];
      return row ? ({ id: row.id, match_count: row.match_count, first_seen: row.first_seen } as T) : null;
    }

    return null;
  }

  async run(): Promise<D1Result> {
    const normalized = this.query.trim().replace(/\s+/g, " ");
    if (normalized.startsWith("INSERT INTO alerts")) {
      const [
        id,
        rule_id,
        title,
        severity,
        source,
        status,
        dedupe_key,
        match_count,
        first_seen,
        last_seen,
        created_at,
        updated_at,
        event_json
      ] = this.params as [string, string, string, string, string, string, string | null, number, string, string, string, string, string];
      this.db.alerts.push({ id, rule_id, title, severity, source, status, dedupe_key, match_count, first_seen, last_seen, created_at, updated_at, event_json });
    } else if (normalized.startsWith("UPDATE alerts SET")) {
      const [matchCount, lastSeen, updatedAt, eventJson, id] = this.params as [number, string, string, string, string];
      const row = this.db.alerts.find((alert) => alert.id === id);
      if (row) {
        row.match_count = matchCount;
        row.last_seen = lastSeen;
        row.updated_at = updatedAt;
        row.event_json = eventJson;
      }
    } else if (normalized.startsWith("INSERT INTO alert_timeline")) {
      const [id, alert_id, action, metadata_json] = this.params as [string, string, string, string];
      this.db.timeline.push({ id, alert_id, action, metadata_json });
    } else if (normalized.startsWith("INSERT INTO detection_health")) {
      const [lastEvalAt, events, alerts, statelessCount, statefulCount] = this.params as [string, number, number, number, number];
      const existing = this.db.detectionHealth;
      this.db.detectionHealth = {
        last_eval_at: lastEvalAt,
        total_events_evaluated: (existing?.total_events_evaluated ?? 0) + events,
        total_alerts_created: (existing?.total_alerts_created ?? 0) + alerts,
        stateless_rule_count: statelessCount,
        stateful_rule_count: statefulCount
      };
    } else if (normalized.startsWith("INSERT INTO detection_rules")) {
      // params[0] = id, params[8] = enabled
      const id = this.params[0] as string;
      const enabled = this.params[8] as number;
      const existing = this.db.detectionRules.find((rule) => rule.id === id);
      if (!existing) {
        this.db.detectionRules.push({ id, enabled, match_count: 0, last_triggered_at: null });
      }
      // ON CONFLICT preserves enabled + stats, so an existing row is left as-is.
    } else if (normalized.startsWith("UPDATE detection_rules SET match_count = match_count + 1")) {
      const [lastTriggeredAt, , id] = this.params as [string, string, string];
      const row = this.db.detectionRules.find((rule) => rule.id === id);
      if (row) {
        row.match_count += 1;
        row.last_triggered_at = lastTriggeredAt;
      }
    }

    return { success: true, meta: {} } as D1Result;
  }
}
