import { describe, expect, it } from "vitest";

import { FakeAlertDb } from "./alerts-fake-db.js";
import {
  DetectionRuleNotFoundError,
  getDetectionRule,
  getDisabledRuleIds,
  listDetectionRules,
  recordRuleTriggers,
  seedDetectionRules,
  setDetectionRuleEnabled,
  type DetectionRuleSeed
} from "./detection-rules.js";

function seed(overrides: Partial<DetectionRuleSeed> & { id: string }): DetectionRuleSeed {
  return {
    title: `Rule ${overrides.id}`,
    description: "a rule",
    severity: "high",
    source: "aws_cloudtrail",
    class_name: "authentication",
    execution: "sigma",
    tags: ["aws"],
    enabled: true,
    definition: { id: overrides.id, detection: {} },
    ...overrides
  };
}

describe("seedDetectionRules", () => {
  it("inserts rules with hydrated tags, enabled, and definition", async () => {
    const db = new FakeAlertDb();
    await seedDetectionRules(db, [seed({ id: "r1", tags: ["a", "b"] })]);

    const rule = await getDetectionRule(db, "r1");
    expect(rule?.id).toBe("r1");
    expect(rule?.tags).toEqual(["a", "b"]);
    expect(rule?.enabled).toBe(true);
    expect(rule?.match_count).toBe(0);
    expect(rule?.definition).toMatchObject({ id: "r1" });
  });

  it("is idempotent and preserves operator enabled-override + stats on reseed", async () => {
    const db = new FakeAlertDb();
    await seedDetectionRules(db, [seed({ id: "r1", title: "Old title" })]);
    await setDetectionRuleEnabled(db, "r1", false);
    await recordRuleTriggers(db, ["r1"]);

    // Redeploy reseeds the same id with refreshed static metadata.
    await seedDetectionRules(db, [seed({ id: "r1", title: "New title", severity: "critical" })]);

    const rule = await getDetectionRule(db, "r1");
    expect(rule?.title).toBe("New title"); // static metadata refreshed
    expect(rule?.severity).toBe("critical");
    expect(rule?.enabled).toBe(false); // operator override preserved
    expect(rule?.match_count).toBe(1); // stats preserved
  });
});

describe("listDetectionRules", () => {
  it("lists all rules sorted by id and filters by enabled/source", async () => {
    const db = new FakeAlertDb();
    await seedDetectionRules(db, [
      seed({ id: "b-rule", source: "kubernetes_audit" }),
      seed({ id: "a-rule", source: "aws_cloudtrail" })
    ]);
    await setDetectionRuleEnabled(db, "a-rule", false);

    const all = await listDetectionRules(db);
    expect(all.map((rule) => rule.id)).toEqual(["a-rule", "b-rule"]);

    const enabled = await listDetectionRules(db, { enabled: true });
    expect(enabled.map((rule) => rule.id)).toEqual(["b-rule"]);

    const k8s = await listDetectionRules(db, { source: "kubernetes_audit" });
    expect(k8s.map((rule) => rule.id)).toEqual(["b-rule"]);
  });
});

describe("setDetectionRuleEnabled", () => {
  it("toggles enabled and returns the updated rule", async () => {
    const db = new FakeAlertDb();
    await seedDetectionRules(db, [seed({ id: "r1" })]);

    const disabled = await setDetectionRuleEnabled(db, "r1", false);
    expect(disabled.enabled).toBe(false);
    const reEnabled = await setDetectionRuleEnabled(db, "r1", true);
    expect(reEnabled.enabled).toBe(true);
  });

  it("throws DetectionRuleNotFoundError for an unknown id", async () => {
    const db = new FakeAlertDb();
    await expect(setDetectionRuleEnabled(db, "missing", false)).rejects.toBeInstanceOf(DetectionRuleNotFoundError);
  });
});

describe("recordRuleTriggers / getDisabledRuleIds", () => {
  it("increments match_count and sets last_triggered_at", async () => {
    const db = new FakeAlertDb();
    await seedDetectionRules(db, [seed({ id: "r1" })]);
    await recordRuleTriggers(db, ["r1", "r1"]);

    const rule = await getDetectionRule(db, "r1");
    expect(rule?.match_count).toBe(2);
    expect(rule?.last_triggered_at).toBeTruthy();
  });

  it("returns the ids of disabled rules", async () => {
    const db = new FakeAlertDb();
    await seedDetectionRules(db, [seed({ id: "r1" }), seed({ id: "r2" })]);
    await setDetectionRuleEnabled(db, "r2", false);

    expect(await getDisabledRuleIds(db)).toEqual(["r2"]);
  });

  it("is a no-op for an empty trigger list", async () => {
    const db = new FakeAlertDb();
    await seedDetectionRules(db, [seed({ id: "r1" })]);
    await recordRuleTriggers(db, []);
    expect((await getDetectionRule(db, "r1"))?.match_count).toBe(0);
  });
});
