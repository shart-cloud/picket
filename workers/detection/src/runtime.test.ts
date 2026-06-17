import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import type { OcsfEvent } from "@picket/core";
import type { SigmaRule } from "@picket/sigma-engine";

const rule: SigmaRule = {
  id: "runtime-threshold",
  title: "Runtime threshold",
  description: "Exercises threshold persistence in the Workers runtime.",
  severity: "medium",
  tags: ["test.runtime"],
  enabled: true,
  execution: "stateful",
  logsource: { source: "okta_auth", class_name: "authentication" },
  detection: { selection: { status: "failure" }, condition: "selection" },
  dedupe_key: "src_endpoint.ip",
  dedupe_prefix: "runtime-threshold",
  stateful: {
    type: "threshold",
    field: "src_endpoint.ip",
    threshold: 3,
    window: "5m",
    suppress_for: "30m"
  }
};

describe("StatefulDetectionObject runtime", () => {
  it("persists threshold state and suppresses a repeated alert", async () => {
    if (!env.STATEFUL_DETECTION) throw new Error("STATEFUL_DETECTION binding is required");
    const stub = env.STATEFUL_DETECTION.getByName("runtime-threshold:198.51.100.23");

    await expect(stub.evaluate(rule, eventAt(0))).resolves.toBeUndefined();
    await expect(stub.evaluate(rule, eventAt(1))).resolves.toBeUndefined();
    await expect(stub.evaluate(rule, eventAt(2))).resolves.toEqual(
      expect.objectContaining({
        rule_id: "runtime-threshold",
        dedupe_key: "runtime-threshold:198.51.100.23"
      })
    );
    await expect(stub.evaluate(rule, eventAt(3))).resolves.toBeUndefined();
  });
});

function eventAt(minuteOffset: number): OcsfEvent {
  return {
    time: new Date(Date.parse("2026-06-12T12:00:00.000Z") + minuteOffset * 60_000).toISOString(),
    source: "okta_auth",
    category: "identity_access",
    class_name: "authentication",
    activity_name: "User login",
    status: "failure",
    src_endpoint: { ip: "198.51.100.23" },
    metadata: { product_name: "runtime-test", raw_event: { minuteOffset } }
  };
}
