import { describe, expect, it } from "vitest";

import type { OcsfEvent } from "./index.js";
import { assertOcsfEvent, OcsfValidationError, validateOcsfEvent } from "./ocsf-schema.js";

function baseEvent(overrides: Partial<OcsfEvent> = {}): OcsfEvent {
  return {
    time: "2026-05-26T12:00:00.000Z",
    source: "aws_cloudtrail",
    category: "identity_access",
    class_name: "authentication",
    activity_name: "ConsoleLogin",
    status: "success",
    actor: { user: { uid: "AIDAEXAMPLE", name: "alice" } },
    metadata: { product_name: "AWS CloudTrail", raw_event: {} },
    ...overrides
  };
}

describe("validateOcsfEvent", () => {
  it("accepts a well-formed authentication event", () => {
    expect(validateOcsfEvent(baseEvent())).toEqual([]);
  });

  it("accepts a well-formed api_activity event", () => {
    const event = baseEvent({
      class_name: "api_activity",
      activity_name: "list",
      actor: undefined,
      api: { operation: "list", service: { name: "kubernetes" } }
    });
    expect(validateOcsfEvent(event)).toEqual([]);
  });

  it("rejects unknown enum values", () => {
    const event = baseEvent({
      source: "made_up_source" as OcsfEvent["source"],
      category: "nope" as OcsfEvent["category"],
      class_name: "bogus" as OcsfEvent["class_name"],
      status: "maybe" as OcsfEvent["status"]
    });
    const issues = validateOcsfEvent(event);
    expect(issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining("source"),
        expect.stringContaining("category"),
        expect.stringContaining("class"),
        expect.stringContaining("status")
      ])
    );
  });

  it("rejects a class that does not belong to its category", () => {
    const event = baseEvent({ category: "network_activity" });
    expect(validateOcsfEvent(event)).toEqual([
      expect.stringContaining('class_name "authentication" is not valid for category "network_activity"')
    ]);

    const strict = baseEvent({ category: "identity_access", class_name: "authentication" });
    expect(validateOcsfEvent(strict)).toEqual([]);
  });

  it("accepts a well-formed network activity event", () => {
    const event = baseEvent({
      category: "network_activity",
      class_name: "network_activity",
      source: "aws_vpc_flow",
      actor: undefined,
      src_endpoint: { ip: "10.0.1.10" },
      dst_endpoint: { ip: "198.51.100.42" }
    });
    expect(validateOcsfEvent(event)).toEqual([]);
  });

  it("requires actor.user identity for authentication events", () => {
    const event = baseEvent({ actor: { user: {} } });
    expect(validateOcsfEvent(event)).toEqual([
      expect.stringContaining("authentication events require actor.user")
    ]);
  });

  it("requires actor.user identity for account_change events", () => {
    const event = baseEvent({ class_name: "account_change", activity_name: "AttachUserPolicy", actor: undefined });
    expect(validateOcsfEvent(event)).toEqual([
      expect.stringContaining("account_change events require actor.user")
    ]);
  });

  it("requires api.operation and api.service.name for api_activity events", () => {
    const event = baseEvent({ class_name: "api_activity", actor: undefined, api: {} });
    const issues = validateOcsfEvent(event);
    expect(issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining("api.operation"),
        expect.stringContaining("api.service.name")
      ])
    );
  });

  it("rejects a non-ISO time", () => {
    expect(validateOcsfEvent(baseEvent({ time: "not-a-date" }))).toEqual([
      expect.stringContaining("time must be an ISO-8601")
    ]);
  });

  it("requires metadata.product_name and raw_event", () => {
    const event = baseEvent({ metadata: { product_name: "", raw_event: undefined } as OcsfEvent["metadata"] });
    delete (event.metadata as Record<string, unknown>).raw_event;
    const issues = validateOcsfEvent(event);
    expect(issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining("metadata.product_name"),
        expect.stringContaining("metadata.raw_event")
      ])
    );
  });

  it("flags leaf fields with the wrong type", () => {
    const event = baseEvent({ src_endpoint: { ip: 12345 as unknown as string } });
    expect(validateOcsfEvent(event)).toEqual([expect.stringContaining("src_endpoint.ip must be a string")]);
  });

  it("collects multiple issues at once", () => {
    const event = baseEvent({ activity_name: "", status: "weird" as OcsfEvent["status"], actor: { user: {} } });
    expect(validateOcsfEvent(event).length).toBeGreaterThanOrEqual(3);
  });
});

describe("assertOcsfEvent", () => {
  it("returns the event when valid", () => {
    const event = baseEvent();
    expect(assertOcsfEvent(event)).toBe(event);
  });

  it("throws OcsfValidationError listing the issues when invalid", () => {
    try {
      assertOcsfEvent(baseEvent({ source: "x" as OcsfEvent["source"], activity_name: "" }));
      throw new Error("expected assertOcsfEvent to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(OcsfValidationError);
      expect((error as OcsfValidationError).issues.length).toBeGreaterThanOrEqual(2);
    }
  });
});
