import { describe, expect, it } from "vitest";

import { parseAlertEvent, summarizeAlertEvent } from "./alert-utils";

describe("alert event summary", () => {
  it("extracts analyst-facing identity, endpoint, and IOC context", () => {
    const event = parseAlertEvent(
      JSON.stringify({
        time: "2026-06-12T12:00:00.000Z",
        source: "aws_cloudtrail",
        category: "identity_access",
        class_name: "api_activity",
        activity_name: "AttachUserPolicy",
        status: "success",
        actor: { user: { email: "alice@example.com" } },
        src_endpoint: { ip: "198.51.100.10" },
        threat_match: {
          indicator: "198.51.100.10",
          indicator_type: "ipv4",
          matched_field: "src_endpoint_ip",
          feed_name: "known-c2"
        },
        metadata: { product_name: "AWS CloudTrail", raw_event: {} }
      })
    );

    expect(event).not.toBeNull();
    expect(summarizeAlertEvent(event!)).toMatchObject({
      activity: "AttachUserPolicy",
      outcome: "success",
      user: "alice@example.com",
      sourceIp: "198.51.100.10",
      threat: { indicator: "198.51.100.10", feed: "known-c2" }
    });
  });
});
