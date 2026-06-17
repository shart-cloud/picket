import { describe, expect, it } from "vitest";

import type { Alert, OcsfEvent } from "./index.js";
import { flattenAlert, flattenOcsfEvent } from "./flatten.js";

const fullEvent: OcsfEvent = {
  time: "2026-05-27T12:00:00Z",
  source: "aws_cloudtrail",
  category: "identity_access",
  class_name: "authentication",
  activity_name: "ConsoleLogin",
  status: "success",
  message: "ok",
  actor: {
    user: { uid: "AIDA123", name: "root", email: "root@example.com", type: "Root" },
    session: { uid: "sess-1" }
  },
  user: { uid: "u1", name: "n1", email: "e@x", type: "IAMUser" },
  src_endpoint: { ip: "1.2.3.4", name: "host", uid: "e1", country: "US", region: "CA", city: "SF" },
  dst_endpoint: { ip: "5.6.7.8" },
  api: { operation: "ConsoleLogin", service: { name: "signin.amazonaws.com" } },
  cloud: { provider: "aws", region: "us-east-1", account: { uid: "111", name: "prod" } },
  http_request: { user_agent: "ua", url: "https://x", http_method: "POST" },
  metadata: { product_name: "AWS CloudTrail", original_uid: "evt-1", raw_event: { foo: "bar" } }
};

describe("flattenOcsfEvent", () => {
  it("flattens nested fields with dotted snake_case keys", () => {
    const r = flattenOcsfEvent(fullEvent);
    expect(r["actor_user_uid"]).toBe("AIDA123");
    expect(r["actor_user_email"]).toBe("root@example.com");
    expect(r["actor_session_uid"]).toBe("sess-1");
    expect(r["src_endpoint_ip"]).toBe("1.2.3.4");
    expect(r["src_endpoint_city"]).toBe("SF");
    expect(r["dst_endpoint_ip"]).toBe("5.6.7.8");
    expect(r["api_operation"]).toBe("ConsoleLogin");
    expect(r["api_service_name"]).toBe("signin.amazonaws.com");
    expect(r["cloud_account_uid"]).toBe("111");
    expect(r["http_request_user_agent"]).toBe("ua");
    expect(r["metadata_product_name"]).toBe("AWS CloudTrail");
    expect(r["metadata_raw_event"]).toBe(JSON.stringify({ foo: "bar" }));
    expect(r["time"]).toBe("2026-05-27T12:00:00Z");
  });

  it("omits undefined keys instead of writing null", () => {
    const minimal: OcsfEvent = {
      time: "2026-05-27T12:00:00Z",
      source: "aws_cloudtrail",
      category: "identity_access",
      class_name: "authentication",
      activity_name: "ConsoleLogin",
      status: "success",
      metadata: { product_name: "AWS CloudTrail", raw_event: null }
    };
    const r = flattenOcsfEvent(minimal);
    expect("actor_user_uid" in r).toBe(false);
    expect("src_endpoint_ip" in r).toBe(false);
    expect("message" in r).toBe(false);
    expect("metadata_original_uid" in r).toBe(false);
    expect(r["metadata_raw_event"]).toBe("null");
  });

  it("flattens a stamped threat_match", () => {
    const r = flattenOcsfEvent({
      ...fullEvent,
      threat_match: {
        indicator: "1.2.3.4",
        indicator_type: "ipv4",
        matched_field: "src_endpoint_ip",
        feed_name: "abuse.ch",
        threat_type: "c2"
      }
    });
    expect(r["threat_match_indicator"]).toBe("1.2.3.4");
    expect(r["threat_match_indicator_type"]).toBe("ipv4");
    expect(r["threat_match_field"]).toBe("src_endpoint_ip");
    expect(r["threat_match_feed_name"]).toBe("abuse.ch");
    expect(r["threat_match_threat_type"]).toBe("c2");
  });

  it("omits threat_match columns when unstamped", () => {
    const r = flattenOcsfEvent(fullEvent);
    expect("threat_match_indicator" in r).toBe(false);
  });

  it("does not mutate the source event", () => {
    const copy = structuredClone(fullEvent);
    flattenOcsfEvent(fullEvent);
    expect(fullEvent).toEqual(copy);
  });
});

describe("flattenAlert", () => {
  it("flattens alert primitives and nested event under event_ prefix", () => {
    const alert: Alert = {
      id: "a1",
      rule_id: "r1",
      title: "Root login",
      severity: "high",
      source: "aws_cloudtrail",
      status: "open",
      dedupe_key: "root:1.2.3.4",
      match_count: 1,
      first_seen: "2026-05-27T12:00:00Z",
      last_seen: "2026-05-27T12:00:00Z",
      event: fullEvent
    };
    const r = flattenAlert(alert);
    expect(r["id"]).toBe("a1");
    expect(r["rule_id"]).toBe("r1");
    expect(r["match_count"]).toBe(1);
    expect(r["event_actor_user_uid"]).toBe("AIDA123");
    expect(r["event_src_endpoint_ip"]).toBe("1.2.3.4");
    expect(r["event_metadata_raw_event"]).toBe(JSON.stringify({ foo: "bar" }));
    expect("event" in r).toBe(false);
  });
});
