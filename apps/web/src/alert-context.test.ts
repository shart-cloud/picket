import { describe, expect, it } from "vitest";
import type { OcsfEvent } from "@picket/core";
import { buildAlertContextQuery } from "./alert-context";

describe("buildAlertContextQuery", () => {
  it("builds a bounded query around user and source IP pivots", () => {
    const event = {
      activity_name: "ConsoleLogin",
      status: "failure",
      actor: { user: { email: "root@example.com", uid: "root" } },
      src_endpoint: { ip: "203.0.113.44" }
    } as OcsfEvent;

    const query = buildAlertContextQuery({
      source: "aws_cloudtrail",
      lastSeen: "2026-06-24T12:00:00.000Z",
      event,
      windowMinutes: 30
    });

    expect(query?.startTime).toBe("2026-06-24T11:30:00.000Z");
    expect(query?.endTime).toBe("2026-06-24T12:30:00.000Z");
    expect(query?.pivots).toContain("source IP 203.0.113.44");
    expect(query?.sql).toContain("FROM aws_cloudtrail");
    expect(query?.sql).toContain("src_endpoint_ip = '203.0.113.44'");
    expect(query?.sql).toContain("actor_user_email = 'root@example.com'");
  });

  it("rejects unsafe table names", () => {
    const event = { activity_name: "x", status: "success", src_endpoint: { ip: "1.2.3.4" } } as OcsfEvent;
    expect(buildAlertContextQuery({ source: "aws;drop", lastSeen: "2026-06-24T12:00:00.000Z", event, windowMinutes: 30 })).toBeNull();
  });
});
