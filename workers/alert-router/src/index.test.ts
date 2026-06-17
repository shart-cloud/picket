import { afterEach, describe, expect, it, vi } from "vitest";

import type { Alert } from "@picket/core";
import { FakeAlertDb, type FakeAlertRow } from "@picket/core/alerts-fake-db";
import {
  parseRecipients,
  routeAlert,
  sendEmailAlert,
  toEmailMessage,
  toSlackMessage,
  type AlertRouterEnv
} from "./index";

interface FakeSendEmailCall {
  from: string;
  to: string;
  subject: string;
  text?: string;
  html?: string;
}

function fakeSendEmail(): {
  binding: SendEmail;
  calls: FakeSendEmailCall[];
  rejectOn: (recipient: string, reason: string) => void;
} {
  const calls: FakeSendEmailCall[] = [];
  const rejections = new Map<string, string>();
  const binding = {
    async send(payload: unknown): Promise<EmailSendResult> {
      const p = payload as {
        from: string | { email: string; name?: string };
        to: string | string[];
        subject: string;
        text?: string;
        html?: string;
      };
      const recipients = Array.isArray(p.to) ? p.to : [p.to];
      const from = typeof p.from === "string" ? p.from : p.from.email;
      for (const recipient of recipients) {
        calls.push({ from, to: recipient, subject: p.subject, text: p.text, html: p.html });
        const reason = rejections.get(recipient);
        if (reason) throw new Error(reason);
      }
      return { messageId: `msg-${calls.length}` } as unknown as EmailSendResult;
    }
  } as unknown as SendEmail;
  return {
    binding,
    calls,
    rejectOn: (recipient, reason) => rejections.set(recipient, reason)
  };
}

const alert: Alert = {
  id: "alert-1",
  rule_id: "aws-root-account-usage",
  title: "AWS root account console login",
  severity: "high",
  source: "aws_cloudtrail",
  status: "open",
  dedupe_key: "aws-root:123456789012",
  match_count: 1,
  first_seen: "2026-05-26T12:00:00.000Z",
  last_seen: "2026-05-26T12:00:00.000Z",
  event: {
    time: "2026-05-26T12:00:00.000Z",
    source: "aws_cloudtrail",
    category: "identity_access",
    class_name: "authentication",
    activity_name: "ConsoleLogin",
    status: "success",
    actor: {
      user: {
        uid: "123456789012",
        type: "Root"
      }
    },
    src_endpoint: {
      ip: "203.0.113.10"
    },
    metadata: {
      product_name: "AWS CloudTrail",
      raw_event: {}
    }
  }
};

function seededDb(): FakeAlertDb {
  const row: FakeAlertRow = {
    id: alert.id,
    rule_id: alert.rule_id,
    title: alert.title,
    severity: alert.severity,
    source: alert.source,
    status: alert.status,
    match_count: alert.match_count,
    first_seen: alert.first_seen,
    last_seen: alert.last_seen,
    updated_at: alert.last_seen,
    event_json: JSON.stringify(alert.event)
  };
  return new FakeAlertDb([row]);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("toSlackMessage", () => {
  it("formats alert details for Slack", () => {
    const message = toSlackMessage(alert);

    expect(message.text).toBe("[HIGH] AWS root account console login");
    expect(JSON.stringify(message.blocks)).toContain("aws-root-account-usage");
    expect(JSON.stringify(message.blocks)).toContain("203.0.113.10");
  });
});

describe("routeAlert", () => {
  it("sends alerts to configured Slack and webhook destinations", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));

    const attempts = await routeAlert(alert, {
      SLACK_WEBHOOK_URL: "https://hooks.slack.test/example",
      ALERT_WEBHOOK_URL: "https://webhook.test/alerts",
      ALERT_WEBHOOK_AUTH_HEADER: "Bearer test"
    });

    expect(attempts).toEqual([
      { destination: "slack", ok: true, status: 200 },
      { destination: "webhook", ok: true, status: 200 }
    ]);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://webhook.test/alerts",
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: "Bearer test" })
      })
    );
  });

  it("returns a failed attempt instead of throwing when a destination fails", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("bad", { status: 500 }));

    const attempts = await routeAlert(alert, { SLACK_WEBHOOK_URL: "https://hooks.slack.test/example" });

    expect(attempts).toHaveLength(1);
    expect(attempts[0]).toMatchObject({ destination: "slack", ok: false });
    expect(attempts[0]?.error).toContain("Slack delivery failed with status 500");
  });

  it("returns an empty array and warns when no destinations are configured", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const fetchMock = vi.spyOn(globalThis, "fetch");

    const attempts = await routeAlert(alert, {});

    expect(attempts).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalled();
  });

  it("records delivery_attempted + delivery_succeeded timeline rows on success", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
    const db = seededDb();

    await routeAlert(alert, {
      SLACK_WEBHOOK_URL: "https://hooks.slack.test/example",
      ALERT_WEBHOOK_URL: "https://webhook.test/alerts",
      ALERT_STATE_DB: db as unknown as D1Database
    });

    expect(db.timeline.map((entry) => entry.action)).toEqual([
      "delivery_attempted",
      "delivery_succeeded",
      "delivery_attempted",
      "delivery_succeeded"
    ]);

    const [, slackSucceeded, , webhookSucceeded] = db.timeline;
    expect(JSON.parse(slackSucceeded?.metadata_json ?? "{}")).toMatchObject({
      destination: "slack",
      status: 200
    });
    expect(JSON.parse(webhookSucceeded?.metadata_json ?? "{}")).toMatchObject({
      destination: "webhook",
      status: 200
    });
    expect(db.timeline.every((entry) => entry.actor === "router")).toBe(true);
  });

  it("records delivery_attempted + delivery_failed timeline rows on failure", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("bad", { status: 500 }));
    const db = seededDb();

    const attempts = await routeAlert(alert, {
      SLACK_WEBHOOK_URL: "https://hooks.slack.test/example",
      ALERT_STATE_DB: db as unknown as D1Database
    });

    expect(attempts[0]?.ok).toBe(false);
    expect(db.timeline.map((entry) => entry.action)).toEqual([
      "delivery_attempted",
      "delivery_failed"
    ]);
    const failed = db.timeline.at(-1);
    expect(failed?.action).toBe("delivery_failed");
    const metadata = JSON.parse(failed?.metadata_json ?? "{}") as { destination: string; error: string };
    expect(metadata.destination).toBe("slack");
    expect(metadata.error).toContain("Slack delivery failed");
  });

  it("attempts every destination even when one fails", async () => {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response("bad", { status: 500 }))
      .mockResolvedValueOnce(new Response("ok"));
    const db = seededDb();

    const attempts = await routeAlert(alert, {
      SLACK_WEBHOOK_URL: "https://hooks.slack.test/example",
      ALERT_WEBHOOK_URL: "https://webhook.test/alerts",
      ALERT_STATE_DB: db as unknown as D1Database
    });

    expect(attempts.map((attempt) => ({ destination: attempt.destination, ok: attempt.ok }))).toEqual([
      { destination: "slack", ok: false },
      { destination: "webhook", ok: true }
    ]);
    expect(db.timeline.map((entry) => entry.action)).toEqual([
      "delivery_attempted",
      "delivery_failed",
      "delivery_attempted",
      "delivery_succeeded"
    ]);
  });

  it("delivers without ALERT_STATE_DB configured", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));

    const attempts = await routeAlert(alert, {
      SLACK_WEBHOOK_URL: "https://hooks.slack.test/example"
    });

    expect(attempts).toEqual([{ destination: "slack", ok: true, status: 200 }]);
  });

  it("orders attempts as slack → email → webhook when all are configured", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
    const email = fakeSendEmail();

    const attempts = await routeAlert(alert, {
      SLACK_WEBHOOK_URL: "https://hooks.slack.test/example",
      ALERT_WEBHOOK_URL: "https://webhook.test/alerts",
      SEND_EMAIL: email.binding,
      ALERT_EMAIL_FROM: "picket@example.com",
      ALERT_EMAIL_TO: "soc@example.com"
    });

    expect(attempts.map((attempt) => attempt.destination)).toEqual(["slack", "email", "webhook"]);
    expect(attempts.every((attempt) => attempt.ok)).toBe(true);
  });
});

describe("parseRecipients", () => {
  it("splits, trims, and drops empties", () => {
    expect(parseRecipients("a@x.com , b@x.com,, c@x.com ")).toEqual([
      "a@x.com",
      "b@x.com",
      "c@x.com"
    ]);
  });

  it("returns an empty list for undefined or whitespace", () => {
    expect(parseRecipients(undefined)).toEqual([]);
    expect(parseRecipients("   ")).toEqual([]);
    expect(parseRecipients(",, ,")).toEqual([]);
  });
});

describe("toEmailMessage", () => {
  it("uses [PICKET <SEVERITY>] in the subject", () => {
    const message = toEmailMessage(alert);
    expect(message.subject).toBe("[PICKET HIGH] AWS root account console login");
  });

  it("renders severity, rule, source IP, and alert id in both bodies", () => {
    const message = toEmailMessage(alert);
    expect(message.text).toContain("Severity: high");
    expect(message.text).toContain("Rule: aws-root-account-usage");
    expect(message.text).toContain("Source IP: 203.0.113.10");
    expect(message.text).toContain("Alert ID: alert-1");
    expect(message.html).toContain("high");
    expect(message.html).toContain("aws-root-account-usage");
    expect(message.html).toContain("203.0.113.10");
    expect(message.html).toContain("background:#d24"); // high → red
  });

  it("HTML-escapes untrusted title and actor fields", () => {
    const hostile: Alert = {
      ...alert,
      title: `<script>alert("xss")</script>`,
      event: {
        ...alert.event,
        actor: { user: { name: `</td><img src=x onerror="alert(1)">` } }
      }
    };
    const message = toEmailMessage(hostile);
    expect(message.html).not.toContain("<script>");
    expect(message.html).not.toContain('onerror="alert(1)"');
    expect(message.html).toContain("&lt;script&gt;");
    expect(message.html).toContain("&lt;/td&gt;");
  });
});

describe("sendEmailAlert", () => {
  it("sends one message per recipient and returns status 202", async () => {
    const email = fakeSendEmail();

    const result = await sendEmailAlert(
      alert,
      email.binding,
      "picket@example.com",
      ["soc@example.com", "oncall@example.com"]
    );

    expect(result).toEqual({ destination: "email", status: 202 });
    expect(email.calls.map((call) => call.to)).toEqual(["soc@example.com", "oncall@example.com"]);
    expect(email.calls.every((call) => call.from === "picket@example.com")).toBe(true);
    expect(email.calls.every((call) => call.subject.startsWith("[PICKET HIGH] "))).toBe(true);
    expect(email.calls.every((call) => (call.html ?? "").length > 0)).toBe(true);
    expect(email.calls.every((call) => (call.text ?? "").length > 0)).toBe(true);
  });

  it("throws an aggregated error naming the failing recipient", async () => {
    const email = fakeSendEmail();
    email.rejectOn("bad@example.com", "smtp 550");

    await expect(
      sendEmailAlert(
        alert,
        email.binding,
        "picket@example.com",
        ["good@example.com", "bad@example.com"]
      )
    ).rejects.toThrow(/Email delivery failed for bad@example\.com \(smtp 550\)/);
  });
});

describe("routeAlert email destination", () => {
  function emailEnv(extras: Partial<AlertRouterEnv> = {}): {
    env: AlertRouterEnv;
    email: ReturnType<typeof fakeSendEmail>;
    db: FakeAlertDb;
  } {
    const email = fakeSendEmail();
    const db = seededDb();
    return {
      email,
      db,
      env: {
        SEND_EMAIL: email.binding,
        ALERT_EMAIL_FROM: "picket@example.com",
        ALERT_EMAIL_TO: "soc@example.com, oncall@example.com",
        ALERT_STATE_DB: db as unknown as D1Database,
        ...extras
      }
    };
  }

  it("delivers to all recipients and records one attempted+succeeded timeline pair", async () => {
    const { env, email, db } = emailEnv();

    const attempts = await routeAlert(alert, env);

    expect(attempts).toHaveLength(1);
    expect(attempts[0]).toMatchObject({ destination: "email", ok: true, status: 202 });
    expect(email.calls.map((call) => call.to)).toEqual([
      "soc@example.com",
      "oncall@example.com"
    ]);

    expect(db.timeline.map((entry) => entry.action)).toEqual([
      "delivery_attempted",
      "delivery_succeeded"
    ]);
    for (const entry of db.timeline) {
      const metadata = JSON.parse(entry.metadata_json ?? "{}") as {
        destination: string;
        recipients: string[];
      };
      expect(metadata.destination).toBe("email");
      expect(metadata.recipients).toEqual(["soc@example.com", "oncall@example.com"]);
    }
  });

  it("records delivery_failed when one recipient rejects, and the attempt names it", async () => {
    const { env, email, db } = emailEnv();
    email.rejectOn("oncall@example.com", "rate limited");

    const attempts = await routeAlert(alert, env);

    expect(attempts[0]?.ok).toBe(false);
    expect(attempts[0]?.error).toContain("oncall@example.com");
    expect(attempts[0]?.error).toContain("rate limited");

    expect(db.timeline.map((entry) => entry.action)).toEqual([
      "delivery_attempted",
      "delivery_failed"
    ]);
    const failed = db.timeline.at(-1);
    const metadata = JSON.parse(failed?.metadata_json ?? "{}") as {
      destination: string;
      recipients: string[];
      error: string;
    };
    expect(metadata.destination).toBe("email");
    expect(metadata.recipients).toEqual(["soc@example.com", "oncall@example.com"]);
    expect(metadata.error).toContain("oncall@example.com");
  });

  it("skips email entirely when only ALERT_EMAIL_FROM is set", async () => {
    const db = seededDb();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);

    const attempts = await routeAlert(alert, {
      ALERT_EMAIL_FROM: "picket@example.com",
      ALERT_STATE_DB: db as unknown as D1Database
    });

    expect(attempts).toEqual([]);
    expect(db.timeline).toHaveLength(0);
    expect(warn).toHaveBeenCalled();
  });
});
