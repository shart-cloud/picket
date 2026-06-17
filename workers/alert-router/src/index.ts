import type { Alert } from "@picket/core";
import {
  recordDeliveryAttempt,
  recordDeliveryFailed,
  recordDeliverySucceeded,
  type AlertStateDb
} from "@picket/core/alerts";

export interface AlertRouterEnv {
  SLACK_WEBHOOK_URL?: string;
  ALERT_WEBHOOK_URL?: string;
  ALERT_WEBHOOK_AUTH_HEADER?: string;
  ALERT_STATE_DB?: D1Database;
  SEND_EMAIL?: SendEmail;
  ALERT_EMAIL_FROM?: string;
  ALERT_EMAIL_TO?: string;
  PICKET_CONSOLE_URL?: string;
}

// Placeholder base for the (not-yet-built) query explorer / alert console.
// Override with PICKET_CONSOLE_URL once the frontend exists.
const DEFAULT_CONSOLE_URL = "https://picket.example.com";

export function alertLink(alert: Alert, consoleUrl?: string): string {
  const base = (consoleUrl ?? DEFAULT_CONSOLE_URL).replace(/\/+$/, "");
  return `${base}/alerts/${encodeURIComponent(alert.id)}`;
}

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return Response.json({ ok: true, worker: "picket-alert-router" });
    }

    return Response.json({ error: "Not found" }, { status: 404 });
  },

  async queue(batch: MessageBatch<Alert>, env: AlertRouterEnv): Promise<void> {
    for (const message of batch.messages) {
      const attempts = await routeAlert(message.body, env);
      const failures = attempts.filter((attempt) => !attempt.ok);
      if (failures.length > 0) {
        console.error(
          JSON.stringify({
            message: "alert delivery failed",
            alert_id: message.body.id,
            attempts
          })
        );
        message.retry();
      } else {
        message.ack();
      }
    }
  }
} satisfies ExportedHandler<AlertRouterEnv, Alert>;

export type DeliveryDestination = "slack" | "email" | "webhook";

export interface DeliveryAttempt {
  destination: DeliveryDestination;
  ok: boolean;
  status?: number;
  error?: string;
  metadata?: Record<string, unknown>;
}

export async function routeAlert(alert: Alert, env: AlertRouterEnv): Promise<DeliveryAttempt[]> {
  const destinations: Array<{
    name: DeliveryDestination;
    metadata?: Record<string, unknown>;
    send: () => Promise<DeliveryResult>;
  }> = [];

  if (env.SLACK_WEBHOOK_URL) {
    const url = env.SLACK_WEBHOOK_URL;
    destinations.push({ name: "slack", send: () => sendSlackAlert(alert, url, env.PICKET_CONSOLE_URL) });
  }

  const recipients = parseRecipients(env.ALERT_EMAIL_TO);
  if (env.SEND_EMAIL && env.ALERT_EMAIL_FROM && recipients.length > 0) {
    const sender = env.ALERT_EMAIL_FROM;
    const binding = env.SEND_EMAIL;
    destinations.push({
      name: "email",
      metadata: { recipients },
      send: () => sendEmailAlert(alert, binding, sender, recipients)
    });
  }

  if (env.ALERT_WEBHOOK_URL) {
    const url = env.ALERT_WEBHOOK_URL;
    const auth = env.ALERT_WEBHOOK_AUTH_HEADER;
    destinations.push({ name: "webhook", send: () => sendWebhookAlert(alert, url, auth) });
  }

  if (destinations.length === 0) {
    console.warn(
      JSON.stringify({ message: "no alert destinations configured", alert_id: alert.id })
    );
    return [];
  }

  const db = env.ALERT_STATE_DB as AlertStateDb | undefined;
  const attempts: DeliveryAttempt[] = [];

  for (const destination of destinations) {
    if (db) {
      await recordDeliveryAttempt(db, alert.id, destination.name, destination.metadata);
    }
    try {
      const result = await destination.send();
      if (db) {
        await recordDeliverySucceeded(
          db,
          alert.id,
          destination.name,
          result.status,
          destination.metadata
        );
      }
      attempts.push({
        destination: destination.name,
        ok: true,
        status: result.status,
        ...(destination.metadata ? { metadata: destination.metadata } : {})
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (db) {
        await recordDeliveryFailed(db, alert.id, destination.name, message, destination.metadata);
      }
      attempts.push({
        destination: destination.name,
        ok: false,
        error: message,
        ...(destination.metadata ? { metadata: destination.metadata } : {})
      });
    }
  }

  return attempts;
}

export interface DeliveryResult {
  destination: DeliveryDestination;
  status: number;
}

export async function sendSlackAlert(
  alert: Alert,
  webhookUrl: string,
  consoleUrl?: string
): Promise<DeliveryResult> {
  const response = await fetch(webhookUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(toSlackMessage(alert, consoleUrl))
  });

  if (!response.ok) {
    throw new Error(`Slack delivery failed with status ${response.status}`);
  }

  return { destination: "slack", status: response.status };
}

export async function sendWebhookAlert(
  alert: Alert,
  webhookUrl: string,
  authHeader?: string
): Promise<DeliveryResult> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json"
  };

  if (authHeader) headers.Authorization = authHeader;

  const response = await fetch(webhookUrl, {
    method: "POST",
    headers,
    body: JSON.stringify(alert)
  });

  if (!response.ok) {
    throw new Error(`Webhook delivery failed with status ${response.status}`);
  }

  return { destination: "webhook", status: response.status };
}

export function parseRecipients(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

const SEVERITY_COLORS: Record<Alert["severity"], string> = {
  critical: "#b00",
  high: "#d24",
  medium: "#e80",
  low: "#888",
  informational: "#06b"
};

export interface EmailPayload {
  subject: string;
  text: string;
  html: string;
}

export function toEmailMessage(alert: Alert): EmailPayload {
  const actor =
    alert.event.actor?.user?.email ??
    alert.event.actor?.user?.name ??
    alert.event.actor?.user?.uid ??
    "unknown";
  const sourceIp = alert.event.src_endpoint?.ip ?? "unknown";
  const severityColor = SEVERITY_COLORS[alert.severity] ?? "#444";

  const subject = `[PICKET ${alert.severity.toUpperCase()}] ${alert.title}`;

  const fields: Array<[string, string]> = [
    ["Severity", alert.severity],
    ["Rule", alert.rule_id],
    ["Source", alert.source],
    ["Status", alert.status],
    ["Actor", actor],
    ["Source IP", sourceIp],
    ["First Seen", alert.first_seen],
    ["Last Seen", alert.last_seen],
    ["Match Count", String(alert.match_count)],
    ["Alert ID", alert.id]
  ];

  const text = [
    `[${alert.severity.toUpperCase()}] ${alert.title}`,
    "",
    ...fields.map(([label, value]) => `${label}: ${value}`)
  ].join("\n");

  const rows = fields
    .map(
      ([label, value]) =>
        `      <tr><th align="left" style="padding:4px 12px 4px 0;">${escapeHtml(label)}</th><td style="padding:4px 0;">${escapeHtml(value)}</td></tr>`
    )
    .join("\n");

  const html = [
    `<h2 style="margin:0 0 8px 0;">`,
    `  <span style="display:inline-block;padding:2px 8px;margin-right:8px;border-radius:3px;background:${severityColor};color:#fff;font-size:12px;text-transform:uppercase;">${escapeHtml(alert.severity)}</span>`,
    `  ${escapeHtml(alert.title)}`,
    `</h2>`,
    `<table style="border-collapse:collapse;font-family:system-ui,-apple-system,sans-serif;font-size:14px;">`,
    rows,
    `</table>`
  ].join("\n");

  return { subject, text, html };
}

export async function sendEmailAlert(
  alert: Alert,
  binding: SendEmail,
  from: string,
  recipients: readonly string[]
): Promise<DeliveryResult> {
  const message = toEmailMessage(alert);
  const failures: Array<{ recipient: string; reason: string }> = [];

  for (const recipient of recipients) {
    try {
      await binding.send({
        from,
        to: recipient,
        subject: message.subject,
        text: message.text,
        html: message.html
      });
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      failures.push({ recipient, reason });
    }
  }

  if (failures.length > 0) {
    const summary = failures
      .map((failure) => `${failure.recipient} (${failure.reason})`)
      .join(", ");
    throw new Error(`Email delivery failed for ${summary}`);
  }

  return { destination: "email", status: 202 };
}

export function toSlackMessage(alert: Alert, consoleUrl?: string): SlackMessage {
  const actor = alert.event.actor?.user?.email ?? alert.event.actor?.user?.name ?? alert.event.actor?.user?.uid ?? "unknown";
  const sourceIp = alert.event.src_endpoint?.ip ?? "unknown";
  const link = alertLink(alert, consoleUrl);

  return {
    text: `[${alert.severity.toUpperCase()}] ${alert.title}`,
    blocks: [
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*${alert.title}*\nSeverity: *${alert.severity}*\nRule: \`${alert.rule_id}\``
        }
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Source*\n${alert.source}` },
          { type: "mrkdwn", text: `*Status*\n${alert.status}` },
          { type: "mrkdwn", text: `*Actor*\n${actor}` },
          { type: "mrkdwn", text: `*Source IP*\n${sourceIp}` },
          { type: "mrkdwn", text: `*First Seen*\n${alert.first_seen}` },
          { type: "mrkdwn", text: `*Alert ID*\n${alert.id}` }
        ]
      },
      {
        type: "section",
        text: { type: "mrkdwn", text: `<${link}|View event in Picket>` }
      }
    ]
  };
}

export interface SlackMessage {
  text: string;
  blocks: Array<
    | {
        type: "section";
        text: {
          type: "mrkdwn";
          text: string;
        };
      }
    | {
        type: "section";
        fields: Array<{
          type: "mrkdwn";
          text: string;
        }>;
      }
  >;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
