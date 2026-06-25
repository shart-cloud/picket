import type { OcsfEvent } from "@picket/core";

export interface AlertContextQueryInput {
  source: string;
  lastSeen: string;
  event: OcsfEvent;
  windowMinutes: number;
}

export interface AlertContextQuery {
  sql: string;
  pivots: string[];
  startTime: string;
  endTime: string;
}

export function buildAlertContextQuery(input: AlertContextQueryInput): AlertContextQuery | null {
  const table = safeIdentifier(input.source);
  if (!table) return null;

  const center = new Date(input.lastSeen);
  if (Number.isNaN(center.getTime())) return null;
  const windowMs = Math.max(5, Math.min(24 * 60, input.windowMinutes)) * 60_000;
  const startTime = new Date(center.getTime() - windowMs).toISOString();
  const endTime = new Date(center.getTime() + windowMs).toISOString();
  const pivots = contextPivots(input.event);
  if (pivots.length === 0) return null;

  const clauses = pivots.map((pivot) => `${pivot.column} = ${quoteSql(pivot.value)}`);
  const columns = [
    "time",
    `${quoteSql(table)} AS source`,
    "activity_name",
    "status",
    "actor_user_email",
    "actor_user_uid",
    "src_endpoint_ip",
    "api_operation",
    "cloud_provider",
    "threat_match_indicator"
  ];

  return {
    startTime,
    endTime,
    pivots: pivots.map((pivot) => pivot.label),
    sql: `SELECT ${columns.join(", ")}
FROM ${table}
WHERE time >= ${quoteSql(startTime)}
  AND time <= ${quoteSql(endTime)}
  AND (${clauses.join(" OR ")})
ORDER BY time DESC
LIMIT 50`
  };
}

function contextPivots(event: OcsfEvent): Array<{ column: string; value: string; label: string }> {
  const actor = event.actor?.user;
  const values = [
    { column: "src_endpoint_ip", value: event.src_endpoint?.ip, label: `source IP ${event.src_endpoint?.ip ?? ""}` },
    { column: "actor_user_email", value: actor?.email ?? event.user?.email, label: `user ${actor?.email ?? event.user?.email ?? ""}` },
    { column: "actor_user_uid", value: actor?.uid ?? event.user?.uid, label: `user id ${actor?.uid ?? event.user?.uid ?? ""}` }
  ];

  const seen = new Set<string>();
  return values.filter((entry): entry is { column: string; value: string; label: string } => {
    if (!entry.value) return false;
    const key = `${entry.column}:${entry.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function safeIdentifier(value: string): string | null {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(value) ? value : null;
}

function quoteSql(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}
