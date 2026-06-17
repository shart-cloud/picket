import type { OcsfEvent } from "@picket/core";

export interface AlertEventSummary {
  activity: string;
  outcome: string;
  user?: string;
  sourceIp?: string;
  destination?: string;
  operation?: string;
  cloud?: string;
  threat?: {
    indicator: string;
    type: string;
    field: string;
    feed?: string;
    threatType?: string;
  };
}

export function parseAlertEvent(value: string): OcsfEvent | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!parsed || typeof parsed !== "object") return null;
    return parsed as OcsfEvent;
  } catch {
    return null;
  }
}

export function summarizeAlertEvent(event: OcsfEvent): AlertEventSummary {
  const actor = event.actor?.user;
  const user = actor?.email ?? actor?.name ?? actor?.uid ?? event.user?.email ?? event.user?.name ?? event.user?.uid;
  const destination = event.dst_endpoint?.ip ?? event.dst_endpoint?.name ?? event.dst_endpoint?.uid;
  const cloud = [event.cloud?.provider, event.cloud?.account?.name ?? event.cloud?.account?.uid, event.cloud?.region]
    .filter((value): value is string => Boolean(value))
    .join(" / ");

  return {
    activity: event.activity_name,
    outcome: event.status,
    user,
    sourceIp: event.src_endpoint?.ip,
    destination,
    operation: event.api?.operation,
    cloud: cloud || undefined,
    threat: event.threat_match
      ? {
          indicator: event.threat_match.indicator,
          type: event.threat_match.indicator_type,
          field: event.threat_match.matched_field,
          feed: event.threat_match.feed_name,
          threatType: event.threat_match.threat_type
        }
      : undefined
  };
}
