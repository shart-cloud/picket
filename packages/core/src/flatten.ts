import type { Alert, OcsfEvent } from "./index.js";

export type FlatRecord = Record<string, string | number | boolean | unknown>;

export function flattenOcsfEvent(event: OcsfEvent): FlatRecord {
  const out: FlatRecord = {};
  set(out, "time", event.time);
  set(out, "source", event.source);
  set(out, "category", event.category);
  set(out, "class_name", event.class_name);
  set(out, "activity_name", event.activity_name);
  set(out, "status", event.status);
  set(out, "message", event.message);

  const actor = event.actor;
  if (actor) {
    const user = actor.user;
    if (user) {
      set(out, "actor_user_uid", user.uid);
      set(out, "actor_user_name", user.name);
      set(out, "actor_user_email", user.email);
      set(out, "actor_user_type", user.type);
    }
    const session = actor.session;
    if (session) set(out, "actor_session_uid", session.uid);
  }

  const user = event.user;
  if (user) {
    set(out, "user_uid", user.uid);
    set(out, "user_name", user.name);
    set(out, "user_email", user.email);
    set(out, "user_type", user.type);
  }

  flattenEndpoint(out, "src_endpoint", event.src_endpoint);
  flattenEndpoint(out, "dst_endpoint", event.dst_endpoint);

  const api = event.api;
  if (api) {
    set(out, "api_operation", api.operation);
    if (api.service) set(out, "api_service_name", api.service.name);
  }

  const cloud = event.cloud;
  if (cloud) {
    set(out, "cloud_provider", cloud.provider);
    set(out, "cloud_region", cloud.region);
    if (cloud.account) {
      set(out, "cloud_account_uid", cloud.account.uid);
      set(out, "cloud_account_name", cloud.account.name);
    }
  }

  const http = event.http_request;
  if (http) {
    set(out, "http_request_user_agent", http.user_agent);
    set(out, "http_request_url", http.url);
    set(out, "http_request_http_method", http.http_method);
  }

  const threat = event.threat_match;
  if (threat) {
    set(out, "threat_match_indicator", threat.indicator);
    set(out, "threat_match_indicator_type", threat.indicator_type);
    set(out, "threat_match_field", threat.matched_field);
    set(out, "threat_match_feed_name", threat.feed_name);
    set(out, "threat_match_threat_type", threat.threat_type);
  }

  const meta = event.metadata;
  set(out, "metadata_product_name", meta.product_name);
  set(out, "metadata_original_uid", meta.original_uid);
  if (meta.raw_event !== undefined) out["metadata_raw_event"] = JSON.stringify(meta.raw_event);

  return out;
}

export function flattenAlert(alert: Alert): FlatRecord {
  const out: FlatRecord = {};
  set(out, "id", alert.id);
  set(out, "rule_id", alert.rule_id);
  set(out, "title", alert.title);
  set(out, "severity", alert.severity);
  set(out, "source", alert.source);
  set(out, "status", alert.status);
  set(out, "dedupe_key", alert.dedupe_key);
  out["match_count"] = alert.match_count;
  set(out, "first_seen", alert.first_seen);
  set(out, "last_seen", alert.last_seen);

  const event = flattenOcsfEvent(alert.event);
  for (const [k, v] of Object.entries(event)) {
    out[`event_${k}`] = v;
  }

  return out;
}

function flattenEndpoint(
  out: FlatRecord,
  prefix: "src_endpoint" | "dst_endpoint",
  endpoint: OcsfEvent["src_endpoint"]
): void {
  if (!endpoint) return;
  set(out, `${prefix}_ip`, endpoint.ip);
  set(out, `${prefix}_name`, endpoint.name);
  set(out, `${prefix}_uid`, endpoint.uid);
  set(out, `${prefix}_country`, endpoint.country);
  set(out, `${prefix}_region`, endpoint.region);
  set(out, `${prefix}_city`, endpoint.city);
}

function set(out: FlatRecord, key: string, value: string | undefined): void {
  if (value === undefined) return;
  out[key] = value;
}
