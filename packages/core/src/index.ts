export { flattenOcsfEvent, flattenAlert, type FlatRecord } from "./flatten.js";
export {
  assertOcsfEvent,
  validateOcsfEvent,
  OcsfValidationError,
  OCSF_SOURCES,
  OCSF_CATEGORIES,
  OCSF_CLASSES,
  OCSF_STATUSES
} from "./ocsf-schema.js";

export type SourceId =
  | "aws_cloudtrail"
  | "aws_vpc_flow"
  | "aws_guardduty"
  | "gcp_cloud_audit"
  | "azure_activity"
  | "azure_ad_signin"
  | "github_audit"
  | "m365_management"
  | "okta_auth"
  | "cloudflare_audit"
  | "kubernetes_audit";

export type OcsfCategory = "identity_access" | "network_activity" | "findings" | "discovery";

export type OcsfClass = "authentication" | "api_activity" | "account_change" | "network_activity" | "detection_finding";

export type OcsfStatus = "success" | "failure" | "unknown";

export interface OcsfEndpoint {
  ip?: string;
  name?: string;
  uid?: string;
  country?: string;
  region?: string;
  city?: string;
}

export interface OcsfUser {
  uid?: string;
  name?: string;
  email?: string;
  type?: string;
}

export interface OcsfActor {
  user?: OcsfUser;
  session?: {
    uid?: string;
  };
}

export interface OcsfApiDetails {
  operation?: string;
  service?: {
    name?: string;
  };
}

export interface OcsfCloudDetails {
  provider?: string;
  region?: string;
  account?: {
    uid?: string;
    name?: string;
  };
}

export interface OcsfHttpRequest {
  user_agent?: string;
  url?: string;
  http_method?: string;
}

export type IndicatorType = "ipv4" | "ipv6" | "domain" | "url" | "sha256";

// Stamped onto an event at ingest time when one of its indicator-bearing fields
// (e.g. src_endpoint.ip) matches an IOC synced to the enrichment KV namespace.
// Persisted to the flattened event columns so detection rules and R2 SQL can
// filter on it without a JOIN. See @picket/core/enrichment.
export interface OcsfThreatMatch {
  indicator: string;
  indicator_type: IndicatorType;
  // The flattened event field whose value matched, e.g. "src_endpoint_ip".
  matched_field: string;
  feed_name?: string;
  threat_type?: string;
}

export interface OcsfEvent {
  time: string;
  source: SourceId;
  category: OcsfCategory;
  class_name: OcsfClass;
  activity_name: string;
  status: OcsfStatus;
  message?: string;
  actor?: OcsfActor;
  user?: OcsfUser;
  src_endpoint?: OcsfEndpoint;
  dst_endpoint?: OcsfEndpoint;
  api?: OcsfApiDetails;
  cloud?: OcsfCloudDetails;
  http_request?: OcsfHttpRequest;
  threat_match?: OcsfThreatMatch;
  metadata: {
    product_name: string;
    original_uid?: string;
    raw_event: unknown;
  };
}

export type AlertSeverity = "critical" | "high" | "medium" | "low" | "informational";

export interface Alert {
  id: string;
  rule_id: string;
  title: string;
  severity: AlertSeverity;
  source: SourceId;
  status: "open" | "acknowledged" | "resolved";
  dedupe_key?: string;
  match_count: number;
  first_seen: string;
  last_seen: string;
  event: OcsfEvent;
}

// assertOcsfEvent / validateOcsfEvent now live in ./ocsf-schema.ts and are
// re-exported above.
