// Real OCSF schema validation (Milestone 0.1).
//
// Replaces the previous 5-field presence check with enum validation,
// category/class consistency, leaf-type checks, and per-class required-field
// rules. `validateOcsfEvent` returns every problem it finds (so a malformed new
// source surfaces all issues at once); `assertOcsfEvent` throws if there are any.
//
// Type-only imports from ./index keep this module free of a runtime cycle —
// index re-exports assertOcsfEvent from here.

import type {
  OcsfApiDetails,
  OcsfCategory,
  OcsfClass,
  OcsfCloudDetails,
  OcsfEndpoint,
  OcsfEvent,
  OcsfStatus,
  OcsfUser,
  SourceId
} from "./index.js";

export const OCSF_SOURCES: readonly SourceId[] = [
  "aws_cloudtrail",
  "aws_vpc_flow",
  "aws_guardduty",
  "gcp_cloud_audit",
  "azure_activity",
  "azure_ad_signin",
  "github_audit",
  "m365_management",
  "okta_auth",
  "cloudflare_audit",
  "kubernetes_audit"
];

export const OCSF_CATEGORIES: readonly OcsfCategory[] = ["identity_access", "network_activity", "findings", "discovery"];

export const OCSF_CLASSES: readonly OcsfClass[] = [
  "authentication",
  "api_activity",
  "account_change",
  "network_activity",
  "detection_finding"
];

export const OCSF_STATUSES: readonly OcsfStatus[] = ["success", "failure", "unknown"];

// Which classes are valid within a category. Categories absent from this map are
// not yet constrained — e.g. `network_activity` gets its class set when the M2
// VPC Flow Logs source lands. Present categories are validated strictly.
const CATEGORY_CLASSES: Partial<Record<OcsfCategory, readonly OcsfClass[]>> = {
  identity_access: ["authentication", "api_activity", "account_change"],
  network_activity: ["network_activity"],
  findings: ["detection_finding"]
};

export class OcsfValidationError extends Error {
  readonly issues: string[];

  constructor(issues: string[]) {
    super(`OCSF validation failed: ${issues.join("; ")}`);
    this.name = "OcsfValidationError";
    this.issues = issues;
  }
}

export function validateOcsfEvent(event: OcsfEvent): string[] {
  const issues: string[] = [];

  // --- Required identity fields ---
  if (typeof event.time !== "string" || event.time.length === 0 || Number.isNaN(Date.parse(event.time))) {
    issues.push("time must be an ISO-8601 timestamp string");
  }
  if (!isEnum(event.source, OCSF_SOURCES)) {
    issues.push(`source ${quote(event.source)} is not a known OCSF source`);
  }
  if (!isEnum(event.category, OCSF_CATEGORIES)) {
    issues.push(`category ${quote(event.category)} is not a known OCSF category`);
  }
  if (!isEnum(event.class_name, OCSF_CLASSES)) {
    issues.push(`class_name ${quote(event.class_name)} is not a known OCSF class`);
  }
  if (!isEnum(event.status, OCSF_STATUSES)) {
    issues.push(`status ${quote(event.status)} is not a known OCSF status`);
  }
  if (!nonEmptyString(event.activity_name)) {
    issues.push("activity_name is required");
  }
  if (event.message !== undefined && typeof event.message !== "string") {
    issues.push("message must be a string when present");
  }

  // --- Metadata ---
  if (!event.metadata || typeof event.metadata !== "object") {
    issues.push("metadata object is required");
  } else {
    if (!nonEmptyString(event.metadata.product_name)) {
      issues.push("metadata.product_name is required");
    }
    if (!("raw_event" in event.metadata)) {
      issues.push("metadata.raw_event is required (event provenance)");
    }
    if (event.metadata.original_uid !== undefined && typeof event.metadata.original_uid !== "string") {
      issues.push("metadata.original_uid must be a string when present");
    }
  }

  // --- Category / class consistency ---
  if (isEnum(event.category, OCSF_CATEGORIES) && isEnum(event.class_name, OCSF_CLASSES)) {
    const allowed = CATEGORY_CLASSES[event.category];
    if (allowed && !allowed.includes(event.class_name)) {
      issues.push(`class_name "${event.class_name}" is not valid for category "${event.category}"`);
    }
  }

  // --- Leaf-type checks on optional nested objects ---
  validateEndpoint(event.src_endpoint, "src_endpoint", issues);
  validateEndpoint(event.dst_endpoint, "dst_endpoint", issues);
  validateUser(event.actor?.user, "actor.user", issues);
  validateUser(event.user, "user", issues);
  validateApi(event.api, issues);
  validateCloud(event.cloud, issues);
  if (event.http_request !== undefined) {
    if (!isPlainObject(event.http_request)) {
      issues.push("http_request must be an object when present");
    } else {
      validateStringFields(event.http_request, "http_request", ["user_agent", "url", "http_method"], issues);
    }
  }

  // --- Per-class required fields ---
  switch (event.class_name) {
    case "authentication":
    case "account_change":
      if (!hasUserIdentity(event.actor?.user)) {
        issues.push(`${event.class_name} events require actor.user with a uid, name, or email`);
      }
      break;
    case "api_activity":
      if (!nonEmptyString(event.api?.operation)) {
        issues.push("api_activity events require api.operation");
      }
      if (!nonEmptyString(event.api?.service?.name)) {
        issues.push("api_activity events require api.service.name");
      }
      break;
    case "network_activity":
      if (!nonEmptyString(event.src_endpoint?.ip)) {
        issues.push("network_activity events require src_endpoint.ip");
      }
      if (!nonEmptyString(event.dst_endpoint?.ip)) {
        issues.push("network_activity events require dst_endpoint.ip");
      }
      break;
    default:
      break;
  }

  return issues;
}

export function assertOcsfEvent(event: OcsfEvent): OcsfEvent {
  const issues = validateOcsfEvent(event);
  if (issues.length > 0) {
    throw new OcsfValidationError(issues);
  }
  return event;
}

function validateEndpoint(endpoint: OcsfEndpoint | undefined, path: string, issues: string[]): void {
  if (endpoint === undefined) return;
  if (!isPlainObject(endpoint)) {
    issues.push(`${path} must be an object when present`);
    return;
  }
  validateStringFields(endpoint, path, ["ip", "name", "uid", "country", "region", "city"], issues);
}

function validateUser(user: OcsfUser | undefined, path: string, issues: string[]): void {
  if (user === undefined) return;
  if (!isPlainObject(user)) {
    issues.push(`${path} must be an object when present`);
    return;
  }
  validateStringFields(user, path, ["uid", "name", "email", "type"], issues);
}

function validateApi(api: OcsfApiDetails | undefined, issues: string[]): void {
  if (api === undefined) return;
  if (!isPlainObject(api)) {
    issues.push("api must be an object when present");
    return;
  }
  if (api.operation !== undefined && typeof api.operation !== "string") {
    issues.push("api.operation must be a string when present");
  }
  if (api.service !== undefined) {
    if (!isPlainObject(api.service)) {
      issues.push("api.service must be an object when present");
    } else if (api.service.name !== undefined && typeof api.service.name !== "string") {
      issues.push("api.service.name must be a string when present");
    }
  }
}

function validateCloud(cloud: OcsfCloudDetails | undefined, issues: string[]): void {
  if (cloud === undefined) return;
  if (!isPlainObject(cloud)) {
    issues.push("cloud must be an object when present");
    return;
  }
  validateStringFields(cloud, "cloud", ["provider", "region"], issues);
  if (cloud.account !== undefined) {
    if (!isPlainObject(cloud.account)) {
      issues.push("cloud.account must be an object when present");
    } else {
      validateStringFields(cloud.account, "cloud.account", ["uid", "name"], issues);
    }
  }
}

function validateStringFields(
  obj: Record<string, unknown>,
  path: string,
  fields: string[],
  issues: string[]
): void {
  for (const field of fields) {
    const value = obj[field];
    if (value !== undefined && typeof value !== "string") {
      issues.push(`${path}.${field} must be a string when present`);
    }
  }
}

function hasUserIdentity(user: OcsfUser | undefined): boolean {
  if (!isPlainObject(user)) return false;
  return nonEmptyString(user.uid) || nonEmptyString(user.name) || nonEmptyString(user.email);
}

function isEnum<T extends string>(value: unknown, allowed: readonly T[]): value is T {
  return typeof value === "string" && (allowed as readonly string[]).includes(value);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function quote(value: unknown): string {
  return typeof value === "string" ? `"${value}"` : String(value);
}
