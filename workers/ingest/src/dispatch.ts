import {
  flavorOfRecord,
  normalizeAzureActivity,
  normalizeAzureAdSignin,
  normalizeCloudTrail,
  normalizeCloudflareAudit,
  normalizeGithubAudit,
  normalizeGcpCloudAudit,
  normalizeGuardDuty,
  normalizeK8sAudit,
  normalizeM365Management,
  normalizeVpcFlowLog,
  parseVpcFlowLogs,
  parseNdjson
} from "@picket/normalize";
import type { OcsfEvent, SourceId } from "@picket/core";

type JsonObject = Record<string, unknown>;

export interface DispatchResult {
  events: OcsfEvent[];
  parse_failures: number;
}

export async function dispatch(source: SourceId, request: Request): Promise<DispatchResult> {
  switch (source) {
    case "aws_cloudtrail":
      return dispatchCloudTrail(await request.json());
    case "aws_vpc_flow":
      return dispatchVpcFlow(await request.text());
    case "aws_guardduty":
      return dispatchJsonRecords(await request.text(), guardDutyRecords, normalizeGuardDuty, "expected GuardDuty finding object or EventBridge { detail }");
    case "gcp_cloud_audit":
      return dispatchJsonRecords(await request.text(), genericJsonRecords, normalizeGcpCloudAudit, "expected GCP Cloud Audit log object or JSON/NDJSON batch");
    case "azure_activity":
      return dispatchJsonRecords(await request.text(), genericJsonRecords, normalizeAzureActivity, "expected Azure Activity log object or JSON/NDJSON batch");
    case "azure_ad_signin":
      return dispatchJsonRecords(await request.text(), genericJsonRecords, normalizeAzureAdSignin, "expected Azure AD sign-in log object or JSON/NDJSON batch");
    case "github_audit":
      return dispatchJsonRecords(await request.text(), genericJsonRecords, normalizeGithubAudit, "expected GitHub audit log object or JSON/NDJSON batch");
    case "m365_management":
      return dispatchJsonRecords(await request.text(), genericJsonRecords, normalizeM365Management, "expected M365 Management Activity object or JSON/NDJSON batch");
    case "kubernetes_audit":
      return dispatchK8sAudit(await request.text());
    case "cloudflare_audit":
      return dispatchCloudflareAudit(await request.text());
    case "okta_auth":
      throw httpError(400, "okta_auth is not a supported ingest source");
    default:
      throw httpError(400, `unknown source: ${source as string}`);
  }
}

function dispatchJsonRecords(
  body: string,
  extract: (payload: unknown, body: string) => JsonObject[],
  normalize: (record: JsonObject) => OcsfEvent,
  error: string
): DispatchResult {
  const payload = parseJson(body);
  const records = extract(payload, body);
  if (records.length === 0) throw httpError(400, error);
  return normalizeRecords(records, normalize);
}

function dispatchVpcFlow(body: string): DispatchResult {
  const records = parseVpcFlowLogs(body);
  if (records.length === 0) throw httpError(400, "expected VPC Flow Logs text records");
  return normalizeRecords(records, normalizeVpcFlowLog);
}

function dispatchCloudTrail(payload: unknown): DispatchResult {
  const records = cloudTrailRecords(payload);
  if (records.length === 0) throw httpError(400, "expected CloudTrail event object or { Records: [...] }");
  return normalizeRecords(records, normalizeCloudTrail);
}

function dispatchK8sAudit(body: string): DispatchResult {
  const records = parseNdjson(body);
  if (records.length === 0) throw httpError(400, "expected NDJSON body with at least one k8s audit record");
  return normalizeRecords(records, (record) => normalizeK8sAudit(record, { flavor: flavorOfRecord(record) }));
}

function dispatchCloudflareAudit(body: string): DispatchResult {
  const payload = parseJson(body);
  const records = payload === undefined ? parseNdjson(body) : cloudflareAuditRecords(payload);
  if (records.length === 0) throw httpError(400, "expected Cloudflare audit event object or { result: [...] }");
  return normalizeRecords(records, normalizeCloudflareAudit);
}

// Normalize a batch record-by-record. A record that fails normalization or OCSF
// schema validation is dropped and counted, so one malformed event never fails
// the whole batch — the same degradation the k8s path always had.
function normalizeRecords(records: JsonObject[], normalize: (record: JsonObject) => OcsfEvent): DispatchResult {
  let parse_failures = 0;
  const events: OcsfEvent[] = [];
  for (const record of records) {
    try {
      events.push(normalize(record));
    } catch {
      parse_failures++;
    }
  }
  return { events, parse_failures };
}

function parseJson(body: string): unknown | undefined {
  try {
    return JSON.parse(body) as unknown;
  } catch {
    return undefined;
  }
}

function cloudflareAuditRecords(payload: unknown): JsonObject[] {
  if (Array.isArray(payload)) return payload.filter(isJsonObject);
  if (isJsonObject(payload) && Array.isArray(payload.result)) return payload.result.filter(isJsonObject);
  if (isJsonObject(payload)) return [payload];
  return [];
}

function cloudTrailRecords(payload: unknown): JsonObject[] {
  if (!isJsonObject(payload)) return [];
  if (Array.isArray(payload.Records)) return payload.Records.filter(isJsonObject);
  return [payload];
}

function guardDutyRecords(payload: unknown): JsonObject[] {
  if (!isJsonObject(payload)) return [];
  if (Array.isArray(payload.Records)) return payload.Records.filter(isJsonObject);
  if (Array.isArray(payload.findings)) return payload.findings.filter(isJsonObject);
  return [payload];
}

function genericJsonRecords(payload: unknown, body: string): JsonObject[] {
  if (Array.isArray(payload)) return payload.filter(isJsonObject);
  if (isJsonObject(payload) && Array.isArray(payload.records)) return payload.records.filter(isJsonObject);
  if (isJsonObject(payload) && Array.isArray(payload.value)) return payload.value.filter(isJsonObject);
  if (isJsonObject(payload)) return [payload];
  return parseNdjson(body);
}

function isJsonObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function httpError(status: number, message: string): HttpError {
  return new HttpError(status, message);
}
