// Ingest-time IOC enrichment (Milestone 4).
//
// High-priority threat-intel indicators are synced into a Workers KV namespace
// and looked up while events are ingested. When an event carries an indicator
// (today: source/destination IPs) that matches a stored IOC, a `threat_match`
// is stamped onto the event before it reaches the detection engine and the
// pipeline. This is the low-latency (<100ms) path; the analytical path is a
// query-time JOIN against the `threat_intel` Iceberg table (deferred).
//
// KV layout: one key per indicator, `ioc:<indicator_type>:<indicator>`. The
// value is the full IocRecord as JSON; the same descriptive fields are mirrored
// into KV metadata so `listIocs` can render rows without a GET per key.

import type { IndicatorType, OcsfEvent, OcsfThreatMatch } from "./index.js";

export type { IndicatorType } from "./index.js";

export interface IocRecord {
  indicator: string;
  indicator_type: IndicatorType;
  feed_name?: string;
  threat_type?: string;
  // ISO-8601 timestamp of when the IOC was loaded. Optional on input.
  added_at?: string;
}

// Descriptive fields stored alongside the key so `listIocs` avoids a GET per IOC.
export interface IocMetadata {
  feed_name?: string;
  threat_type?: string;
  added_at?: string;
}

// Minimal structural subset of Cloudflare's KVNamespace — enough to store and
// look up IOCs, and trivially fakeable in tests. The Worker's bound
// `KVNamespace` satisfies this shape.
export interface IocKvNamespace {
  get(key: string): Promise<string | null>;
  put(
    key: string,
    value: string,
    options?: { metadata?: IocMetadata; expirationTtl?: number }
  ): Promise<void>;
  delete(key: string): Promise<void>;
  list(options?: {
    prefix?: string;
    cursor?: string;
    limit?: number;
  }): Promise<{
    keys: { name: string; metadata?: IocMetadata }[];
    list_complete: boolean;
    cursor?: string;
  }>;
}

export const IOC_KEY_PREFIX = "ioc:";

export const INDICATOR_TYPES: readonly IndicatorType[] = ["ipv4", "ipv6", "domain", "url", "sha256"];

export function isIndicatorType(value: unknown): value is IndicatorType {
  return typeof value === "string" && (INDICATOR_TYPES as readonly string[]).includes(value);
}

// Indicators are case-folded so lookups are stable: domains/URLs/hashes are
// lowercased; IPs are already canonical-enough for an exact-string match.
export function normalizeIndicator(indicatorType: IndicatorType, indicator: string): string {
  const trimmed = indicator.trim();
  return indicatorType === "ipv4" ? trimmed : trimmed.toLowerCase();
}

export function iocKey(indicatorType: IndicatorType, indicator: string): string {
  return `${IOC_KEY_PREFIX}${indicatorType}:${normalizeIndicator(indicatorType, indicator)}`;
}

export async function putIoc(kv: IocKvNamespace, ioc: IocRecord): Promise<IocRecord> {
  const indicator = normalizeIndicator(ioc.indicator_type, ioc.indicator);
  const record: IocRecord = {
    indicator,
    indicator_type: ioc.indicator_type,
    ...(ioc.feed_name ? { feed_name: ioc.feed_name } : {}),
    ...(ioc.threat_type ? { threat_type: ioc.threat_type } : {}),
    ...(ioc.added_at ? { added_at: ioc.added_at } : {})
  };
  await kv.put(iocKey(ioc.indicator_type, indicator), JSON.stringify(record), {
    metadata: {
      ...(record.feed_name ? { feed_name: record.feed_name } : {}),
      ...(record.threat_type ? { threat_type: record.threat_type } : {}),
      ...(record.added_at ? { added_at: record.added_at } : {})
    }
  });
  return record;
}

// Best-effort bulk load. Returns the number of IOCs written.
export async function putIocs(kv: IocKvNamespace, iocs: readonly IocRecord[]): Promise<number> {
  let written = 0;
  for (const ioc of iocs) {
    await putIoc(kv, ioc);
    written++;
  }
  return written;
}

export async function getIoc(
  kv: IocKvNamespace,
  indicatorType: IndicatorType,
  indicator: string
): Promise<IocRecord | null> {
  const raw = await kv.get(iocKey(indicatorType, indicator));
  if (raw === null) return null;
  return parseIocRecord(raw, indicatorType, normalizeIndicator(indicatorType, indicator));
}

// Returns false when the IOC wasn't present, true when a delete was issued.
export async function deleteIoc(
  kv: IocKvNamespace,
  indicatorType: IndicatorType,
  indicator: string
): Promise<boolean> {
  const key = iocKey(indicatorType, indicator);
  const existing = await kv.get(key);
  if (existing === null) return false;
  await kv.delete(key);
  return true;
}

export interface ListIocsOptions {
  indicator_type?: IndicatorType;
  limit?: number;
}

// Lists IOCs from key names + metadata (no GET per key). KV list is paginated;
// we follow cursors up to `limit` (default 1000).
export async function listIocs(kv: IocKvNamespace, options: ListIocsOptions = {}): Promise<IocRecord[]> {
  const limit = options.limit ?? 1000;
  const prefix = options.indicator_type
    ? `${IOC_KEY_PREFIX}${options.indicator_type}:`
    : IOC_KEY_PREFIX;

  const records: IocRecord[] = [];
  let cursor: string | undefined;
  do {
    const page = await kv.list({ prefix, cursor, limit: Math.min(1000, limit - records.length) });
    for (const key of page.keys) {
      const parsed = parseKeyName(key.name);
      if (!parsed) continue;
      const meta = key.metadata ?? {};
      records.push({
        indicator: parsed.indicator,
        indicator_type: parsed.indicator_type,
        ...(meta.feed_name ? { feed_name: meta.feed_name } : {}),
        ...(meta.threat_type ? { threat_type: meta.threat_type } : {}),
        ...(meta.added_at ? { added_at: meta.added_at } : {})
      });
      if (records.length >= limit) return records;
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  return records;
}

// A candidate indicator extracted from an event field, paired with the
// flattened field name it came from (recorded on the match for triage).
interface Candidate {
  indicator_type: IndicatorType;
  indicator: string;
  matched_field: string;
}

function candidateIndicators(event: OcsfEvent): Candidate[] {
  const out: Candidate[] = [];
  pushIp(out, event.src_endpoint?.ip, "src_endpoint_ip");
  pushIp(out, event.dst_endpoint?.ip, "dst_endpoint_ip");
  return out;
}

function pushIp(out: Candidate[], ip: string | undefined, field: string): void {
  if (!ip) return;
  out.push({ indicator_type: ip.includes(":") ? "ipv6" : "ipv4", indicator: ip, matched_field: field });
}

export interface EnrichResult {
  events: OcsfEvent[];
  // Number of events that received a threat_match this batch.
  match_count: number;
}

// Stamps `threat_match` onto each event whose indicators hit the KV store.
// Mutates events in place (and returns them) so the same array flows on to the
// detection worker and the pipeline. Indicators are deduped across the batch so
// a repeated IP is looked up once. The first matching field on an event wins.
export async function enrichEvents(events: OcsfEvent[], kv: IocKvNamespace): Promise<EnrichResult> {
  if (events.length === 0) return { events, match_count: 0 };

  // Collect unique candidate keys across the whole batch.
  const lookups = new Map<string, Candidate>();
  for (const event of events) {
    for (const candidate of candidateIndicators(event)) {
      lookups.set(iocKey(candidate.indicator_type, candidate.indicator), candidate);
    }
  }
  if (lookups.size === 0) return { events, match_count: 0 };

  const hits = new Map<string, IocRecord>();
  await Promise.all(
    [...lookups.entries()].map(async ([key, candidate]) => {
      const record = await getIoc(kv, candidate.indicator_type, candidate.indicator);
      if (record) hits.set(key, record);
    })
  );
  if (hits.size === 0) return { events, match_count: 0 };

  let match_count = 0;
  for (const event of events) {
    if (event.threat_match) continue;
    for (const candidate of candidateIndicators(event)) {
      const record = hits.get(iocKey(candidate.indicator_type, candidate.indicator));
      if (!record) continue;
      event.threat_match = toThreatMatch(record, candidate.matched_field);
      match_count++;
      break;
    }
  }
  return { events, match_count };
}

function toThreatMatch(record: IocRecord, matchedField: string): OcsfThreatMatch {
  return {
    indicator: record.indicator,
    indicator_type: record.indicator_type,
    matched_field: matchedField,
    ...(record.feed_name ? { feed_name: record.feed_name } : {}),
    ...(record.threat_type ? { threat_type: record.threat_type } : {})
  };
}

function parseIocRecord(raw: string, fallbackType: IndicatorType, fallbackIndicator: string): IocRecord {
  try {
    const parsed = JSON.parse(raw) as Partial<IocRecord>;
    return {
      indicator: typeof parsed.indicator === "string" ? parsed.indicator : fallbackIndicator,
      indicator_type: isIndicatorType(parsed.indicator_type) ? parsed.indicator_type : fallbackType,
      ...(typeof parsed.feed_name === "string" ? { feed_name: parsed.feed_name } : {}),
      ...(typeof parsed.threat_type === "string" ? { threat_type: parsed.threat_type } : {}),
      ...(typeof parsed.added_at === "string" ? { added_at: parsed.added_at } : {})
    };
  } catch {
    return { indicator: fallbackIndicator, indicator_type: fallbackType };
  }
}

// `ioc:<type>:<indicator>` — the indicator may itself contain ":" (ipv6), so
// split only on the first two delimiters.
function parseKeyName(name: string): { indicator_type: IndicatorType; indicator: string } | null {
  if (!name.startsWith(IOC_KEY_PREFIX)) return null;
  const rest = name.slice(IOC_KEY_PREFIX.length);
  const sep = rest.indexOf(":");
  if (sep === -1) return null;
  const indicatorType = rest.slice(0, sep);
  const indicator = rest.slice(sep + 1);
  if (!isIndicatorType(indicatorType) || indicator.length === 0) return null;
  return { indicator_type: indicatorType, indicator };
}

export function formatIocTable(records: readonly IocRecord[]): string {
  if (records.length === 0) return "No IOCs loaded.";
  const header = ["TYPE", "INDICATOR", "FEED", "THREAT TYPE"];
  const rows = records.map((r) => [
    r.indicator_type,
    r.indicator,
    r.feed_name ?? "-",
    r.threat_type ?? "-"
  ]);
  const widths = header.map((h, i) => Math.max(h.length, ...rows.map((row) => (row[i] ?? "").length)));
  const line = (cols: string[]) => cols.map((c, i) => c.padEnd(widths[i] ?? 0)).join("  ").trimEnd();
  return [line(header), ...rows.map(line)].join("\n");
}
