import type { Hono } from "hono";

import {
  deleteIoc,
  getIoc,
  isIndicatorType,
  listIocs,
  putIoc,
  type IndicatorType,
  type IocRecord
} from "@picket/core/enrichment";

import type { AdminEnv } from "./index";

// Enrichment routes (Milestone 4): manage the threat-intel IOCs synced into the
// enrichment KV namespace, which the ingest Worker looks up to stamp events.
// All routes 503 when ENRICHMENT_KV is unbound rather than throwing.
export function registerEnrichmentRoutes(app: Hono<{ Bindings: AdminEnv }>): void {
  app.get("/api/v1/enrichment/feeds", async (c) => {
    const kv = c.env.ENRICHMENT_KV;
    if (!kv) return c.json({ error: "Enrichment KV is not configured." }, 503);

    const iocs = await listIocs(kv);
    const feeds = new Map<string, { name: string; type: string; indicator_count: number; last_updated: string | null }>();
    for (const ioc of iocs) {
      const name = ioc.feed_name ?? "manual";
      const existing = feeds.get(name) ?? { name, type: "ioc", indicator_count: 0, last_updated: null };
      existing.indicator_count += 1;
      if (ioc.added_at && (!existing.last_updated || ioc.added_at > existing.last_updated)) existing.last_updated = ioc.added_at;
      feeds.set(name, existing);
    }
    return c.json({ feeds: [...feeds.values()].sort((left, right) => left.name.localeCompare(right.name)) });
  });

  app.post("/api/v1/enrichment/feeds", async (c) => {
    const kv = c.env.ENRICHMENT_KV;
    if (!kv) return c.json({ error: "Enrichment KV is not configured." }, 503);

    const body = await readJsonBody(c.req.raw.clone());
    const parsed = parseFeedInput(body);
    if ("error" in parsed) return c.json({ error: parsed.error }, 400);

    const loadedAt = new Date().toISOString();
    const records: IocRecord[] = [];
    for (const ioc of parsed.iocs) {
      records.push(await putIoc(kv, { ...ioc, feed_name: ioc.feed_name ?? parsed.name, added_at: ioc.added_at ?? loadedAt }));
    }
    await safelyAppendRows(
      c.env.THREAT_INTEL_PIPELINE,
      records.map((ioc) => threatIntelRow(ioc, true, loadedAt)),
      "threat_intel"
    );
    return c.json({ feed: { name: parsed.name, type: parsed.type, indicator_count: records.length, last_updated: loadedAt } }, 201);
  });

  app.get("/api/v1/enrichment/iocs", async (c) => {
    const kv = c.env.ENRICHMENT_KV;
    if (!kv) return c.json({ error: "Enrichment KV is not configured." }, 503);

    const url = new URL(c.req.url);
    const typeParam = url.searchParams.get("type");
    if (typeParam !== null && !isIndicatorType(typeParam)) {
      return c.json({ error: `Invalid indicator type: ${typeParam}` }, 400);
    }
    const limit = parsePositiveInt(url.searchParams.get("limit"));
    if (limit === "invalid") return c.json({ error: "limit must be a positive integer." }, 400);

    const iocs = await listIocs(kv, {
      ...(typeParam ? { indicator_type: typeParam } : {}),
      ...(limit !== undefined ? { limit } : {})
    });
    return c.json({ iocs });
  });

  app.post("/api/v1/enrichment/iocs", async (c) => {
    const kv = c.env.ENRICHMENT_KV;
    if (!kv) return c.json({ error: "Enrichment KV is not configured." }, 503);

    const body = await readJsonBody(c.req.raw.clone());
    const raw = Array.isArray(body?.iocs) ? body.iocs : body ? [body] : [];
    if (raw.length === 0) {
      return c.json({ error: "Provide an IOC object or an `iocs` array." }, 400);
    }

    const iocs: IocRecord[] = [];
    for (const [i, entry] of raw.entries()) {
      const parsed = parseIocInput(entry);
      if ("error" in parsed) return c.json({ error: `iocs[${i}]: ${parsed.error}` }, 400);
      iocs.push(parsed.ioc);
    }

    const loadedAt = new Date().toISOString();
    const records: IocRecord[] = [];
    for (const ioc of iocs) {
      records.push(await putIoc(kv, { ...ioc, added_at: ioc.added_at ?? loadedAt }));
    }

    await safelyAppendRows(
      c.env.THREAT_INTEL_PIPELINE,
      records.map((ioc) => threatIntelRow(ioc, true, loadedAt)),
      "threat_intel"
    );
    return c.json({ written: records.length }, 201);
  });

  app.post("/api/v1/enrichment/iocs/import", async (c) => {
    const kv = c.env.ENRICHMENT_KV;
    if (!kv) return c.json({ error: "Enrichment KV is not configured." }, 503);

    const url = new URL(c.req.url);
    const defaults = {
      feed_name: url.searchParams.get("feed") ?? undefined,
      threat_type: url.searchParams.get("threat_type") ?? undefined
    };
    const parsed = parseIocCsv(await c.req.text(), defaults);
    if ("error" in parsed) return c.json({ error: parsed.error }, 400);
    if (parsed.iocs.length === 0) return c.json({ error: "CSV did not contain any IOC rows." }, 400);

    const loadedAt = new Date().toISOString();
    const records: IocRecord[] = [];
    for (const ioc of parsed.iocs) {
      records.push(await putIoc(kv, { ...ioc, added_at: ioc.added_at ?? loadedAt }));
    }

    await safelyAppendRows(
      c.env.THREAT_INTEL_PIPELINE,
      records.map((ioc) => threatIntelRow(ioc, true, loadedAt)),
      "threat_intel"
    );
    return c.json({ written: records.length }, 201);
  });

  app.post("/api/v1/enrichment/iocs/check", async (c) => {
    const kv = c.env.ENRICHMENT_KV;
    if (!kv) return c.json({ error: "Enrichment KV is not configured." }, 503);

    const body = await readJsonBody(c.req.raw.clone());
    const raw = Array.isArray(body?.indicators) ? body.indicators : body ? [body] : [];
    if (raw.length === 0) return c.json({ error: "Provide an indicator object or an `indicators` array." }, 400);

    const results: Array<{ indicator: string; indicator_type: IndicatorType; matched: boolean; ioc: IocRecord | null }> = [];
    for (const [i, entry] of raw.entries()) {
      const parsed = parseIndicatorInput(entry);
      if ("error" in parsed) return c.json({ error: `indicators[${i}]: ${parsed.error}` }, 400);
      const ioc = await getIoc(kv, parsed.indicator_type, parsed.indicator);
      results.push({
        indicator: parsed.indicator,
        indicator_type: parsed.indicator_type,
        matched: ioc !== null,
        ioc
      });
    }
    return c.json({ results, match_count: results.filter((result) => result.matched).length });
  });

  app.delete("/api/v1/enrichment/iocs/:type/:indicator", async (c) => {
    const kv = c.env.ENRICHMENT_KV;
    if (!kv) return c.json({ error: "Enrichment KV is not configured." }, 503);

    const type = c.req.param("type");
    if (!isIndicatorType(type)) return c.json({ error: `Invalid indicator type: ${type}` }, 400);
    const indicator = decodeURIComponent(c.req.param("indicator"));

    const existing = await getIoc(kv, type, indicator);
    const removed = await deleteIoc(kv, type, indicator);
    if (!removed) return c.json({ error: `IOC not found: ${type}/${indicator}` }, 404);
    const loadedAt = new Date().toISOString();
    await safelyAppendRows(
      c.env.THREAT_INTEL_PIPELINE,
      [threatIntelRow(existing ?? { indicator, indicator_type: type }, false, loadedAt)],
      "threat_intel"
    );
    return c.json({ deleted: true });
  });

  app.post("/api/v1/enrichment/assets", async (c) => {
    if (!c.env.ASSETS_PIPELINE) return c.json({ error: "Assets Pipeline is not configured." }, 503);
    const body = await readJsonBody(c.req.raw.clone());
    const raw = Array.isArray(body?.assets) ? body.assets : body ? [body] : [];
    if (raw.length === 0) return c.json({ error: "Provide an asset object or an `assets` array." }, 400);

    const loadedAt = new Date().toISOString();
    const rows: AssetPipelineRow[] = [];
    for (const [i, entry] of raw.entries()) {
      const parsed = parseAssetInput(entry, loadedAt);
      if ("error" in parsed) return c.json({ error: `assets[${i}]: ${parsed.error}` }, 400);
      rows.push(parsed.row);
    }
    await safelyAppendRows(c.env.ASSETS_PIPELINE, rows, "assets");
    return c.json({ written: rows.length }, 201);
  });

  app.post("/api/v1/enrichment/users", async (c) => {
    if (!c.env.USERS_PIPELINE) return c.json({ error: "Users Pipeline is not configured." }, 503);
    const body = await readJsonBody(c.req.raw.clone());
    const raw = Array.isArray(body?.users) ? body.users : body ? [body] : [];
    if (raw.length === 0) return c.json({ error: "Provide a user object or a `users` array." }, 400);

    const loadedAt = new Date().toISOString();
    const rows: UserPipelineRow[] = [];
    for (const [i, entry] of raw.entries()) {
      const parsed = parseUserInput(entry, loadedAt);
      if ("error" in parsed) return c.json({ error: `users[${i}]: ${parsed.error}` }, 400);
      rows.push(parsed.row);
    }
    await safelyAppendRows(c.env.USERS_PIPELINE, rows, "users");
    return c.json({ written: rows.length }, 201);
  });
}

interface ThreatIntelPipelineRow {
  [key: string]: unknown;
  indicator: string;
  indicator_type: IndicatorType;
  feed_name?: string;
  threat_type?: string;
  active: boolean;
  added_at: string;
  loaded_at: string;
}

interface AssetPipelineRow {
  [key: string]: unknown;
  asset_uid: string;
  hostname?: string;
  ip?: string;
  owner?: string;
  department?: string;
  criticality?: string;
  active: boolean;
  loaded_at: string;
}

interface UserPipelineRow {
  [key: string]: unknown;
  user_uid: string;
  user_name?: string;
  user_email?: string;
  department?: string;
  title?: string;
  criticality?: string;
  active: boolean;
  loaded_at: string;
}

function threatIntelRow(ioc: IocRecord, active: boolean, loadedAt: string): ThreatIntelPipelineRow {
  return {
    indicator: ioc.indicator,
    indicator_type: ioc.indicator_type,
    ...(ioc.feed_name ? { feed_name: ioc.feed_name } : {}),
    ...(ioc.threat_type ? { threat_type: ioc.threat_type } : {}),
    active,
    added_at: ioc.added_at ?? loadedAt,
    loaded_at: loadedAt
  };
}

async function safelyAppendRows(
  pipeline: AdminEnv["THREAT_INTEL_PIPELINE"] | undefined,
  rows: Record<string, unknown>[],
  table: string
): Promise<void> {
  if (!pipeline || rows.length === 0) return;
  try {
    await pipeline.send(rows);
  } catch (error) {
    console.error(JSON.stringify({ message: `${table} pipeline write failed`, error: errorMessage(error) }));
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

type IocInput = { indicator?: unknown; indicator_type?: unknown; feed_name?: unknown; threat_type?: unknown; added_at?: unknown };

type FeedInput = { name?: unknown; type?: unknown; iocs?: unknown };

function parseFeedInput(value: unknown): { name: string; type: string; iocs: IocRecord[] } | { error: string } {
  if (!value || typeof value !== "object" || Array.isArray(value)) return { error: "Request body must be an object." };
  const input = value as FeedInput;
  if (typeof input.name !== "string" || input.name.trim().length === 0) return { error: "`name` is required." };
  const rawIocs = Array.isArray(input.iocs) ? input.iocs : [];
  if (rawIocs.length === 0) return { error: "`iocs` must contain at least one IOC." };
  const iocs: IocRecord[] = [];
  for (const [i, entry] of rawIocs.entries()) {
    const parsed = parseIocInput(entry);
    if ("error" in parsed) return { error: `iocs[${i}]: ${parsed.error}` };
    iocs.push(parsed.ioc);
  }
  return { name: input.name.trim(), type: typeof input.type === "string" && input.type.trim() ? input.type.trim() : "csv", iocs };
}

function parseIndicatorInput(entry: unknown): { indicator: string; indicator_type: IndicatorType } | { error: string } {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return { error: "must be an object" };
  const value = entry as { indicator?: unknown; indicator_type?: unknown };
  if (typeof value.indicator !== "string" || value.indicator.trim().length === 0) {
    return { error: "`indicator` (non-empty string) is required" };
  }
  if (!isIndicatorType(value.indicator_type)) {
    return { error: "`indicator_type` must be one of ipv4, ipv6, domain, url, sha256" };
  }
  return { indicator: value.indicator, indicator_type: value.indicator_type };
}

function parseIocInput(entry: unknown): { ioc: IocRecord } | { error: string } {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    return { error: "must be an object" };
  }
  const value = entry as IocInput;
  if (typeof value.indicator !== "string" || value.indicator.trim().length === 0) {
    return { error: "`indicator` (non-empty string) is required" };
  }
  if (!isIndicatorType(value.indicator_type)) {
    return { error: "`indicator_type` must be one of ipv4, ipv6, domain, url, sha256" };
  }
  if (value.feed_name !== undefined && typeof value.feed_name !== "string") {
    return { error: "`feed_name` must be a string when present" };
  }
  if (value.threat_type !== undefined && typeof value.threat_type !== "string") {
    return { error: "`threat_type` must be a string when present" };
  }
  if (value.added_at !== undefined && typeof value.added_at !== "string") {
    return { error: "`added_at` must be a string when present" };
  }
  const ioc: IocRecord = {
    indicator: value.indicator,
    indicator_type: value.indicator_type as IndicatorType,
    ...(value.feed_name ? { feed_name: value.feed_name } : {}),
    ...(value.threat_type ? { threat_type: value.threat_type } : {}),
    ...(value.added_at ? { added_at: value.added_at } : {})
  };
  return { ioc };
}

type AssetInput = {
  asset_uid?: unknown;
  hostname?: unknown;
  ip?: unknown;
  owner?: unknown;
  department?: unknown;
  criticality?: unknown;
  active?: unknown;
};

function parseAssetInput(entry: unknown, loadedAt: string): { row: AssetPipelineRow } | { error: string } {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return { error: "must be an object" };
  const value = entry as AssetInput;
  if (typeof value.asset_uid !== "string" || value.asset_uid.trim().length === 0) {
    return { error: "`asset_uid` (non-empty string) is required" };
  }
  const strings = optionalStrings(value as Record<string, unknown>, ["hostname", "ip", "owner", "department", "criticality"]);
  if ("error" in strings) return strings;
  if (value.active !== undefined && typeof value.active !== "boolean") return { error: "`active` must be a boolean" };
  return { row: { asset_uid: value.asset_uid.trim(), ...strings.values, active: value.active ?? true, loaded_at: loadedAt } };
}

type UserInput = {
  user_uid?: unknown;
  user_name?: unknown;
  user_email?: unknown;
  department?: unknown;
  title?: unknown;
  criticality?: unknown;
  active?: unknown;
};

function parseUserInput(entry: unknown, loadedAt: string): { row: UserPipelineRow } | { error: string } {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return { error: "must be an object" };
  const value = entry as UserInput;
  if (typeof value.user_uid !== "string" || value.user_uid.trim().length === 0) {
    return { error: "`user_uid` (non-empty string) is required" };
  }
  const strings = optionalStrings(value as Record<string, unknown>, ["user_name", "user_email", "department", "title", "criticality"]);
  if ("error" in strings) return strings;
  if (value.active !== undefined && typeof value.active !== "boolean") return { error: "`active` must be a boolean" };
  return { row: { user_uid: value.user_uid.trim(), ...strings.values, active: value.active ?? true, loaded_at: loadedAt } };
}

function optionalStrings(
  value: Record<string, unknown>,
  keys: readonly string[]
): { values: Record<string, string> } | { error: string } {
  const values: Record<string, string> = {};
  for (const key of keys) {
    const raw = value[key];
    if (raw === undefined || raw === "") continue;
    if (typeof raw !== "string") return { error: `\`${key}\` must be a string when present` };
    values[key] = raw;
  }
  return { values };
}

function parseIocCsv(
  text: string,
  defaults: { feed_name?: string; threat_type?: string }
): { iocs: IocRecord[] } | { error: string } {
  const rows = parseCsv(text);
  if ("error" in rows) return rows;
  if (rows.rows.length === 0) return { iocs: [] };
  const [header, ...data] = rows.rows;
  if (!header) return { iocs: [] };
  const columns = header.map((h) => h.trim());
  const indicatorIndex = columns.indexOf("indicator");
  const typeIndex = columns.indexOf("indicator_type");
  if (indicatorIndex === -1 || typeIndex === -1) {
    return { error: "CSV header must include indicator and indicator_type columns." };
  }

  const iocs: IocRecord[] = [];
  for (const [rowIndex, row] of data.entries()) {
    if (row.every((cell) => cell.trim() === "")) continue;
    const entry: IocInput = {
      indicator: row[indicatorIndex],
      indicator_type: row[typeIndex],
      feed_name: cell(row, columns, "feed_name") ?? defaults.feed_name,
      threat_type: cell(row, columns, "threat_type") ?? defaults.threat_type,
      added_at: cell(row, columns, "added_at")
    };
    const parsed = parseIocInput(entry);
    if ("error" in parsed) return { error: `CSV row ${rowIndex + 2}: ${parsed.error}` };
    iocs.push(parsed.ioc);
  }
  return { iocs };
}

function cell(row: readonly string[], columns: readonly string[], name: string): string | undefined {
  const index = columns.indexOf(name);
  const value = index === -1 ? undefined : row[index]?.trim();
  return value ? value : undefined;
}

function parseCsv(text: string): { rows: string[][] } | { error: string } {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"' && text[i + 1] === '"') {
        field += '"';
        i += 1;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (ch !== "\r") {
      field += ch;
    }
  }
  if (inQuotes) return { error: "CSV has an unterminated quoted field." };
  row.push(field);
  if (row.length > 1 || row[0] !== "" || rows.length === 0) rows.push(row);
  return { rows };
}

function parsePositiveInt(value: string | null): number | undefined | "invalid" {
  if (value === null) return undefined;
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) return "invalid";
  return n;
}

async function readJsonBody(request: Request): Promise<({ iocs?: unknown; indicators?: unknown; assets?: unknown; users?: unknown; name?: unknown; type?: unknown } & IocInput) | null> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) return null;
  try {
    const parsed = (await request.json()) as unknown;
    if (parsed && typeof parsed === "object") return parsed as { iocs?: unknown; indicators?: unknown; assets?: unknown; users?: unknown; name?: unknown; type?: unknown } & IocInput;
    return null;
  } catch {
    return null;
  }
}
