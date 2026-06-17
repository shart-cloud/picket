import { describe, expect, it } from "vitest";

import type { OcsfEvent } from "./index.js";
import {
  deleteIoc,
  enrichEvents,
  formatIocTable,
  getIoc,
  iocKey,
  listIocs,
  normalizeIndicator,
  putIoc,
  putIocs,
  type IocKvNamespace,
  type IocMetadata,
  type IocRecord
} from "./enrichment.js";

// In-memory KV fake mirroring the structural subset enrichment.ts depends on,
// including metadata round-tripping and prefix/cursor-paginated list.
function fakeKv(): IocKvNamespace & { store: Map<string, { value: string; metadata?: IocMetadata }> } {
  const store = new Map<string, { value: string; metadata?: IocMetadata }>();
  return {
    store,
    async get(key) {
      return store.get(key)?.value ?? null;
    },
    async put(key, value, options) {
      store.set(key, { value, metadata: options?.metadata });
    },
    async delete(key) {
      store.delete(key);
    },
    async list(options) {
      const prefix = options?.prefix ?? "";
      const all = [...store.entries()]
        .filter(([name]) => name.startsWith(prefix))
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      const start = options?.cursor ? Number(options.cursor) : 0;
      const limit = options?.limit ?? 1000;
      const page = all.slice(start, start + limit);
      const next = start + limit;
      const complete = next >= all.length;
      return {
        keys: page.map(([name, entry]) => ({ name, metadata: entry.metadata })),
        list_complete: complete,
        ...(complete ? {} : { cursor: String(next) })
      };
    }
  };
}

const baseEvent: OcsfEvent = {
  time: "2026-06-10T12:00:00Z",
  source: "aws_cloudtrail",
  category: "identity_access",
  class_name: "authentication",
  activity_name: "ConsoleLogin",
  status: "success",
  src_endpoint: { ip: "9.9.9.9" },
  metadata: { product_name: "AWS CloudTrail", raw_event: {} }
};

describe("iocKey / normalizeIndicator", () => {
  it("lowercases domains but leaves ipv4 as-is", () => {
    expect(normalizeIndicator("domain", "EVIL.Example.COM")).toBe("evil.example.com");
    expect(normalizeIndicator("ipv4", "1.2.3.4")).toBe("1.2.3.4");
    expect(iocKey("ipv4", "1.2.3.4")).toBe("ioc:ipv4:1.2.3.4");
    expect(iocKey("domain", "EVIL.com")).toBe("ioc:domain:evil.com");
  });
});

describe("putIoc / getIoc / deleteIoc", () => {
  it("round-trips an IOC with descriptive fields", async () => {
    const kv = fakeKv();
    await putIoc(kv, { indicator: "1.2.3.4", indicator_type: "ipv4", feed_name: "abuse.ch", threat_type: "c2" });
    const got = await getIoc(kv, "ipv4", "1.2.3.4");
    expect(got).toEqual({ indicator: "1.2.3.4", indicator_type: "ipv4", feed_name: "abuse.ch", threat_type: "c2" });
  });

  it("returns null for an absent IOC", async () => {
    const kv = fakeKv();
    expect(await getIoc(kv, "ipv4", "1.2.3.4")).toBeNull();
  });

  it("deleteIoc reports whether the IOC existed", async () => {
    const kv = fakeKv();
    await putIoc(kv, { indicator: "1.2.3.4", indicator_type: "ipv4" });
    expect(await deleteIoc(kv, "ipv4", "1.2.3.4")).toBe(true);
    expect(await deleteIoc(kv, "ipv4", "1.2.3.4")).toBe(false);
    expect(await getIoc(kv, "ipv4", "1.2.3.4")).toBeNull();
  });
});

describe("listIocs", () => {
  it("lists from key names + metadata across pages, filtered by type", async () => {
    const kv = fakeKv();
    await putIocs(kv, [
      { indicator: "1.1.1.1", indicator_type: "ipv4", feed_name: "f1" },
      { indicator: "2.2.2.2", indicator_type: "ipv4", threat_type: "scanner" },
      { indicator: "evil.com", indicator_type: "domain", feed_name: "f2" }
    ]);

    const ipv4 = await listIocs(kv, { indicator_type: "ipv4" });
    expect(ipv4).toHaveLength(2);
    expect(ipv4.map((r) => r.indicator).sort()).toEqual(["1.1.1.1", "2.2.2.2"]);
    expect(ipv4.find((r) => r.indicator === "1.1.1.1")?.feed_name).toBe("f1");

    const all = await listIocs(kv);
    expect(all).toHaveLength(3);
  });

  it("respects limit", async () => {
    const kv = fakeKv();
    await putIocs(kv, [
      { indicator: "1.1.1.1", indicator_type: "ipv4" },
      { indicator: "2.2.2.2", indicator_type: "ipv4" },
      { indicator: "3.3.3.3", indicator_type: "ipv4" }
    ]);
    expect(await listIocs(kv, { limit: 2 })).toHaveLength(2);
  });
});

describe("enrichEvents", () => {
  it("stamps threat_match on the matching event and field", async () => {
    const kv = fakeKv();
    await putIoc(kv, { indicator: "6.6.6.6", indicator_type: "ipv4", feed_name: "abuse.ch", threat_type: "c2" });

    const hit: OcsfEvent = { ...baseEvent, src_endpoint: { ip: "6.6.6.6" } };
    const miss: OcsfEvent = { ...baseEvent, src_endpoint: { ip: "9.9.9.9" } };
    const result = await enrichEvents([hit, miss], kv);

    expect(result.match_count).toBe(1);
    expect(hit.threat_match).toEqual({
      indicator: "6.6.6.6",
      indicator_type: "ipv4",
      matched_field: "src_endpoint_ip",
      feed_name: "abuse.ch",
      threat_type: "c2"
    });
    expect(miss.threat_match).toBeUndefined();
  });

  it("matches on dst_endpoint and records the field", async () => {
    const kv = fakeKv();
    await putIoc(kv, { indicator: "7.7.7.7", indicator_type: "ipv4" });
    const event: OcsfEvent = { ...baseEvent, src_endpoint: undefined, dst_endpoint: { ip: "7.7.7.7" } };
    await enrichEvents([event], kv);
    expect(event.threat_match?.matched_field).toBe("dst_endpoint_ip");
  });

  it("deduplicates lookups for a repeated indicator", async () => {
    const kv = fakeKv();
    await putIoc(kv, { indicator: "6.6.6.6", indicator_type: "ipv4" });
    let gets = 0;
    const counting: IocKvNamespace = { ...kv, get: (k) => { gets++; return kv.get(k); } };

    const a: OcsfEvent = { ...baseEvent, src_endpoint: { ip: "6.6.6.6" } };
    const b: OcsfEvent = { ...baseEvent, src_endpoint: { ip: "6.6.6.6" } };
    const result = await enrichEvents([a, b], counting);

    expect(result.match_count).toBe(2);
    expect(gets).toBe(1);
  });

  it("no-ops on an empty batch or events without indicators", async () => {
    const kv = fakeKv();
    expect((await enrichEvents([], kv)).match_count).toBe(0);
    const noIp: OcsfEvent = { ...baseEvent, src_endpoint: undefined };
    expect((await enrichEvents([noIp], kv)).match_count).toBe(0);
    expect(noIp.threat_match).toBeUndefined();
  });
});

describe("formatIocTable", () => {
  it("renders a header and rows", () => {
    const rows: IocRecord[] = [
      { indicator: "1.1.1.1", indicator_type: "ipv4", feed_name: "abuse.ch", threat_type: "c2" }
    ];
    const out = formatIocTable(rows);
    expect(out).toContain("INDICATOR");
    expect(out).toContain("1.1.1.1");
    expect(out).toContain("abuse.ch");
  });

  it("handles an empty list", () => {
    expect(formatIocTable([])).toBe("No IOCs loaded.");
  });
});
