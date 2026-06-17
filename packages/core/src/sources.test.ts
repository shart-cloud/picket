import { describe, expect, it } from "vitest";

import {
  applyTableSuffix,
  formatOcsfSchema,
  isKnownSource,
  OCSF_EVENT_FIELDS,
  ocsfSchemaForSource,
  SAMPLE_LIMIT,
  sampleQuery,
  sampleTableName
} from "./sources.js";

describe("sources helpers", () => {
  it("recognizes the OCSF source ids", () => {
    expect(isKnownSource("aws_cloudtrail")).toBe(true);
    expect(isKnownSource("aws_vpc_flow")).toBe(true);
    expect(isKnownSource("kubernetes_audit")).toBe(true);
    expect(isKnownSource("not_a_source")).toBe(false);
  });

  it("exposes a field schema mirroring the flattened OCSF event", () => {
    const schema = ocsfSchemaForSource("aws_cloudtrail");
    expect(schema.source).toBe("aws_cloudtrail");
    expect(schema.field_count).toBe(OCSF_EVENT_FIELDS.length);
    const names = schema.fields.map((field) => field.name);
    expect(names).toContain("time");
    expect(names).toContain("actor_user_uid");
    expect(names).toContain("src_endpoint_ip");
    expect(names).toContain("metadata_raw_event");
    // time is a timestamp; raw event is json; the rest are strings.
    expect(schema.fields.find((f) => f.name === "time")?.type).toBe("timestamp");
    expect(schema.fields.find((f) => f.name === "metadata_raw_event")?.type).toBe("json");
  });

  it("builds the source table name with and without a suffix", () => {
    expect(sampleTableName("aws_cloudtrail")).toBe("aws_cloudtrail");
    expect(sampleTableName("aws_cloudtrail", "pure_alien")).toBe("aws_cloudtrail_pure_alien");
    expect(sampleTableName("aws_cloudtrail", null)).toBe("aws_cloudtrail");
  });

  it("generates a recent-events sample query", () => {
    expect(sampleQuery("aws_cloudtrail", "pure_alien")).toBe(
      `SELECT * FROM aws_cloudtrail_pure_alien ORDER BY time DESC LIMIT ${SAMPLE_LIMIT}`
    );
    expect(sampleQuery("kubernetes_audit")).toBe(
      "SELECT * FROM kubernetes_audit ORDER BY time DESC LIMIT 10"
    );
  });

  it("rewrites FROM/JOIN tables with the deployed suffix", () => {
    const sql = "SELECT * FROM aws_cloudtrail e JOIN threat_intel ti ON e.src_endpoint_ip = ti.indicator";
    const out = applyTableSuffix(sql, "pure_alien");
    expect(out).toContain("FROM aws_cloudtrail_pure_alien");
    expect(out).toContain("JOIN threat_intel_pure_alien");
    // Aliases and columns are untouched.
    expect(out).toContain("e.src_endpoint_ip");
  });

  it("is a no-op without a suffix or for unknown tables", () => {
    expect(applyTableSuffix("SELECT * FROM aws_cloudtrail", null)).toBe("SELECT * FROM aws_cloudtrail");
    expect(applyTableSuffix("SELECT * FROM some_other_table", "sfx")).toBe("SELECT * FROM some_other_table");
  });

  it("renders a grouped schema table", () => {
    const out = formatOcsfSchema(ocsfSchemaForSource("aws_cloudtrail"));
    expect(out).toContain("OCSF schema for aws_cloudtrail");
    expect(out).toContain("[actor]");
    expect(out).toContain("actor_user_uid");
  });
});
