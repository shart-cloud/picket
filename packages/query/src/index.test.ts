import { describe, expect, it } from "vitest";

import { explainQuery, planR2Sql, presetQuery, R2_SQL_CAPABILITIES, validateR2Sql } from "./index";

describe("R2_SQL_CAPABILITIES", () => {
  it("tracks current JOIN-capable R2 SQL assumptions", () => {
    expect(R2_SQL_CAPABILITIES.joins).toBe(true);
    expect(R2_SQL_CAPABILITIES.subqueries).toBe(true);
    expect(R2_SQL_CAPABILITIES.commonTableExpressions).toBe(true);
    expect(R2_SQL_CAPABILITIES.unsupportedFeatures).toContain("window functions");
  });
});

describe("validateR2Sql", () => {
  it("allows JOIN queries with time filters", () => {
    expect(validateR2Sql(presetQuery("okta-to-aws-sensitive-actions"))).toEqual({
      valid: true,
      errors: [],
      warnings: []
    });
  });

  it("rejects mutating SQL", () => {
    const result = validateR2Sql("DELETE FROM aws_cloudtrail WHERE time > now() - interval '1' hour");

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("R2 SQL queries must start with SELECT or WITH.");
    expect(result.errors).toContain("R2 SQL is read-only; mutating and DDL statements are not supported.");
  });

  it("rejects unsupported features", () => {
    const result = validateR2Sql("SELECT row_number() OVER (PARTITION BY actor_user_uid) FROM okta_auth");

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("R2 SQL does not currently support window functions.");
  });

  it("warns when queries omit time filters", () => {
    const result = validateR2Sql("SELECT * FROM aws_cloudtrail LIMIT 10");

    expect(result.valid).toBe(true);
    expect(result.warnings).toContain("Add a time-range WHERE filter to control scan cost and JOIN selectivity.");
  });
});

describe("presetQuery", () => {
  it("generates enrichment JOIN queries", () => {
    const sql = presetQuery("threat-intel-ip-matches", { hours: 1, limit: 25 });

    expect(sql).toContain("JOIN threat_intel ti");
    expect(sql).toContain("interval '1' hour");
    expect(sql).toContain("LIMIT 25");
  });
});

describe("planR2Sql", () => {
  it("extracts referenced tables, join, time filter, and limit", () => {
    const plan = planR2Sql(presetQuery("okta-to-aws-sensitive-actions"));
    expect(plan.tables).toEqual(["okta_auth", "aws_cloudtrail"]);
    expect(plan.has_join).toBe(true);
    expect(plan.has_time_filter).toBe(true);
    expect(plan.has_limit).toBe(true);
    expect(plan.read_only).toBe(true);
  });

  it("flags a single-table query with no join", () => {
    const plan = planR2Sql("SELECT * FROM aws_cloudtrail LIMIT 10");
    expect(plan.tables).toEqual(["aws_cloudtrail"]);
    expect(plan.has_join).toBe(false);
    expect(plan.has_time_filter).toBe(false);
  });

  it("marks mutating statements as not read-only", () => {
    expect(planR2Sql("DELETE FROM aws_cloudtrail").read_only).toBe(false);
  });
});

describe("explainQuery", () => {
  it("returns validation plus a plan for a valid query", () => {
    const explain = explainQuery("SELECT * FROM aws_cloudtrail WHERE time > now() - interval '1' hour LIMIT 10");
    expect(explain.valid).toBe(true);
    expect(explain.errors).toEqual([]);
    expect(explain.plan.tables).toEqual(["aws_cloudtrail"]);
  });

  it("surfaces validation errors for a rejected query", () => {
    const explain = explainQuery("DELETE FROM aws_cloudtrail");
    expect(explain.valid).toBe(false);
    expect(explain.errors.length).toBeGreaterThan(0);
  });
});
