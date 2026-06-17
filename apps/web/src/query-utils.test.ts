import { describe, expect, it } from "vitest";

import { asQueryResult, queryResultToCsv, queryResultToJson, sortQueryRows } from "./query-utils";

describe("query result utilities", () => {
  it("normalizes result rows and derives columns when the API omits them", () => {
    expect(asQueryResult({ rows: [{ time: "2026-06-12", count: 2 }, { count: 1, source: "aws" }] })).toEqual({
      columns: ["time", "count", "source"],
      rows: [{ time: "2026-06-12", count: 2 }, { count: 1, source: "aws" }]
    });
  });

  it("sorts numbers numerically and leaves the source rows untouched", () => {
    const rows = [{ count: 10 }, { count: 2 }];
    expect(sortQueryRows(rows, "count", "asc")).toEqual([{ count: 2 }, { count: 10 }]);
    expect(rows).toEqual([{ count: 10 }, { count: 2 }]);
  });

  it("exports valid CSV and JSON", () => {
    const result = {
      columns: ["name", "detail"],
      rows: [{ name: "alpha", detail: "comma, quote \" and\nnewline" }]
    };
    expect(queryResultToCsv(result)).toBe('name,detail\nalpha,"comma, quote "" and\nnewline"');
    expect(JSON.parse(queryResultToJson(result))).toEqual(result.rows);
  });
});
