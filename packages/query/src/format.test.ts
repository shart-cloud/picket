import { describe, expect, it } from "vitest";

import { formatRows } from "./format.js";
import type { R2SqlResult } from "./executor.js";

const empty: R2SqlResult = { columns: ["id", "name"], rows: [] };

const sample: R2SqlResult = {
  columns: ["id", "name", "tags"],
  rows: [
    { id: 1, name: "alpha", tags: "a,b" },
    { id: 2, name: "with\nnewline", tags: 'quote"inside' }
  ]
};

describe("formatRows", () => {
  it("table renders header, separator, and aligned rows", () => {
    const simple: R2SqlResult = {
      columns: ["id", "name"],
      rows: [
        { id: 1, name: "alpha" },
        { id: 2, name: "beta" }
      ]
    };
    const out = formatRows(simple, "table");
    const lines = out.split("\n");
    expect(lines[0]).toMatch(/^id\s+name/);
    expect(lines).toHaveLength(2 + simple.rows.length);
    expect(out).toContain("alpha");
    expect(out).toContain("beta");
  });

  it("table renders (0 rows) when empty", () => {
    expect(formatRows(empty, "table")).toBe("(0 rows)");
  });

  it("json renders a parseable array of rows", () => {
    const out = formatRows(sample, "json");
    expect(JSON.parse(out)).toEqual(sample.rows);
  });

  it("json renders [] when empty", () => {
    expect(formatRows(empty, "json")).toBe("[]");
  });

  it("csv quotes cells with commas, newlines, and quotes", () => {
    const out = formatRows(sample, "csv");
    expect(out).toBe(
      'id,name,tags\n' +
        '1,alpha,"a,b"\n' +
        '2,"with\nnewline","quote""inside"'
    );
  });

  it("csv renders just the header line when empty", () => {
    expect(formatRows(empty, "csv")).toBe("id,name");
  });
});
