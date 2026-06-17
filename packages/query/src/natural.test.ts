import { describe, expect, it } from "vitest";

import {
  buildNlSqlSystem,
  createAnthropicNlSqlClient,
  DEFAULT_NL_QUERY_MODEL,
  naturalLanguageToSql,
  NlSqlError,
  type NlSqlClient
} from "./natural.js";
import { validateR2Sql } from "./index.js";

const FIELDS = [
  { name: "time", type: "timestamp" },
  { name: "actor_user_uid", type: "string" },
  { name: "src_endpoint_country", type: "string" }
];
const TABLES = ["aws_cloudtrail", "kubernetes_audit"];

describe("buildNlSqlSystem", () => {
  it("includes tables, columns, and R2 SQL constraints", () => {
    const system = buildNlSqlSystem({ fields: FIELDS, tables: TABLES });
    expect(system).toContain("aws_cloudtrail");
    expect(system).toContain("actor_user_uid (string)");
    expect(system).toContain("Read-only");
    expect(system).toContain("window functions"); // from R2_SQL_CAPABILITIES.unsupportedFeatures
    expect(system).toContain("emit_query");
  });
});

describe("naturalLanguageToSql", () => {
  const validSql =
    "SELECT actor_user_uid FROM aws_cloudtrail WHERE time > now() - interval '24' hour AND src_endpoint_country <> 'US' LIMIT 100";

  it("returns the generated SQL with a passing validation", async () => {
    const client: NlSqlClient = { generate: async () => ({ sql: validSql, rationale: "recent non-US activity" }) };
    const result = await naturalLanguageToSql(
      client,
      { system: "sys", question: "non-US logins in the last day" },
      validateR2Sql
    );
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
    expect(result.sql).toBe(validSql);
    expect(result.rationale).toBe("recent non-US activity");
  });

  it("surfaces validation errors for a rejected query without throwing", async () => {
    const client: NlSqlClient = { generate: async () => ({ sql: "DELETE FROM aws_cloudtrail" }) };
    const result = await naturalLanguageToSql(client, { system: "s", question: "q" }, validateR2Sql);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("throws on an empty model response", async () => {
    const client: NlSqlClient = { generate: async () => ({ sql: "   " }) };
    await expect(naturalLanguageToSql(client, { system: "s", question: "q" }, validateR2Sql)).rejects.toBeInstanceOf(
      NlSqlError
    );
  });
});

describe("createAnthropicNlSqlClient", () => {
  function fakeFetch(handler: (url: string, init: RequestInit) => { status: number; body: unknown }) {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fn: typeof fetch = async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      calls.push({ url, init: init ?? {} });
      const res = handler(url, init ?? {});
      return new Response(JSON.stringify(res.body), { status: res.status });
    };
    return { fetch: fn, calls };
  }

  it("posts a forced emit_query tool call and extracts the SQL", async () => {
    const fetched = fakeFetch((url, init) => {
      expect(url).toBe("https://api.anthropic.com/v1/messages");
      const headers = init.headers as Record<string, string>;
      expect(headers["x-api-key"]).toBe("sk-test");
      expect(headers["anthropic-version"]).toBe("2023-06-01");
      const body = JSON.parse(init.body as string) as Record<string, unknown>;
      expect(body.model).toBe(DEFAULT_NL_QUERY_MODEL);
      expect(body.tool_choice).toEqual({ type: "tool", name: "emit_query" });
      expect(body).not.toHaveProperty("temperature"); // removed on Opus 4.8
      return {
        status: 200,
        body: {
          content: [
            { type: "tool_use", name: "emit_query", input: { sql: "SELECT 1", rationale: "trivial" } }
          ]
        }
      };
    });
    const client = createAnthropicNlSqlClient({ apiKey: "sk-test", fetchImpl: fetched.fetch });

    const out = await client.generate({ system: "sys", question: "q" });
    expect(out).toEqual({ sql: "SELECT 1", rationale: "trivial" });
    expect(fetched.calls).toHaveLength(1);
  });

  it("honors a model override", async () => {
    const fetched = fakeFetch((_url, init) => {
      const body = JSON.parse(init.body as string) as Record<string, unknown>;
      expect(body.model).toBe("claude-sonnet-4-6");
      return { status: 200, body: { content: [{ type: "tool_use", name: "emit_query", input: { sql: "SELECT 1" } }] } };
    });
    const client = createAnthropicNlSqlClient({ apiKey: "k", model: "claude-sonnet-4-6", fetchImpl: fetched.fetch });
    await client.generate({ system: "s", question: "q" });
  });

  it("raises NlSqlError on an API error response", async () => {
    const fetched = fakeFetch(() => ({ status: 401, body: { error: { message: "invalid x-api-key" } } }));
    const client = createAnthropicNlSqlClient({ apiKey: "bad", fetchImpl: fetched.fetch });
    await expect(client.generate({ system: "s", question: "q" })).rejects.toThrow(/invalid x-api-key/);
  });

  it("raises NlSqlError when no tool_use block is present", async () => {
    const fetched = fakeFetch(() => ({ status: 200, body: { content: [{ type: "text", text: "I cannot." }] } }));
    const client = createAnthropicNlSqlClient({ apiKey: "k", fetchImpl: fetched.fetch });
    await expect(client.generate({ system: "s", question: "q" })).rejects.toThrow(/emit_query/);
  });
});
