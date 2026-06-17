import { R2_SQL_CAPABILITIES } from "./index.js";

// Natural-language → R2 SQL (Milestone 4). A question plus the lake schema and
// R2 SQL constraints is sent to Claude, which returns a single read-only SELECT
// via a forced tool call. The caller validates the result with validateR2Sql and
// runs it through the existing async query-job flow.
//
// The Anthropic call uses a small injectable fetch client (mirroring
// createR2SqlHttpExecutor) rather than the SDK, so the Worker stays light and
// tests can inject a fake client / fake fetch.

export const DEFAULT_NL_QUERY_MODEL = "claude-opus-4-8";
const ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION = "2023-06-01";
const EMIT_QUERY_TOOL = "emit_query";

export interface NlSqlGenerateInput {
  system: string;
  question: string;
}

export interface NlSqlGeneration {
  sql: string;
  rationale?: string;
}

// The model-call seam. Tests inject a fake; production uses the Anthropic client.
export interface NlSqlClient {
  generate(input: NlSqlGenerateInput): Promise<NlSqlGeneration>;
}

export class NlSqlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NlSqlError";
  }
}

export interface NlSqlField {
  name: string;
  type: string;
}

export interface BuildNlSqlSystemInput {
  fields: readonly NlSqlField[];
  tables: readonly string[];
}

// Builds the system prompt: the queryable tables, the OCSF column schema, and the
// R2 SQL constraints the generated query must satisfy.
export function buildNlSqlSystem(input: BuildNlSqlSystemInput): string {
  const fieldLines = input.fields.map((field) => `  - ${field.name} (${field.type})`).join("\n");
  const unsupported = R2_SQL_CAPABILITIES.unsupportedFeatures.join(", ");

  return [
    "You translate a security analyst's natural-language question into a single read-only R2 SQL query over an OCSF event lake.",
    "",
    "Queryable tables (each row is one normalized OCSF event; all tables share the same columns):",
    input.tables.map((table) => `  - ${table}`).join("\n"),
    "",
    "Columns available on every table:",
    fieldLines,
    "",
    "R2 SQL constraints — the query MUST satisfy all of these:",
    "  - Start with SELECT or WITH. Read-only only: never INSERT/UPDATE/DELETE/DDL.",
    `  - Unsupported (do not use): ${unsupported}.`,
    "  - JOINs, subqueries, and CTEs are supported. Prefer a time-range WHERE filter on `time` to bound the scan.",
    "  - Use `now() - interval 'N' hour` (or day/minute) for relative time windows.",
    "  - Always include a LIMIT unless the question is an aggregate count.",
    "",
    "Return the query by calling the emit_query tool exactly once. Do not explain outside the tool call."
  ].join("\n");
}

// Generate + validate. Returns the generated SQL plus the validation result so
// the caller can decide whether to execute it. Never executes anything itself.
export async function naturalLanguageToSql(
  client: NlSqlClient,
  input: NlSqlGenerateInput,
  validate: (sql: string) => { valid: boolean; errors: string[]; warnings: string[] }
): Promise<{ sql: string; rationale?: string; valid: boolean; errors: string[]; warnings: string[] }> {
  const generation = await client.generate(input);
  const sql = generation.sql.trim();
  if (sql.length === 0) throw new NlSqlError("Model returned an empty query.");
  const validation = validate(sql);
  return {
    sql,
    rationale: generation.rationale,
    valid: validation.valid,
    errors: validation.errors,
    warnings: validation.warnings
  };
}

export interface AnthropicNlSqlOptions {
  apiKey: string;
  model?: string;
  maxTokens?: number;
  fetchImpl?: typeof fetch;
}

// Anthropic Messages API client. Forces a single `emit_query` tool call so the
// model returns exactly one SQL string (no prose, no prefill — prefills are
// rejected on current models). No temperature (removed on Opus 4.8) and no
// streaming; determinism comes from the forced tool output + constrained prompt.
export function createAnthropicNlSqlClient(options: AnthropicNlSqlOptions): NlSqlClient {
  const fetchImpl = options.fetchImpl ?? fetch;
  const model = options.model || DEFAULT_NL_QUERY_MODEL;
  const maxTokens = options.maxTokens ?? 1024;

  return {
    async generate(input: NlSqlGenerateInput): Promise<NlSqlGeneration> {
      const body = {
        model,
        max_tokens: maxTokens,
        system: input.system,
        messages: [{ role: "user", content: input.question }],
        tools: [
          {
            name: EMIT_QUERY_TOOL,
            description: "Return the single read-only R2 SQL query that answers the analyst's question.",
            input_schema: {
              type: "object",
              properties: {
                sql: {
                  type: "string",
                  description: "A single read-only R2 SQL SELECT (or WITH) query that answers the question."
                },
                rationale: {
                  type: "string",
                  description: "One short sentence describing what the query returns."
                }
              },
              required: ["sql"]
            }
          }
        ],
        tool_choice: { type: "tool", name: EMIT_QUERY_TOOL }
      };

      const response = await fetchImpl(ANTHROPIC_MESSAGES_URL, {
        method: "POST",
        headers: {
          "x-api-key": options.apiKey,
          "anthropic-version": ANTHROPIC_VERSION,
          "content-type": "application/json"
        },
        body: JSON.stringify(body)
      });

      const text = await response.text();
      let parsed: unknown;
      try {
        parsed = text.length === 0 ? null : JSON.parse(text);
      } catch {
        throw new NlSqlError(`Anthropic API returned non-JSON (HTTP ${response.status}): ${truncate(text, 200)}`);
      }

      if (!response.ok) {
        const message =
          isJsonObject(parsed) && isJsonObject(parsed.error) && typeof parsed.error.message === "string"
            ? parsed.error.message
            : `HTTP ${response.status}`;
        throw new NlSqlError(`Anthropic API error: ${message}`);
      }

      return extractGeneration(parsed);
    }
  };
}

// Pull the emit_query tool_use block out of a Messages API response.
function extractGeneration(parsed: unknown): NlSqlGeneration {
  if (!isJsonObject(parsed) || !Array.isArray(parsed.content)) {
    throw new NlSqlError("Anthropic API returned an unexpected payload.");
  }
  for (const block of parsed.content) {
    if (isJsonObject(block) && block.type === "tool_use" && block.name === EMIT_QUERY_TOOL && isJsonObject(block.input)) {
      const sql = block.input.sql;
      if (typeof sql !== "string") break;
      const rationale = typeof block.input.rationale === "string" ? block.input.rationale : undefined;
      return { sql, rationale };
    }
  }
  throw new NlSqlError("Model did not return a query via the emit_query tool.");
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}
