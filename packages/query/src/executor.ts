export type R2SqlRow = Record<string, unknown>;

export interface R2SqlResult {
  columns: string[];
  rows: R2SqlRow[];
}

export interface R2SqlExecutor {
  execute(sql: string): Promise<R2SqlResult>;
}

export interface R2SqlHttpOptions {
  warehouse: string;
  token?: string;
  env?: NodeJS.ProcessEnv;
  fetch?: typeof fetch;
}

export class R2SqlAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "R2SqlAuthError";
  }
}

export class R2SqlQueryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "R2SqlQueryError";
  }
}

/**
 * Executes R2 SQL queries by POSTing to the R2 SQL HTTP API directly.
 *
 * Why HTTP and not `wrangler r2 sql query`: wrangler renders results with
 * `logger.table()` (pretty-printed text), so its stdout is not parseable.
 * Internally wrangler calls the same API endpoint this function uses; we
 * reuse its auth conventions (WRANGLER_R2_SQL_AUTH_TOKEN with fallback to
 * CLOUDFLARE_API_TOKEN) so credentials configured for wrangler work here too.
 */
export function createR2SqlHttpExecutor(options: R2SqlHttpOptions): R2SqlExecutor {
  const env = options.env ?? process.env;
  const fetchImpl = options.fetch ?? fetch;
  const token =
    options.token ?? env.WRANGLER_R2_SQL_AUTH_TOKEN ?? env.CLOUDFLARE_API_TOKEN;

  const { warehouse } = options;
  const splitIndex = warehouse.indexOf("_");
  if (splitIndex === -1) {
    throw new Error(
      `Invalid R2 SQL warehouse "${warehouse}". Expected format: <account_id>_<bucket_name>.`
    );
  }
  const accountId = warehouse.slice(0, splitIndex);
  const bucketName = warehouse.slice(splitIndex + 1);
  const url = `https://api.sql.cloudflarestorage.com/api/v1/accounts/${accountId}/r2-sql/query/${bucketName}`;

  return {
    async execute(sql: string): Promise<R2SqlResult> {
      if (!token) {
        throw new R2SqlAuthError(
          "Missing R2 SQL auth token. Set WRANGLER_R2_SQL_AUTH_TOKEN or CLOUDFLARE_API_TOKEN. See https://developers.cloudflare.com/r2/sql/platform/troubleshooting/"
        );
      }

      const response = await fetchImpl(url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ warehouse, query: sql })
      });

      const text = await response.text();
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new R2SqlQueryError(
          `R2 SQL API returned a non-JSON response (HTTP ${response.status}): ${truncate(text, 200)}`
        );
      }

      if (!isJsonObject(parsed)) {
        throw new R2SqlQueryError("R2 SQL API returned an unexpected payload.");
      }

      if (parsed.success !== true) {
        const errors = Array.isArray(parsed.errors)
          ? parsed.errors
              .map((entry) =>
                isJsonObject(entry)
                  ? `${entry.code ?? "error"}: ${entry.message ?? "unknown"}`
                  : String(entry)
              )
              .join("; ")
          : `HTTP ${response.status}`;
        throw new R2SqlQueryError(errors || `HTTP ${response.status}`);
      }

      const result = parsed.result;
      if (!isJsonObject(result)) return { columns: [], rows: [] };

      const schema = Array.isArray(result.schema) ? result.schema : [];
      const columns = schema
        .map((field) => (isJsonObject(field) && typeof field.name === "string" ? field.name : null))
        .filter((name): name is string => name !== null);

      const rawRows = Array.isArray(result.rows) ? result.rows : [];
      const rows: R2SqlRow[] = rawRows.filter(isJsonObject);

      return { columns, rows };
    }
  };
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}
