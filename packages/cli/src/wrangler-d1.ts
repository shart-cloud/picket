import { spawn } from "node:child_process";

import type { AlertStateDb, AlertStateStatement } from "@picket/core/alerts";

export interface WranglerD1Options {
  databaseName: string;
  remote?: boolean;
  configPath?: string;
}

export function createWranglerD1(options: WranglerD1Options): AlertStateDb {
  return {
    prepare: (sql: string) => new WranglerStatement(sql, [], options)
  };
}

class WranglerStatement implements AlertStateStatement {
  constructor(
    private readonly sql: string,
    private readonly params: readonly unknown[],
    private readonly options: WranglerD1Options
  ) {}

  bind(...params: unknown[]): AlertStateStatement {
    return new WranglerStatement(this.sql, params, this.options);
  }

  async first<T = unknown>(): Promise<T | null> {
    const results = await this.exec<T>();
    return results[0] ?? null;
  }

  async all<T = unknown>(): Promise<{ results: T[] }> {
    return { results: await this.exec<T>() };
  }

  async run(): Promise<unknown> {
    await this.exec<unknown>();
    return { success: true };
  }

  private async exec<T>(): Promise<T[]> {
    const command = inlineParams(this.sql, this.params);
    const args = ["d1", "execute", this.options.databaseName, "--json", "--command", command];
    if (this.options.remote) args.push("--remote");
    else args.push("--local");
    if (this.options.configPath) args.push("--config", this.options.configPath);

    const { stdout } = await runWrangler(args);
    return parseResults<T>(stdout);
  }
}

function runWrangler(args: readonly string[]): Promise<{ stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn("wrangler", args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += String(chunk)));
    child.stderr.on("data", (chunk) => (stderr += String(chunk)));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve({ stdout });
      else reject(new Error(`wrangler exited with code ${code}: ${stderr.trim() || stdout.trim()}`));
    });
  });
}

function parseResults<T>(stdout: string): T[] {
  const start = stdout.indexOf("[");
  if (start === -1) return [];
  const parsed = JSON.parse(stdout.slice(start)) as unknown;
  if (!Array.isArray(parsed)) return [];
  const first = parsed[0];
  if (first && typeof first === "object" && "results" in first) {
    const results = (first as { results?: unknown }).results;
    return Array.isArray(results) ? (results as T[]) : [];
  }
  return [];
}

function inlineParams(sql: string, params: readonly unknown[]): string {
  let index = 0;
  return sql.replace(/\?/g, () => {
    if (index >= params.length) throw new Error("Not enough parameters supplied for SQL placeholders.");
    const value = params[index];
    index += 1;
    return formatLiteral(value);
  });
}

function formatLiteral(value: unknown): string {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Cannot bind non-finite number to SQL.");
    return String(value);
  }
  if (typeof value === "boolean") return value ? "1" : "0";
  return `'${String(value).replace(/'/g, "''")}'`;
}
