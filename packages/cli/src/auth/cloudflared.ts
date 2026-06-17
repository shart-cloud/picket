import { spawn } from "node:child_process";

// Thin wrapper around the `cloudflared` CLI for Access service-token /
// browser-login flows. The CLI shells out — embedding the cf-jwt-assertion
// flow ourselves would mean re-implementing the IdP redirect dance.
//
// We only use `cloudflared access login` (opens a browser to obtain a token)
// and `cloudflared access token -app=<url>` (prints the cached token). Both
// commands are no-ops if cloudflared isn't installed; callers should handle
// the ENOENT case gracefully and tell the user how to install it.

export interface CloudflaredRunner {
  run: (args: string[]) => Promise<{ stdout: string; stderr: string; code: number | null }>;
}

export interface AccessOptions {
  appUrl: string;
  // Where to send stderr/stdout for interactive flows ("login" prints a URL
  // and waits). For `token`, we capture stdout and only forward stderr.
  stdio?: "inherit" | "pipe";
}

export class CloudflaredNotInstalledError extends Error {
  constructor() {
    super("cloudflared is not installed or not on PATH. Install from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/ and re-run.");
    this.name = "CloudflaredNotInstalledError";
  }
}

export function defaultCloudflaredRunner(): CloudflaredRunner {
  return {
    async run(args) {
      return new Promise((resolve, reject) => {
        const child = spawn("cloudflared", args, { stdio: ["ignore", "pipe", "pipe"] });
        let stdout = "";
        let stderr = "";
        child.stdout?.on("data", (chunk: Buffer) => {
          stdout += chunk.toString("utf8");
        });
        child.stderr?.on("data", (chunk: Buffer) => {
          stderr += chunk.toString("utf8");
        });
        child.on("error", (err) => {
          if (isNodeError(err) && err.code === "ENOENT") {
            reject(new CloudflaredNotInstalledError());
            return;
          }
          reject(err);
        });
        child.on("close", (code) => resolve({ stdout, stderr, code }));
      });
    }
  };
}

// Try to fetch a cached Access JWT for `appUrl`. Returns undefined if the
// command fails or prints nothing usable — caller can then invoke
// `cloudflaredLogin` to start the browser flow.
export async function cloudflaredAccessToken(
  runner: CloudflaredRunner,
  appUrl: string
): Promise<string | undefined> {
  const { stdout, code } = await runner.run(["access", "token", `-app=${appUrl}`]);
  if (code !== 0) return undefined;
  const trimmed = stdout.trim();
  if (trimmed.length === 0) return undefined;
  // `cloudflared access token` prints "Unable to find token for provided application..."
  // on stdout when there's no cached token; filter that out.
  if (!looksLikeJwt(trimmed)) return undefined;
  return trimmed;
}

export async function cloudflaredAccessLogin(
  runner: CloudflaredRunner,
  appUrl: string
): Promise<{ ok: boolean; stderr: string }> {
  const result = await runner.run(["access", "login", appUrl]);
  return { ok: result.code === 0, stderr: result.stderr };
}

function looksLikeJwt(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 3 && parts.every((p) => p.length > 0 && /^[A-Za-z0-9_-]+$/.test(p));
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
