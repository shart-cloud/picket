import type { AdminClientOptions } from "../admin-client.js";
import {
  cloudflaredAccessToken,
  CloudflaredNotInstalledError,
  defaultCloudflaredRunner,
  type CloudflaredRunner
} from "./cloudflared.js";
import {
  createCredentialsIo,
  isExpired,
  lookupCredential,
  type CredentialsIo
} from "./credentials.js";

// Resolves which auth headers to attach to admin-API calls. Multiple
// mechanisms are supported simultaneously (Access JWT for the perimeter,
// bearer for the in-app session); the precedence below mirrors what most
// users intuit:
//
//   flags > env vars > credentials file (login) > on-demand cloudflared
//
// Precedence within each leg:
//   Access leg:  flags > env (CF_ACCESS_*) > cloudflared `access token`
//                Skipped entirely when meta.access_required is false or
//                PICKET_SKIP_ACCESS=1.
//   App leg:     flags > env (PICKET_API_TOKEN) > credentials file bearer
//                  > env (PICKET_SESSION_COOKIE, deprecated)

export interface ResolveAuthInput {
  apiUrl: string;
  env: NodeJS.ProcessEnv;
  flags?: {
    accessClientId?: string;
    accessClientSecret?: string;
    accessJwt?: string;
    bearerToken?: string;
  };
  // Whether the deployment requires an Access JWT (from /api/v1/meta).
  // Defaults to true so a CLI that hasn't called meta yet still tries the
  // Access leg.
  accessRequired?: boolean;
  // Test injection points.
  cloudflared?: CloudflaredRunner;
  credentialsIo?: CredentialsIo;
}

export interface ResolvedAuth {
  accessClientId?: string;
  accessClientSecret?: string;
  accessJwt?: string;
  bearerToken?: string;
  sessionCookie?: string;
  // Diagnostics for `picket whoami` / verbose flows.
  source: {
    access?: "flag" | "env-jwt" | "env-service-token" | "cloudflared" | "skipped";
    app?: "flag" | "env-token" | "credentials" | "env-cookie";
  };
}

export async function resolveAuth(input: ResolveAuthInput): Promise<ResolvedAuth> {
  const source: ResolvedAuth["source"] = {};
  const out: ResolvedAuth = { source };

  const accessRequired = input.accessRequired !== false && input.env.PICKET_SKIP_ACCESS !== "1";

  if (accessRequired) {
    if (input.flags?.accessClientId && input.flags?.accessClientSecret) {
      out.accessClientId = input.flags.accessClientId;
      out.accessClientSecret = input.flags.accessClientSecret;
      source.access = "flag";
    } else if (input.flags?.accessJwt) {
      out.accessJwt = input.flags.accessJwt;
      source.access = "flag";
    } else if (input.env.CF_ACCESS_JWT) {
      out.accessJwt = input.env.CF_ACCESS_JWT;
      source.access = "env-jwt";
    } else if (input.env.CF_ACCESS_CLIENT_ID && input.env.CF_ACCESS_CLIENT_SECRET) {
      out.accessClientId = input.env.CF_ACCESS_CLIENT_ID;
      out.accessClientSecret = input.env.CF_ACCESS_CLIENT_SECRET;
      source.access = "env-service-token";
    } else {
      const runner = input.cloudflared ?? defaultCloudflaredRunner();
      try {
        const token = await cloudflaredAccessToken(runner, input.apiUrl);
        if (token) {
          out.accessJwt = token;
          source.access = "cloudflared";
        }
      } catch (error) {
        if (!(error instanceof CloudflaredNotInstalledError)) throw error;
        // Cloudflared not installed; leave access unset. The request will
        // fail at the perimeter with a clear error; callers can wire `picket
        // login` to do better.
      }
    }
  } else {
    source.access = "skipped";
  }

  if (input.flags?.bearerToken) {
    out.bearerToken = input.flags.bearerToken;
    source.app = "flag";
  } else if (input.env.PICKET_API_TOKEN) {
    out.bearerToken = input.env.PICKET_API_TOKEN;
    source.app = "env-token";
  } else {
    const io = input.credentialsIo ?? createCredentialsIo();
    const store = await io.read().catch(() => ({ records: {} }));
    const record = lookupCredential(store, input.apiUrl);
    if (record && !isExpired(record)) {
      out.bearerToken = record.access_token;
      source.app = "credentials";
    } else if (input.env.PICKET_SESSION_COOKIE) {
      out.sessionCookie = input.env.PICKET_SESSION_COOKIE;
      source.app = "env-cookie";
    }
  }

  return out;
}

export function toAdminClientOptions(
  baseUrl: string,
  resolved: ResolvedAuth
): AdminClientOptions {
  return {
    baseUrl,
    accessClientId: resolved.accessClientId,
    accessClientSecret: resolved.accessClientSecret,
    accessJwt: resolved.accessJwt,
    bearerToken: resolved.bearerToken,
    sessionCookie: resolved.sessionCookie
  };
}
