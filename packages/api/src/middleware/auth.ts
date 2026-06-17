import type { Context, MiddlewareHandler } from "hono";
import type { SourceId } from "@picket/core";
import type { PicketAuth, PicketKeyMetadata } from "../auth";

export interface ApiKeyContext {
  key_id: string;
  user_id: string;
  tenant_id: string;
  source: SourceId;
}

declare module "hono" {
  interface ContextVariableMap {
    apiKey: ApiKeyContext;
  }
}

export function apiKeyAuth(auth: PicketAuth): MiddlewareHandler {
  return async (c, next) => {
    const key = c.req.header("x-api-key");
    if (!key) return unauthorized(c, "missing api key");

    const result = await auth.api.verifyApiKey({ body: { key } });
    if (!result?.valid || !result.key) return unauthorized(c, "invalid api key");

    const metadata = result.key.metadata as PicketKeyMetadata | null;
    if (!metadata?.source || !metadata?.tenant_id) {
      return unauthorized(c, "key missing source or tenant metadata");
    }

    c.set("apiKey", {
      key_id: result.key.id,
      user_id: result.key.referenceId,
      tenant_id: metadata.tenant_id,
      source: metadata.source
    });

    await next();
  };
}

function unauthorized(c: Context, reason: string): Response {
  return c.json({ error: "Unauthorized", reason }, 401);
}
