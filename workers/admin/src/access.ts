import { createRemoteJWKSet, jwtVerify } from "jose";
import type { MiddlewareHandler } from "hono";

export interface AccessConfig {
  teamDomain: string;
  audience: string;
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwks(teamDomain: string) {
  let jwks = jwksCache.get(teamDomain);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`https://${teamDomain}/cdn-cgi/access/certs`));
    jwksCache.set(teamDomain, jwks);
  }
  return jwks;
}

export function requireAccess(config: AccessConfig): MiddlewareHandler {
  return async (c, next) => {
    const token = c.req.header("cf-access-jwt-assertion");
    if (!token) return c.json({ error: "Missing Cloudflare Access token" }, 401);

    try {
      const { payload } = await jwtVerify(token, getJwks(config.teamDomain), {
        issuer: `https://${config.teamDomain}`,
        audience: config.audience
      });
      c.set("accessUser", {
        email: typeof payload.email === "string" ? payload.email : undefined,
        sub: typeof payload.sub === "string" ? payload.sub : undefined
      });
    } catch (error) {
      return c.json({ error: "Invalid Access token", detail: error instanceof Error ? error.message : String(error) }, 401);
    }

    await next();
  };
}

declare module "hono" {
  interface ContextVariableMap {
    accessUser: { email?: string; sub?: string };
  }
}
