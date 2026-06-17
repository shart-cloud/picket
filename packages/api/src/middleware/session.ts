import type { Context, MiddlewareHandler } from "hono";

import type { PicketAuth, PicketSessionUser } from "../auth";

declare module "hono" {
  interface ContextVariableMap {
    sessionUser: PicketSessionUser;
  }
}

export type AuthResolver<TEnv extends object> = (c: Context<{ Bindings: TEnv }>) => PicketAuth;

export function requireSession<TEnv extends object>(
  resolveAuth: AuthResolver<TEnv>
): MiddlewareHandler<{ Bindings: TEnv }> {
  return async (c, next) => {
    const auth = resolveAuth(c);
    const session = await auth.api.getSession({ headers: c.req.raw.headers });
    if (!session) return c.json({ error: "Not authenticated" }, 401);

    c.set("sessionUser", session.user);
    await next();
  };
}
