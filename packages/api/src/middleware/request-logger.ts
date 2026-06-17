import type { MiddlewareHandler } from "hono";

export function requestLogger(workerName: string): MiddlewareHandler {
  return async (c, next) => {
    const start = Date.now();
    await next();
    const key = c.get("apiKey");
    console.log(
      JSON.stringify({
        worker: workerName,
        method: c.req.method,
        path: new URL(c.req.url).pathname,
        status: c.res.status,
        duration_ms: Date.now() - start,
        tenant_id: key?.tenant_id,
        source: key?.source,
        key_id: key?.key_id
      })
    );
  };
}
