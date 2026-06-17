import { Hono, type MiddlewareHandler } from "hono";
import { createPicketAuth, requestLogger, requireSession, type PicketAuth } from "@picket/api";
import { requireAccess } from "./access";
import { registerAlertsRoutes } from "./alerts-routes";
import { registerDashboardRoutes, type DashboardRoutesOptions } from "./dashboard-routes";
import { registerDetectionsRoutes } from "./detections-routes";
import { registerDeviceRoutes } from "./device-routes";
import { registerEnrichmentRoutes } from "./enrichment-routes";
import { registerQueryRoutes, type QueryRoutesOptions } from "./query-routes";
import { registerSourcesRoutes } from "./sources-routes";
import type { IocKvNamespace } from "@picket/core/enrichment";

export interface AdminEnv {
  AUTH_DB: D1Database;
  ALERT_STATE_DB: D1Database;
  BETTER_AUTH_SECRET: string;
  CF_ACCESS_TEAM_DOMAIN: string;
  CF_ACCESS_AUD: string;
  R2_SQL_TOKEN?: string;
  PICKET_R2_WAREHOUSE?: string;
  PICKET_TABLE_SUFFIX?: string;
  QUERY_JOBS_QUEUE?: Queue<{ job_id: string }>;
  // Natural-language query (M4). Secret + optional model override.
  ANTHROPIC_API_KEY?: string;
  PICKET_NL_QUERY_MODEL?: string;
  // Threat-intel IOC store for enrichment management (M4). Same picket-config KV
  // namespace the ingest Worker reads.
  ENRICHMENT_KV?: IocKvNamespace;
  // Query-time enrichment changelog written to the `threat_intel` Iceberg table.
  THREAT_INTEL_PIPELINE?: PicketPipeline;
  ASSETS_PIPELINE?: PicketPipeline;
  USERS_PIPELINE?: PicketPipeline;
}

export interface PicketPipeline {
  send(records: Record<string, unknown>[]): Promise<void>;
}

let authInstance: PicketAuth | undefined;

function getAuth(env: AdminEnv, baseURL: string): PicketAuth {
  if (!authInstance) {
    authInstance = createPicketAuth({
      db: env.AUTH_DB,
      baseURL,
      secret: env.BETTER_AUTH_SECRET,
      deviceVerificationUri: `${baseURL}/device`
    });
  }
  return authInstance;
}

export interface CreateAdminAppOptions {
  accessMiddleware?: (env: AdminEnv) => MiddlewareHandler;
  sessionMiddleware?: MiddlewareHandler<{ Bindings: AdminEnv }>;
  queryRoutes?: QueryRoutesOptions;
  dashboardRoutes?: DashboardRoutesOptions;
  // For tests: inject a stub PicketAuth instead of constructing one against
  // env.AUTH_DB. The default resolves the real auth instance lazily.
  resolveAuth?: (env: AdminEnv, baseURL: string) => PicketAuth;
}

export function createAdminApp(options: CreateAdminAppOptions = {}): Hono<{ Bindings: AdminEnv }> {
  const accessFor =
    options.accessMiddleware ??
    ((env: AdminEnv) =>
      requireAccess({ teamDomain: env.CF_ACCESS_TEAM_DOMAIN, audience: env.CF_ACCESS_AUD }));

  const resolveAuthFor = options.resolveAuth ?? getAuth;

  const sessionMw =
    options.sessionMiddleware ??
    requireSession<AdminEnv>((c) => resolveAuthFor(c.env, new URL(c.req.url).origin));

  const app = new Hono<{ Bindings: AdminEnv }>();

  app.use("*", requestLogger("picket-admin"));

  app.get("/health", (c) => c.json({ ok: true, worker: "picket-admin" }));

  // Discovery endpoint for CLIs. Unauthenticated on purpose so `picket login`
  // can decide whether to run the Access leg before any auth headers exist.
  // access_required is hardcoded today; will become env-driven when the
  // Terraform module gains a non-Access deployment mode.
  app.get("/api/v1/meta", (c) => {
    const baseURL = new URL(c.req.url).origin;
    return c.json({
      access_required: true,
      verification_uri: `${baseURL}/device`,
      api_url: baseURL
    });
  });

  // Cloudflare Access gates all authenticated surfaces.
  app.use("/api/v1/auth/*", (c, next) => accessFor(c.env)(c, next));
  app.use("/api/v1/alerts", (c, next) => accessFor(c.env)(c, next));
  app.use("/api/v1/alerts/*", (c, next) => accessFor(c.env)(c, next));
  app.use("/api/v1/detections", (c, next) => accessFor(c.env)(c, next));
  app.use("/api/v1/detections/*", (c, next) => accessFor(c.env)(c, next));
  app.use("/api/v1/query", (c, next) => accessFor(c.env)(c, next));
  app.use("/api/v1/query/*", (c, next) => accessFor(c.env)(c, next));
  app.use("/api/v1/sources", (c, next) => accessFor(c.env)(c, next));
  app.use("/api/v1/sources/*", (c, next) => accessFor(c.env)(c, next));
  app.use("/api/v1/dashboard/*", (c, next) => accessFor(c.env)(c, next));
  app.use("/api/v1/enrichment", (c, next) => accessFor(c.env)(c, next));
  app.use("/api/v1/enrichment/*", (c, next) => accessFor(c.env)(c, next));
  app.use("/api/v1/me", (c, next) => accessFor(c.env)(c, next));
  app.use("/api/v1/internal/*", (c, next) => accessFor(c.env)(c, next));
  app.use("/device", (c, next) => accessFor(c.env)(c, next));
  app.use("/device/*", (c, next) => accessFor(c.env)(c, next));

  // better-auth session identifies the in-app user for application routes.
  // Query and sources are read-only; Access JWT (or service-token headers)
  // is sufficient identity, no in-app session required. Alerts mutations
  // still want a session so the actor is tied to a logged-in user.
  app.use("/api/v1/alerts", sessionMw);
  app.use("/api/v1/alerts/*", sessionMw);

  app.get("/api/v1/me", async (c) => {
    const auth = resolveAuthFor(c.env, new URL(c.req.url).origin);
    const session = await auth.api.getSession({ headers: c.req.raw.headers });
    return c.json({ access: c.get("accessUser") ?? null, session });
  });

  app.post("/api/v1/auth/access-session", async (c) => {
    const access = c.get("accessUser");
    if (!access?.email) return c.json({ error: "Cloudflare Access email is required." }, 401);

    const auth = resolveAuthFor(c.env, new URL(c.req.url).origin);
    const existing = await auth.api.getSession({ headers: c.req.raw.headers });
    if (existing) return c.json({ user: existing.user, session: existing.session, created: false });

    const user = await auth.findOrCreateUserByEmail(access.email);
    const session = await createBrowserSession(c.env.AUTH_DB, {
      userId: user.id,
      secret: c.env.BETTER_AUTH_SECRET,
      secure: new URL(c.req.url).protocol === "https:"
    });
    c.header("set-cookie", session.cookie);
    return c.json({ user, session: { id: session.id }, created: true }, 201);
  });

  app.all("/api/v1/auth/*", async (c) => {
    const auth = resolveAuthFor(c.env, new URL(c.req.url).origin);
    const rewritten = new Request(c.req.url.replace("/api/v1/auth", "/api/auth"), c.req.raw);
    return auth.handler(rewritten);
  });

  registerAlertsRoutes(app);
  registerDetectionsRoutes(app);
  registerQueryRoutes(app, options.queryRoutes);
  registerSourcesRoutes(app, { query: options.queryRoutes });
  registerDashboardRoutes(app, options.dashboardRoutes);
  registerEnrichmentRoutes(app);
  registerDeviceRoutes(app, {
    resolveAuth: (c) => resolveAuthFor(c.env, new URL(c.req.url).origin)
  });

  // Internal: mint an api-key without a better-auth session. Used to seed
  // ingest credentials for new sources/tenants when there's no UI yet.
  // Access-gated; the caller is identified by the Access JWT.
  app.post("/api/v1/internal/api-keys", async (c) => {
    const body = (await c.req.raw.clone().json().catch(() => null)) as
      | { user_id?: unknown; name?: unknown; source?: unknown; tenant_id?: unknown; expires_in?: unknown }
      | null;
    if (!body || typeof body.user_id !== "string") {
      return c.json({ error: "`user_id` (string) is required" }, 400);
    }
    if (typeof body.source !== "string" || typeof body.tenant_id !== "string") {
      return c.json({ error: "`source` and `tenant_id` are required" }, 400);
    }
    try {
      const created = await createIngestApiKey(c.env.AUTH_DB, {
        userId: body.user_id,
        name: typeof body.name === "string" ? body.name : `${body.source}/${body.tenant_id}`,
        metadata: { source: body.source, tenant_id: body.tenant_id },
        expiresIn: typeof body.expires_in === "number" && body.expires_in > 0 ? body.expires_in : null
      });
      return c.json(
        {
          id: created.id,
          key: created.key,
          name: created.name,
          metadata: created.metadata,
          user_id: created.userId
        },
        201
      );
    } catch (error) {
      return c.json(
        { error: "Failed to mint api-key", detail: error instanceof Error ? error.message : String(error) },
        500
      );
    }
  });

  app.notFound((c) => c.json({ error: "Not found" }, 404));

  return app;
}

interface BrowserSessionResult {
  id: string;
  token: string;
  cookie: string;
}

async function createBrowserSession(
  db: D1Database,
  opts: { userId: string; secret: string; secure: boolean }
): Promise<BrowserSessionResult> {
  const id = crypto.randomUUID();
  const token = `ps_${base64Url(crypto.getRandomValues(new Uint8Array(32)))}`;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

  await db
    .prepare(
      `INSERT INTO session (id, expiresAt, token, createdAt, updatedAt, ipAddress, userAgent, userId)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(id, expiresAt.toISOString(), token, now.toISOString(), now.toISOString(), null, null, opts.userId)
    .run();

  return {
    id,
    token,
    cookie: await serializeSessionCookie(token, opts.secret, opts.secure)
  };
}

async function serializeSessionCookie(token: string, secret: string, secure: boolean): Promise<string> {
  const signature = await hmacSha256Base64(token, secret);
  const name = secure ? "__Secure-better-auth.session_token" : "better-auth.session_token";
  const value = encodeURIComponent(`${token}.${signature}`);
  return `${name}=${value}; Max-Age=604800; Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
}

async function hmacSha256Base64(value: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  let binary = "";
  for (const byte of new Uint8Array(signature)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

interface CreatedApiKey {
  id: string;
  key: string;
  name: string;
  metadata: { source: string; tenant_id: string };
  userId: string;
}

async function createIngestApiKey(
  db: D1Database,
  opts: {
    userId: string;
    name: string;
    metadata: { source: string; tenant_id: string };
    expiresIn: number | null;
  }
): Promise<CreatedApiKey> {
  const id = crypto.randomUUID();
  const key = `pk_${base64Url(crypto.getRandomValues(new Uint8Array(32)))}`;
  const hashedKey = await sha256Base64Url(key);
  const now = new Date();
  const nowIso = now.toISOString();
  const expiresAt = opts.expiresIn ? new Date(now.getTime() + opts.expiresIn * 1000).toISOString() : null;

  // Keep this row shape aligned with @better-auth/api-key createApiKey under
  // createPicketAuth: SHA-256 base64url hash, configId=default, metadata
  // enabled, and the same 60s/600 request rate-limit defaults.
  await db
    .prepare(
      `INSERT INTO apikey (
        id, configId, name, start, referenceId, prefix, key, refillInterval,
        refillAmount, lastRefillAt, enabled, rateLimitEnabled, rateLimitTimeWindow,
        rateLimitMax, requestCount, remaining, lastRequest, expiresAt, createdAt,
        updatedAt, permissions, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      id,
      "default",
      opts.name,
      null,
      opts.userId,
      null,
      hashedKey,
      null,
      null,
      null,
      1,
      1,
      60_000,
      600,
      0,
      null,
      null,
      expiresAt,
      nowIso,
      nowIso,
      null,
      JSON.stringify(opts.metadata)
    )
    .run();

  return { id, key, name: opts.name, metadata: opts.metadata, userId: opts.userId };
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64Url(new Uint8Array(digest));
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

const app = createAdminApp();

export default app satisfies ExportedHandler<AdminEnv>;
