import { betterAuth } from "better-auth";
import { apiKey } from "@better-auth/api-key";
import { bearer, deviceAuthorization } from "better-auth/plugins";
import { Kysely, sql } from "kysely";
import { D1Dialect } from "kysely-d1";
import type { SourceId } from "@picket/core";

// Narrow row shapes for the better-auth tables we touch directly. We don't
// model every column — just enough to satisfy Kysely's column-name typing for
// the queries below.
interface AuthDbSchema {
  user: {
    id: string;
    name: string;
    email: string;
    emailVerified: number;
    image: string | null;
    createdAt: string;
    updatedAt: string;
  };
  deviceCode: {
    id: string;
    deviceCode: string;
    userCode: string;
    userId: string | null;
    expiresAt: string | Date;
    status: string;
    lastPolledAt: string | Date | null;
    pollingInterval: number | null;
    clientId: string | null;
    scope: string | null;
  };
}

export interface PicketAuthOptions {
  db: D1Database;
  baseURL: string;
  secret: string;
  // Where the device flow tells the CLI to send the user. Set to <api-url>/device.
  deviceVerificationUri?: string;
}

export interface PicketKeyMetadata {
  source: SourceId;
  tenant_id: string;
}

// The inferred type of `betterAuth({...})` references zod internals via deep
// imports, which trips TS2742 ("cannot be named without reference to ...") when
// re-exported across package boundaries. We expose a narrowed interface that
// covers only the surface @picket consumers use (verifyApiKey + handler).
export interface VerifyApiKeyResult {
  valid: boolean;
  key: {
    id: string;
    referenceId: string;
    metadata: Record<string, unknown> | null;
  } | null;
}

export interface PicketSessionUser {
  id: string;
  email?: string;
  name?: string;
}

export interface PicketSession {
  user: PicketSessionUser;
  session: { id: string };
}

export interface CreateApiKeyResult {
  id: string;
  key: string;
  name: string | null;
  start: string | null;
  prefix: string | null;
  metadata: Record<string, unknown> | null;
  userId: string;
}

export type DeviceDecisionResult =
  | { ok: true; status: "approved" | "denied" }
  | { ok: false; reason: "not_found" | "expired" | "already_processed" };

export interface PicketAuth {
  api: {
    verifyApiKey: (args: { body: { key: string } }) => Promise<VerifyApiKeyResult>;
    getSession: (args: { headers: Headers }) => Promise<PicketSession | null>;
    createApiKey: (args: {
      body: { userId: string; name?: string; metadata?: Record<string, unknown>; expiresIn?: number | null };
    }) => Promise<CreateApiKeyResult>;
  };
  handler: (request: Request) => Promise<Response>;
  // Find an existing user by email or create one. Used by the /device approval
  // flow when Access JWT is the only identity available (no human login yet).
  findOrCreateUserByEmail: (email: string, name?: string) => Promise<PicketSessionUser>;
  // Apply an approve/deny decision to a pending device code on behalf of
  // `userId`. Bypasses better-auth's deviceApprove/Deny endpoints (which
  // require a session header we can't synthesize) by writing directly to the
  // `deviceCode` row. The CLI's poll on /device/token then picks it up.
  decideDeviceCode: (
    userCode: string,
    userId: string,
    decision: "approved" | "denied"
  ) => Promise<DeviceDecisionResult>;
}

export function createPicketAuth({
  db,
  baseURL,
  secret,
  deviceVerificationUri
}: PicketAuthOptions): PicketAuth {
  const kysely = new Kysely<AuthDbSchema>({ dialect: new D1Dialect({ database: db }) });

  const auth = betterAuth({
    baseURL,
    secret,
    database: {
      db: kysely,
      type: "sqlite"
    },
    plugins: [
      apiKey({
        enableMetadata: true,
        rateLimit: {
          enabled: true,
          timeWindow: 60_000,
          maxRequests: 600
        }
      }),
      deviceAuthorization({
        verificationUri: deviceVerificationUri,
        expiresIn: "15m",
        interval: "5s"
      }),
      bearer()
    ]
  });

  const findOrCreateUserByEmail = async (
    email: string,
    name?: string
  ): Promise<PicketSessionUser> => {
    const existing = await kysely
      .selectFrom("user")
      .select(["id", "email", "name"])
      .where("email", "=", email)
      .executeTakeFirst();
    if (existing) {
      return { id: existing.id, email: existing.email, name: existing.name };
    }
    const id = crypto.randomUUID();
    const displayName = name && name.length > 0 ? name : email;
    const now = new Date().toISOString();
    await kysely
      .insertInto("user")
      .values({
        id,
        name: displayName,
        email,
        emailVerified: 1,
        image: null,
        createdAt: now,
        updatedAt: now
      })
      .execute();
    return { id, email, name: displayName };
  };

  const decideDeviceCode = async (
    userCode: string,
    userId: string,
    decision: "approved" | "denied"
  ): Promise<DeviceDecisionResult> => {
    const cleanCode = userCode.replace(/-/g, "");
    const row = await kysely
      .selectFrom("deviceCode")
      .select(["id", "status", "expiresAt"])
      .where("userCode", "=", cleanCode)
      .executeTakeFirst();
    if (!row) return { ok: false, reason: "not_found" };
    const expiresAt = row.expiresAt instanceof Date ? row.expiresAt : new Date(row.expiresAt);
    if (expiresAt.getTime() < Date.now()) return { ok: false, reason: "expired" };
    if (row.status !== "pending") return { ok: false, reason: "already_processed" };
    await kysely
      .updateTable("deviceCode")
      .set({ status: decision, userId })
      .where("id", "=", row.id)
      .where("status", "=", "pending")
      .execute();
    return { ok: true, status: decision };
  };

  const picket = auth as unknown as Omit<PicketAuth, "findOrCreateUserByEmail" | "decideDeviceCode">;
  return {
    ...picket,
    findOrCreateUserByEmail,
    decideDeviceCode
  };
}

// `sql` is re-exported so consumers that need raw SQL helpers (migrations,
// scripts) can pull it without depending on kysely directly.
export { sql };
