// Standalone config consumed by @better-auth/cli to generate the D1 schema
// migration. The runtime auth instance in @picket/api binds to a D1 via
// Kysely's D1Dialect, which the CLI can't evaluate. This stub uses Kysely's
// in-memory SQLite dialect with better-sqlite3 — same plugin set, same
// schema output.
import Database from "better-sqlite3";
import { betterAuth } from "better-auth";
import { apiKey } from "@better-auth/api-key";
import { bearer, deviceAuthorization } from "better-auth/plugins";
import { Kysely, SqliteDialect } from "kysely";

const db = new Kysely({
  dialect: new SqliteDialect({ database: new Database(":memory:") })
});

export const auth = betterAuth({
  baseURL: "http://localhost",
  secret: "stub-secret-for-cli-schema-gen-only",
  database: { db, type: "sqlite" },
  plugins: [
    apiKey({ enableMetadata: true }),
    deviceAuthorization({ verificationUri: "http://localhost/device", expiresIn: "15m", interval: "5s" }),
    bearer()
  ]
});
