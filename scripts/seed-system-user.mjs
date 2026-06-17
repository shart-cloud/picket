#!/usr/bin/env node
// Seeds the synthetic system@picket.local user that owns all MVP api-keys.
// Runs against the picket-auth D1 via `wrangler d1 execute`.
//
// Usage:
//   node scripts/seed-system-user.mjs                  # local (--local)
//   node scripts/seed-system-user.mjs --remote         # production D1

import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";

const remote = process.argv.includes("--remote");
const userId = process.env.PICKET_SYSTEM_USER_ID ?? randomUUID();
const now = new Date().toISOString();

const sql = `
INSERT OR IGNORE INTO user (id, email, name, emailVerified, createdAt, updatedAt)
VALUES ('${userId}', 'system@picket.local', 'Picket System', 1, '${now}', '${now}');
SELECT id, email FROM user WHERE email = 'system@picket.local';
`.trim();

const args = [
  "wrangler",
  "d1",
  "execute",
  "picket-auth",
  remote ? "--remote" : "--local",
  "--command",
  sql
];

const result = spawnSync("pnpm", ["exec", ...args], { stdio: "inherit" });
process.exit(result.status ?? 1);
