#!/usr/bin/env node

// One-shot helper: drops Iceberg tables from the R2 Data Catalog so the
// pipeline sinks can recreate them. Cloudflare doesn't yet let pipelines
// write to pre-existing catalog tables (API error code 1012), and
// `terraform destroy` doesn't clear the tables inside R2 — only the
// catalog resource itself — so after destroy+apply the tables linger
// and block the new sinks.
//
// Usage:
//   CF_ACCOUNT_ID=... R2_CATALOG_TOKEN=... node scripts/drop-catalog-tables.mjs
//
// Falls back to TF_VAR_r2_catalog_token and TF_VAR_cloudflare_account_id
// for the token / account ID so terraform users don't have to retype them.

const accountId =
  process.env.CLOUDFLARE_ACCOUNT_ID ??
  process.env.CF_ACCOUNT_ID ??
  process.env.TF_VAR_cloudflare_account_id;
const token = process.env.R2_CATALOG_TOKEN ?? process.env.TF_VAR_r2_catalog_token;
const bucket = process.env.R2_BUCKET ?? "picket-lake";
const namespace = process.env.R2_CATALOG_NAMESPACE ?? "default";
const tables = (process.env.R2_TABLES ?? "aws_cloudtrail,kubernetes_audit,cloudflare_audit,picket_alerts")
  .split(",")
  .map((t) => t.trim())
  .filter(Boolean);

if (!accountId || !token) {
  console.error("Missing CF_ACCOUNT_ID and/or R2_CATALOG_TOKEN (or TF_VAR_* equivalents).");
  process.exit(1);
}

// Cloudflare exposes catalog management on the control-plane API
// (`api.cloudflare.com/client/v4/accounts/{id}/r2-catalog/{bucket}/...`),
// separate from the Iceberg REST endpoint on `catalog.cloudflarestorage.com`.
// The Iceberg REST host is for query engines (PyIceberg/Spark) and rejects
// some auth/header shapes from plain fetch; the control-plane path accepts
// the same Cloudflare API token the rest of the project uses and exposes
// the namespace/table CRUD wrangler doesn't surface as commands.
const catalogUri = `https://api.cloudflare.com/client/v4/accounts/${accountId}/r2-catalog/${bucket}`;

console.log(`Catalog base: ${catalogUri}`);
const authHeaders = { Authorization: `Bearer ${token}` };

// Brute-force across the target namespaces + table names. The control-plane
// catalog API doesn't expose a list-namespaces endpoint that we've found, so
// instead of discovering we just attempt each (namespace, table) pair.
// Tables that don't exist return 404 (counted separately, not a failure).
const namespacesToTry = (process.env.R2_CATALOG_NAMESPACES ?? namespace).split(",").map((n) => n.trim()).filter(Boolean);

let dropped = 0;
let absent = 0;
let failed = 0;

for (const ns of namespacesToTry) {
  for (const table of tables) {
    const url = `${catalogUri}/namespaces/${encodeURIComponent(ns)}/tables/${encodeURIComponent(table)}`;
    const res = await fetch(url, { method: "DELETE", headers: authHeaders });
    if (res.status === 200 || res.status === 204) {
      console.log(`✓ dropped ${ns}.${table}`);
      dropped += 1;
    } else if (res.status === 404) {
      console.log(`· not found: ${ns}.${table}`);
      absent += 1;
    } else {
      console.error(`✘ drop ${ns}.${table}: ${res.status} ${await res.text()}`);
      failed += 1;
    }
  }
}

console.log(`\nDropped ${dropped}, not found ${absent}, failed ${failed}.`);
process.exit(failed === 0 ? 0 : 1);
