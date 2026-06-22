#!/usr/bin/env node

// Generates each worker's `wrangler.jsonc` from its committed, account-neutral
// `wrangler.template.jsonc` by substituting `__TOKEN__` placeholders with the
// concrete, account-specific values from `terraform output -json`.
//
// The generated `wrangler.jsonc` files are gitignored: they hold IDs and
// domains unique to whichever Cloudflare account ran `terraform apply`, so they
// must never be committed. Run this after every apply that creates or recreates
// D1 databases, pipeline streams, KV, or the Access app — and it runs
// automatically as the first step of `pnpm deploy:cloudflare`.
//
// To use this project in your own account: `terraform apply` in
// terraform/platform, then `pnpm gen:wrangler`, then `pnpm deploy:cloudflare`.

import { readFile, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..");
const tfDir = resolve(repoRoot, "terraform/platform");

// Workers whose wrangler.jsonc is generated from a template. (detection's
// wrangler.test.jsonc is hand-maintained and account-neutral — not listed.)
export const WORKERS = [
  "detection",
  "alert-router",
  "ingest",
  "admin",
  "query-runner",
  "scheduled-detection"
];

// Placeholder → terraform output value. Stream tokens (`__STREAM_<KEY>__`) are
// derived from the `stream_ids` map so new sources need no change here.
export function buildTokenMap(outputs) {
  const value = (name) => outputs[name]?.value;
  const streams = value("stream_ids") ?? {};

  const map = {
    __AUTH_DB_ID__: value("auth_d1_database_id"),
    __ALERT_STATE_DB_ID__: value("d1_database_id"),
    __ENRICHMENT_KV_ID__: value("kv_namespace_id"),
    __CF_ACCESS_TEAM_DOMAIN__: value("cf_access_team_domain"),
    __CF_ACCESS_AUD__: value("cf_access_aud"),
    __PICKET_R2_WAREHOUSE__: value("r2_catalog_warehouse"),
    __PICKET_TABLE_SUFFIX__: value("r2_catalog_table_suffix")
  };
  for (const [key, id] of Object.entries(streams)) {
    map[`__STREAM_${key.toUpperCase()}__`] = id;
  }
  return map;
}

export function readTerraformOutputs() {
  const result = spawnSync("terraform", ["output", "-json"], {
    cwd: tfDir,
    encoding: "utf8"
  });
  if (result.status !== 0) {
    throw new Error(
      `\`terraform output -json\` failed in ${tfDir}:\n${result.stderr}\n` +
        "Run `terraform apply` in terraform/platform first."
    );
  }
  return JSON.parse(result.stdout);
}

// Only run when invoked directly (not when imported for template extraction).
if (process.argv[1] === import.meta.filename) {
  await main();
}

async function main() {
  const outputs = readTerraformOutputs();
  const tokens = buildTokenMap(outputs);

  // A null value means terraform hasn't produced it yet. The Access AUD is the
  // common one: it stays null until `picket_admin_worker_deployed = true`,
  // which is itself a two-phase bootstrap (deploy admin once, flip the flag,
  // re-apply, regenerate). Fail loudly with that context rather than emitting a
  // literal "null" into a deployed config.
  const unresolved = Object.entries(tokens)
    .filter(([, v]) => v == null || v === "")
    .map(([k]) => k);
  if (unresolved.length > 0) {
    const aud = unresolved.includes("__CF_ACCESS_AUD__")
      ? "\n\n__CF_ACCESS_AUD__ is null until the picket-admin Access app exists: " +
        "deploy picket-admin once, set `picket_admin_worker_deployed = true`, " +
        "`terraform apply`, then re-run `pnpm gen:wrangler`."
      : "";
    throw new Error(
      `Terraform outputs missing values for: ${unresolved.join(", ")}.` + aud
    );
  }

  for (const worker of WORKERS) {
    const templatePath = resolve(repoRoot, `workers/${worker}/wrangler.template.jsonc`);
    const outputPath = resolve(repoRoot, `workers/${worker}/wrangler.jsonc`);

    let body = await readFile(templatePath, "utf8");
    for (const [token, replacement] of Object.entries(tokens)) {
      body = body.split(token).join(replacement);
    }

    const leftover = body.match(/__[A-Z0-9_]+__/g);
    if (leftover) {
      throw new Error(
        `workers/${worker}/wrangler.template.jsonc has unknown placeholders: ` +
          `${[...new Set(leftover)].join(", ")}. Add them to buildTokenMap().`
      );
    }

    await writeFile(outputPath, body);
    console.log(`✓ workers/${worker}/wrangler.jsonc generated`);
  }

  console.log("\nGenerated. Run `pnpm deploy:cloudflare` to push to Cloudflare.");
}
