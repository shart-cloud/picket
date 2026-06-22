#!/usr/bin/env node

import { spawn } from "node:child_process";

// Infra (queue, D1, R2, KV, Pipelines, Data Catalog) is managed by
// terraform/platform. This script only builds and deploys the Worker bundles.

const workerConfigs = [
  "workers/detection/wrangler.jsonc",
  "workers/alert-router/wrangler.jsonc",
  "workers/ingest/wrangler.jsonc",
  "workers/admin/wrangler.jsonc",
  "workers/query-runner/wrangler.jsonc",
  "workers/scheduled-detection/wrangler.jsonc"
];

// Regenerate the gitignored wrangler.jsonc files from their templates +
// `terraform output` so a stale apply can't ship outdated IDs. Fails loudly if
// terraform hasn't produced the required outputs yet.
await run("node", ["scripts/gen-wrangler.mjs"]);
await run("pnpm", ["build"]);

for (const config of workerConfigs) {
  await run("pnpm", ["wrangler", "deploy", "--config", config]);
}

console.log("picket deployed. Configure alert destination secrets with wrangler secret put before production use.");

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: "inherit",
      shell: false
    });

    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve();
        return;
      }

      if (options.allowFailure) {
        if (options.failureMessage) console.warn(options.failureMessage);
        resolve();
        return;
      }

      reject(new Error(`${command} ${args.join(" ")} failed with exit code ${code}`));
    });
  });
}
