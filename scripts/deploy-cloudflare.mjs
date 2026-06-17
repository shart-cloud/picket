#!/usr/bin/env node

import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";

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

await assertBindingsResolved(workerConfigs);
await run("pnpm", ["build"]);

for (const config of workerConfigs) {
  await run("pnpm", ["wrangler", "deploy", "--config", config]);
}

console.log("picket deployed. Configure alert destination secrets with wrangler secret put before production use.");

async function assertBindingsResolved(configs) {
  const unresolved = [];
  for (const config of configs) {
    const body = await readFile(config, "utf8");
    if (body.includes('"MISSING"')) unresolved.push(config);
  }

  if (unresolved.length === 0) return;
  throw new Error(
    `Unresolved Wrangler bindings in:\n${unresolved.map((config) => `  - ${config}`).join("\n")}\n` +
      "Run `pnpm sync:wrangler-bindings` after `terraform apply` before deploying."
  );
}

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
