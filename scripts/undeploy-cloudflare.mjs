#!/usr/bin/env node

import { spawn } from "node:child_process";

// Deletes the deployed Worker scripts. Infra (queue, D1, R2, KV, Pipelines,
// Data Catalog, Access app, custom domain) is terraform-owned — run
// `terraform destroy` separately after this script completes.
//
// Each delete is best-effort: a 404 means the Worker is already gone, which
// is fine. Anything else fails loudly.

const workers = [
  "picket-ingest",
  "picket-detection",
  "picket-alert-router",
  "picket-admin",
  "picket-query-runner",
  "picket-scheduled-detection"
];

for (const worker of workers) {
  await run("pnpm", ["wrangler", "delete", "--name", worker], {
    allowFailure: true,
    failureMessage: `Worker ${worker} may already be deleted; continuing.`
  });
}

console.log("Workers undeployed. Run `terraform destroy` from terraform/platform to tear down infra.");

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
