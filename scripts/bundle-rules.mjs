import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { loadSigmaRulesFromDir } from "../packages/rules/dist/index.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const rulesDir = resolve(root, "rules");
const detectionOutputFile = resolve(root, "workers/detection/src/generated-rules.ts");
const scheduledOutputFile = resolve(root, "workers/scheduled-detection/src/generated-rules.ts");

const ruleOrder = [
  "aws-root-account-usage",
  "aws-console-login-without-mfa",
  "aws-iam-policy-attached-to-user",
  "k8s-anonymous-api-request-succeeded",
  "k8s-excessive-failed-auth",
  "okta-brute-force",
  "okta-impossible-travel"
];
const rules = loadSigmaRulesFromDir(rulesDir)
  .filter((rule) => rule.enabled)
  .sort((left, right) => orderOf(left.id) - orderOf(right.id));
const sigmaRules = rules.filter((rule) => rule.execution === "sigma");
const statefulRules = rules.filter((rule) => rule.execution === "stateful");
const sqlRules = rules.filter((rule) => rule.execution === "sql");

// Realtime engine bundle (workers/detection): sigma + stateful rules.
const detectionContents = `// AUTO-GENERATED - do not edit. Run \`pnpm build:rules\` to regenerate.
import type { SigmaRule } from "@picket/sigma-engine";

export const SIGMA_RULES: SigmaRule[] = ${JSON.stringify(sigmaRules, null, 2)};

export const STATEFUL_RULES: SigmaRule[] = ${JSON.stringify(statefulRules, null, 2)};
`;
writeAtomic(detectionOutputFile, detectionContents);

// Scheduled engine bundle (workers/scheduled-detection): sql rules only.
const scheduledContents = `// AUTO-GENERATED - do not edit. Run \`pnpm build:rules\` to regenerate.
import type { SigmaRule } from "@picket/sigma-engine";

export const SQL_RULES: SigmaRule[] = ${JSON.stringify(sqlRules, null, 2)};
`;
writeAtomic(scheduledOutputFile, scheduledContents);

// Write via a temp file + rename so concurrent `build:rules` invocations (each
// worker's test/typecheck script runs it) can never expose a partial file to a
// reader mid-write. The rename is atomic on the same filesystem.
function writeAtomic(file, contents) {
  mkdirSync(dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, contents);
  renameSync(tmp, file);
}

function orderOf(ruleId) {
  const index = ruleOrder.indexOf(ruleId);
  return index === -1 ? Number.MAX_SAFE_INTEGER : index;
}
