#!/usr/bin/env node

// Syncs IDs from `terraform output -json` into the worker wrangler.jsonc
// files. Run after every `terraform apply` that creates or recreates D1
// databases or pipeline streams — those IDs change on each recreate and
// the wrangler configs reference them literally.
//
// Updates:
//   - workers/admin/wrangler.jsonc        AUTH_DB + ALERT_STATE_DB ids + enrichment pipelines
//   - workers/ingest/wrangler.jsonc       AUTH_DB + ALERT_STATE_DB + per-source pipelines
//   - workers/detection/wrangler.jsonc    ALERT_STATE_DB + ALERTS_PIPELINE
//   - workers/alert-router/wrangler.jsonc ALERT_STATE_DB

import { readFile, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..");
const tfDir = resolve(repoRoot, "terraform/platform");

const tfOutput = spawnSync("terraform", ["output", "-json"], {
  cwd: tfDir,
  encoding: "utf8"
});
if (tfOutput.status !== 0) {
  console.error(`terraform output failed:\n${tfOutput.stderr}`);
  process.exit(1);
}

const outputs = JSON.parse(tfOutput.stdout);
const get = (name) => outputs[name]?.value;

const alertStateId = get("d1_database_id");
const authDbId = get("auth_d1_database_id");
const streamIds = get("stream_ids") ?? {};

if (!alertStateId || !authDbId) {
  console.error("Missing d1_database_id or auth_d1_database_id outputs.");
  process.exit(1);
}

const requiredStreams = [
  "alerts",
  "assets",
  "aws_cloudtrail",
  "aws_guardduty",
  "aws_vpc_flow",
  "azure_activity",
  "azure_ad_signin",
  "cloudflare_audit",
  "gcp_cloud_audit",
  "github_audit",
  "kubernetes_audit",
  "m365_management",
  "threat_intel",
  "users"
];
const missingStreams = requiredStreams.filter((name) => !streamIds[name]);
if (missingStreams.length > 0) {
  console.error(`Missing required stream_ids Terraform outputs: ${missingStreams.join(", ")}`);
  process.exit(1);
}

const edits = [
  {
    path: "workers/admin/wrangler.jsonc",
    replacements: [
      [/"binding":\s*"AUTH_DB"[^}]*?"database_id":\s*"[^"]+"/, (m) => m.replace(/"database_id":\s*"[^"]+"/, `"database_id": "${authDbId}"`)],
      [/"binding":\s*"ALERT_STATE_DB"[^}]*?"database_id":\s*"[^"]+"/, (m) => m.replace(/"database_id":\s*"[^"]+"/, `"database_id": "${alertStateId}"`)],
      [/"binding":\s*"THREAT_INTEL_PIPELINE"[^}]*?"pipeline":\s*"[^"]+"/, (m) => m.replace(/"pipeline":\s*"[^"]+"/, `"pipeline": "${streamIds.threat_intel}"`)],
      [/"binding":\s*"ASSETS_PIPELINE"[^}]*?"pipeline":\s*"[^"]+"/, (m) => m.replace(/"pipeline":\s*"[^"]+"/, `"pipeline": "${streamIds.assets}"`)],
      [/"binding":\s*"USERS_PIPELINE"[^}]*?"pipeline":\s*"[^"]+"/, (m) => m.replace(/"pipeline":\s*"[^"]+"/, `"pipeline": "${streamIds.users}"`)]
    ]
  },
  {
    path: "workers/ingest/wrangler.jsonc",
    replacements: [
      [/"binding":\s*"AUTH_DB"[^}]*?"database_id":\s*"[^"]+"/, (m) => m.replace(/"database_id":\s*"[^"]+"/, `"database_id": "${authDbId}"`)],
      [/"binding":\s*"ALERT_STATE_DB"[^}]*?"database_id":\s*"[^"]+"/, (m) => m.replace(/"database_id":\s*"[^"]+"/, `"database_id": "${alertStateId}"`)],
      [/"binding":\s*"AWS_CLOUDTRAIL_PIPELINE"[^}]*?"pipeline":\s*"[^"]+"/, (m) => m.replace(/"pipeline":\s*"[^"]+"/, `"pipeline": "${streamIds.aws_cloudtrail}"`)],
      [/"binding":\s*"AWS_VPC_FLOW_PIPELINE"[^}]*?"pipeline":\s*"[^"]+"/, (m) => m.replace(/"pipeline":\s*"[^"]+"/, `"pipeline": "${streamIds.aws_vpc_flow}"`)],
      [/"binding":\s*"AWS_GUARDDUTY_PIPELINE"[^}]*?"pipeline":\s*"[^"]+"/, (m) => m.replace(/"pipeline":\s*"[^"]+"/, `"pipeline": "${streamIds.aws_guardduty}"`)],
      [/"binding":\s*"GCP_CLOUD_AUDIT_PIPELINE"[^}]*?"pipeline":\s*"[^"]+"/, (m) => m.replace(/"pipeline":\s*"[^"]+"/, `"pipeline": "${streamIds.gcp_cloud_audit}"`)],
      [/"binding":\s*"AZURE_ACTIVITY_PIPELINE"[^}]*?"pipeline":\s*"[^"]+"/, (m) => m.replace(/"pipeline":\s*"[^"]+"/, `"pipeline": "${streamIds.azure_activity}"`)],
      [/"binding":\s*"AZURE_AD_SIGNIN_PIPELINE"[^}]*?"pipeline":\s*"[^"]+"/, (m) => m.replace(/"pipeline":\s*"[^"]+"/, `"pipeline": "${streamIds.azure_ad_signin}"`)],
      [/"binding":\s*"GITHUB_AUDIT_PIPELINE"[^}]*?"pipeline":\s*"[^"]+"/, (m) => m.replace(/"pipeline":\s*"[^"]+"/, `"pipeline": "${streamIds.github_audit}"`)],
      [/"binding":\s*"M365_MANAGEMENT_PIPELINE"[^}]*?"pipeline":\s*"[^"]+"/, (m) => m.replace(/"pipeline":\s*"[^"]+"/, `"pipeline": "${streamIds.m365_management}"`)],
      [/"binding":\s*"KUBERNETES_AUDIT_PIPELINE"[^}]*?"pipeline":\s*"[^"]+"/, (m) => m.replace(/"pipeline":\s*"[^"]+"/, `"pipeline": "${streamIds.kubernetes_audit}"`)],
      [/"binding":\s*"CLOUDFLARE_AUDIT_PIPELINE"[^}]*?"pipeline":\s*"[^"]+"/, (m) => m.replace(/"pipeline":\s*"[^"]+"/, `"pipeline": "${streamIds.cloudflare_audit}"`)]
    ]
  },
  {
    path: "workers/detection/wrangler.jsonc",
    replacements: [
      [/"binding":\s*"ALERT_STATE_DB"[^}]*?"database_id":\s*"[^"]+"/, (m) => m.replace(/"database_id":\s*"[^"]+"/, `"database_id": "${alertStateId}"`)],
      [/"binding":\s*"ALERTS_PIPELINE"[^}]*?"pipeline":\s*"[^"]+"/, (m) => m.replace(/"pipeline":\s*"[^"]+"/, `"pipeline": "${streamIds.alerts}"`)]
    ]
  },
  {
    path: "workers/alert-router/wrangler.jsonc",
    replacements: [
      [/"binding":\s*"ALERT_STATE_DB"[^}]*?"database_id":\s*"[^"]+"/, (m) => m.replace(/"database_id":\s*"[^"]+"/, `"database_id": "${alertStateId}"`)]
    ]
  },
  {
    path: "workers/query-runner/wrangler.jsonc",
    replacements: [
      [/"binding":\s*"ALERT_STATE_DB"[^}]*?"database_id":\s*"[^"]+"/, (m) => m.replace(/"database_id":\s*"[^"]+"/, `"database_id": "${alertStateId}"`)]
    ]
  }
];

for (const { path, replacements } of edits) {
  const full = resolve(repoRoot, path);
  let body = await readFile(full, "utf8");
  let touched = 0;
  for (const [regex, fn] of replacements) {
    const next = body.replace(regex, fn);
    if (next !== body) touched += 1;
    body = next;
  }
  await writeFile(full, body);
  console.log(`✓ ${path}: ${touched} binding(s) updated`);
}

console.log("\nSynced. Run `pnpm deploy:cloudflare` to push to Cloudflare.");
