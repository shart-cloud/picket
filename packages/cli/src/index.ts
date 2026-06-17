#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { spawn } from "node:child_process";

import { evaluateEvent } from "@picket/detection-worker/evaluator";
import { normalizeCloudTrail } from "@picket/normalize";
import {
  formatRows,
  presetQuery,
  PRESET_QUERY_NAMES as QUERY_PRESET_NAMES,
  type PresetQueryName,
  type QueryOutputFormat
} from "@picket/query";
import {
  AdminApiError,
  AdminClient,
  QueryJobFailedError,
  type AssetRecord,
  type QueryJob,
  type UserRecord
} from "./admin-client.js";
import type { CloudflaredRunner } from "./auth/cloudflared.js";
import {
  createCredentialsIo,
  lookupCredential,
  normalizeApiUrl,
  removeCredential,
  type CredentialsIo
} from "./auth/credentials.js";
import { DeviceAuthError, runLogin } from "./auth/login.js";
import { resolveAuth, toAdminClientOptions } from "./auth/resolve.js";

import {
  ALERT_SEVERITIES,
  ALERT_STATUSES,
  AlertNotFoundError,
  formatAlertDetail,
  formatAlertsTable,
  formatAlertStats,
  type AlertSeverity,
  type AlertStatus
} from "@picket/core/alerts";
import {
  formatSourceHealthTable,
  type SourceHealthRow
} from "@picket/core/source-health";
import { formatDashboardOverview } from "@picket/core/dashboard";
import { formatOcsfSchema, formatSourceStatus } from "@picket/core/sources";
import { formatQueryHistoryTable, formatSavedQueriesTable } from "@picket/core/saved-queries";
import { formatScheduledDetectionsTable } from "@picket/core/scheduled-detection";
import { formatIocTable, isIndicatorType, type IndicatorType, type IocRecord } from "@picket/core/enrichment";
import {
  formatDetectionHealth,
  type DetectionHealthRow
} from "@picket/core/detection-health";
import type { DetectionRuleRow } from "@picket/core/detection-rules";

interface CliIo {
  stdout: Pick<NodeJS.WriteStream, "write">;
  stderr: Pick<NodeJS.WriteStream, "write">;
}

export interface MainOptions {
  adminClient?: AdminClient;
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  runCommand?: RunCommand;
  now?: () => Date;
  // Auth-flow injection points. Tests pass fakes here; production leaves them
  // undefined and gets real filesystem / cloudflared / fetch / setTimeout.
  credentialsIo?: CredentialsIo;
  cloudflared?: CloudflaredRunner;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  openBrowser?: (url: string) => Promise<void> | void;
}

export type RunCommand = (command: string, args: string[], options?: { cwd?: string }) => Promise<void>;

interface QueryArgs {
  preset?: string;
  sql?: string;
  hours?: number;
  limit?: number;
  format: QueryOutputFormat;
  warehouse?: string;
  tableSuffix?: string;
  printOnly: boolean;
  async: boolean;
  jobId?: string;
  apiUrl?: string;
  accessClientId?: string;
  accessClientSecret?: string;
  idempotencyKey?: string;
  verbose: boolean;
}

interface AlertsListArgs {
  status?: AlertStatus;
  severity?: AlertSeverity;
  limit: number;
  format: "table" | "json";
}

const PRESET_QUERY_NAMES = new Set<PresetQueryName>(QUERY_PRESET_NAMES);

export async function main(
  argv = process.argv.slice(2),
  io: CliIo = process,
  options: MainOptions = {}
): Promise<number> {
  const [command, ...args] = argv;

  try {
    switch (command) {
      case "test-event":
        return await testEvent(args, io);
      case "test":
        return await testCommand(args, io);
      case "init":
        return await initCommand(args, io, options);
      case "deploy":
        return await deployCommand(args, io, options);
      case "query":
        return await queryCommand(args, io, options);
      case "alerts":
        return await alertsCommand(args, io, options);
      case "detections":
        return await detectionsCommand(args, io, options);
      case "status":
        return await statusCommand(args, io, options);
      case "dashboard":
        return await dashboardCommand(args, io, options);
      case "sources":
        return await sourcesCommand(args, io, options);
      case "enrichment":
        return await enrichmentCommand(args, io, options);
      case "login":
        return await loginCommand(args, io, options);
      case "logout":
        return await logoutCommand(args, io, options);
      case "whoami":
        return await whoamiCommand(args, io, options);
      case "help":
      case "--help":
      case "-h":
      case undefined:
        io.stdout.write(`${usage()}\n`);
        return command ? 0 : 1;
      default:
        io.stderr.write(`Unknown command: ${command}\n\n${usage()}\n`);
        return 1;
    }
  } catch (error) {
    io.stderr.write(`${errorMessage(error)}\n`);
    return 1;
  }
}

async function testEvent(args: string[], io: CliIo): Promise<number> {
  if (args.length !== 1 || args[0] === undefined) {
    io.stderr.write(`Usage: picket test-event <cloudtrail-json-file>\n`);
    return 1;
  }

  const raw = JSON.parse(await readFile(args[0], "utf8")) as unknown;
  if (!isJsonObject(raw)) {
    throw new Error("CloudTrail fixture must be a JSON object.");
  }

  const normalizedEvent = normalizeCloudTrail(raw);
  const alerts = evaluateEvent(normalizedEvent);

  io.stdout.write(`${JSON.stringify({ normalized_event: normalizedEvent, alerts }, null, 2)}\n`);
  return 0;
}

async function testCommand(args: string[], io: CliIo): Promise<number> {
  if (args.length !== 1 || args[0] === undefined) {
    io.stderr.write(`Usage: picket test <cloudtrail-json-file>\n`);
    io.stderr.write(`Historical rule backtesting is not implemented yet; use this for local event dry-runs.\n`);
    return 1;
  }
  return testEvent(args, io);
}

interface InitArgs {
  directory: string;
  force: boolean;
}

async function initCommand(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseInitArgs(args);
  const root = join(options.cwd ?? process.cwd(), parsed.directory);
  const files = new Map<string, string>([
    [
      "terraform/main.tf",
      `module "picket_platform" {\n  source = "../terraform/platform"\n\n  cloudflare_account_id = var.cloudflare_account_id\n}\n`
    ],
    [
      "terraform/variables.tf",
      `variable "cloudflare_account_id" {\n  type        = string\n  description = "Cloudflare account ID where Picket is deployed."\n}\n`
    ],
    [
      "detections/aws_root_login/rule.yml",
      `# Copy or symlink production Sigma rules here when custom rule deployment is enabled.\n`
    ],
    [
      "enrichment/threat_intel.csv",
      `indicator,indicator_type,feed_name,threat_type\n`
    ],
    [
      "picket.config.yml",
      `terraform_dir: terraform\ndetections_dir: detections\nenrichment_dir: enrichment\n`
    ]
  ]);

  for (const [relative, body] of files) {
    const path = join(root, relative);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, body, { flag: parsed.force ? "w" : "wx" });
  }

  io.stdout.write(`Initialized Picket project in ${parsed.directory}\n`);
  return 0;
}

interface DeployArgs {
  skipTerraform: boolean;
  skipBindings: boolean;
  skipWorkers: boolean;
}

async function deployCommand(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseDeployArgs(args);
  const run = options.runCommand ?? runCommand;
  const cwd = options.cwd ?? process.cwd();

  if (!parsed.skipTerraform) {
    io.stdout.write(`Applying Terraform platform infrastructure...\n`);
    await run("terraform", ["-chdir=terraform/platform", "apply"], { cwd });
  }
  if (!parsed.skipBindings) {
    io.stdout.write(`Syncing Wrangler bindings from Terraform outputs...\n`);
    await run("pnpm", ["sync:wrangler-bindings"], { cwd });
  }
  if (!parsed.skipWorkers) {
    io.stdout.write(`Deploying Worker bundles with Wrangler...\n`);
    await run("pnpm", ["deploy:cloudflare"], { cwd });
  }

  io.stdout.write(`Picket deployment steps completed.\n`);
  return 0;
}

// `picket query` is overloaded: bare flags run a query, while the management
// verbs (history/saved/save/explain) are subcommands. Dispatch on the first arg.
async function queryCommand(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  switch (args[0]) {
    case "history":
      return await queryHistory(args.slice(1), io, options);
    case "saved":
      return await querySaved(args.slice(1), io, options);
    case "save":
      return await querySave(args.slice(1), io, options);
    case "explain":
      return await queryExplain(args.slice(1), io, options);
    case "natural":
      return await queryNatural(args.slice(1), io, options);
    default:
      return await query(args, io, options);
  }
}

async function query(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseQueryArgs(args);
  const env = options.env ?? process.env;
  const tableSuffix = parsed.tableSuffix ?? env.PICKET_TABLE_SUFFIX;

  // --print-only renders SQL locally without execution. Doesn't talk to the
  // admin API — useful for analysts inspecting what a preset expands to.
  if (parsed.printOnly) {
    if (parsed.jobId) {
      io.stderr.write(`--print-only and --job-id are mutually exclusive.\n`);
      return 1;
    }
    if (!parsed.preset) {
      io.stderr.write(`--print-only only applies to --preset (raw --sql is already printable).\n`);
      return 1;
    }
    if (!PRESET_QUERY_NAMES.has(parsed.preset as PresetQueryName)) {
      io.stderr.write(
        `Unknown query preset: ${parsed.preset}\nAvailable presets: ${[...PRESET_QUERY_NAMES].join(", ")}\n`
      );
      return 1;
    }
    const sql = presetQuery(parsed.preset as PresetQueryName, {
      hours: parsed.hours,
      limit: parsed.limit,
      tableSuffix
    });
    io.stdout.write(`${sql}\n`);
    return 0;
  }

  const adminClient = await resolveAdminClient(options, env, parsed);
  if (!adminClient) {
    io.stderr.write(
      `Admin API URL required. Pass --api-url <url> or set PICKET_API_URL.\n`
    );
    return 1;
  }

  // --job-id resumes polling on an existing job and prints its result. No
  // new submission, no body validation.
  if (parsed.jobId) {
    if (parsed.preset || parsed.sql !== undefined) {
      io.stderr.write(`--job-id is mutually exclusive with --preset and --sql.\n`);
      return 1;
    }
    try {
      const job = parsed.async
        ? await adminClient.getJob(parsed.jobId)
        : await adminClient.waitForJob(parsed.jobId);
      return renderJob(job, parsed, io);
    } catch (error) {
      return reportQueryError(error, io);
    }
  }

  // From here on we're submitting a new query — validate inputs.
  if (parsed.preset && parsed.sql !== undefined) {
    io.stderr.write(`--preset and --sql are mutually exclusive.\n`);
    return 1;
  }
  if (!parsed.preset && parsed.sql === undefined) {
    io.stderr.write(
      `Usage: picket query (--preset <name> | --sql "<query>" | --job-id <id>) [--hours <n>] [--limit <n>] [--format table|json|csv] [--async] [--print-only]\n`
    );
    return 1;
  }
  if ((parsed.hours !== undefined || parsed.limit !== undefined) && parsed.sql !== undefined) {
    io.stderr.write(`--hours and --limit are only valid with --preset.\n`);
    return 1;
  }
  if (parsed.preset && !PRESET_QUERY_NAMES.has(parsed.preset as PresetQueryName)) {
    io.stderr.write(
      `Unknown query preset: ${parsed.preset}\nAvailable presets: ${[...PRESET_QUERY_NAMES].join(", ")}\n`
    );
    return 1;
  }

  try {
    const job = await adminClient.submitQuery(
      {
        preset: parsed.preset,
        sql: parsed.sql,
        hours: parsed.hours,
        limit: parsed.limit,
        table_suffix: tableSuffix,
        warehouse: parsed.warehouse
      },
      parsed.idempotencyKey ? { idempotencyKey: parsed.idempotencyKey } : {}
    );

    // --async: return immediately with the id (200 or 202 both apply).
    if (parsed.async) {
      if (job.status === "succeeded") return renderJob(job, parsed, io);
      io.stdout.write(`${JSON.stringify({ id: job.id, status: job.status, location: job.location ?? `/api/v1/query/${job.id}` })}\n`);
      return 0;
    }

    if (job.status === "succeeded") return renderJob(job, parsed, io);
    if (job.status === "failed") throw new QueryJobFailedError(job);

    const final = await adminClient.waitForJob(job.id);
    return renderJob(final, parsed, io);
  } catch (error) {
    return reportQueryError(error, io);
  }
}

interface QueryBodyArgs {
  preset?: string;
  sql?: string;
  hours?: number;
  limit?: number;
  tableSuffix?: string;
  name?: string;
  description?: string;
  owner?: string;
  format: "table" | "json";
  apiUrl?: string;
  accessClientId?: string;
  accessClientSecret?: string;
}

function parseQueryBodyArgs(args: string[]): QueryBodyArgs {
  const parsed: QueryBodyArgs = { format: "table" };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) continue;
    const value = args[index + 1];
    if (arg === "--preset") {
      parsed.preset = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--sql") {
      if (value === undefined) throw new Error(`Missing value for ${arg}.`);
      parsed.sql = value;
      index += 1;
    } else if (arg === "--hours") {
      parsed.hours = positiveInteger(arg, requiredValue(arg, value));
      index += 1;
    } else if (arg === "--limit") {
      parsed.limit = positiveInteger(arg, requiredValue(arg, value));
      index += 1;
    } else if (arg === "--table-suffix") {
      parsed.tableSuffix = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--name") {
      parsed.name = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--description") {
      if (value === undefined) throw new Error(`Missing value for ${arg}.`);
      parsed.description = value;
      index += 1;
    } else if (arg === "--owner") {
      parsed.owner = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--format") {
      const v = requiredValue(arg, value);
      if (v !== "table" && v !== "json") throw new Error("--format must be one of: table, json");
      parsed.format = v;
      index += 1;
    } else if (arg === "--api-url") {
      parsed.apiUrl = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--access-client-id") {
      parsed.accessClientId = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--access-client-secret") {
      parsed.accessClientSecret = requiredValue(arg, value);
      index += 1;
    } else {
      throw new Error(`Unknown query option: ${arg}`);
    }
  }
  return parsed;
}

async function queryExplain(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseQueryBodyArgs(args);
  if (!parsed.preset && parsed.sql === undefined) {
    io.stderr.write(`Usage: picket query explain (--preset <name> | --sql "<query>") [--hours <n>] [--limit <n>] [--format table|json]\n`);
    return 1;
  }
  const adminClient = await requireAdminClient(io, options, parsed);
  if (!adminClient) return 1;
  try {
    const explain = await adminClient.explainQuery({
      preset: parsed.preset,
      sql: parsed.sql,
      hours: parsed.hours,
      limit: parsed.limit,
      table_suffix: parsed.tableSuffix
    });
    if (parsed.format === "json") {
      io.stdout.write(`${JSON.stringify(explain, null, 2)}\n`);
    } else {
      const lines = [
        explain.sql,
        "",
        `valid:           ${explain.valid}`,
        `tables:          ${explain.plan.tables.join(", ") || "-"}`,
        `has_join:        ${explain.plan.has_join}`,
        `has_time_filter: ${explain.plan.has_time_filter}`,
        `has_limit:       ${explain.plan.has_limit}`,
        `read_only:       ${explain.plan.read_only}`
      ];
      if (explain.errors.length > 0) lines.push("", `errors:   ${explain.errors.join("; ")}`);
      if (explain.warnings.length > 0) lines.push(`warnings: ${explain.warnings.join("; ")}`);
      io.stdout.write(`${lines.join("\n")}\n`);
    }
    return 0;
  } catch (error) {
    return reportQueryError(error, io);
  }
}

async function querySave(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseQueryBodyArgs(args);
  if (!parsed.name) {
    io.stderr.write(`Usage: picket query save --name <name> (--preset <name> | --sql "<query>") [--description <text>]\n`);
    return 1;
  }
  if (!parsed.preset && parsed.sql === undefined) {
    io.stderr.write(`picket query save requires --preset or --sql.\n`);
    return 1;
  }
  const adminClient = await requireAdminClient(io, options, parsed);
  if (!adminClient) return 1;
  try {
    const saved = await adminClient.saveQuery({
      name: parsed.name,
      description: parsed.description,
      preset: parsed.preset,
      sql: parsed.sql,
      hours: parsed.hours,
      limit: parsed.limit,
      table_suffix: parsed.tableSuffix
    });
    io.stdout.write(`Saved query "${saved.name}" (id=${saved.id}, owner=${saved.owner}).\n`);
    return 0;
  } catch (error) {
    if (error instanceof AdminApiError && error.status === 400) {
      io.stderr.write(`${error.message}\n`);
      return 1;
    }
    return reportQueryError(error, io);
  }
}

async function querySaved(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseQueryBodyArgs(args);
  const adminClient = await requireAdminClient(io, options, parsed);
  if (!adminClient) return 1;
  const saved = await adminClient.listSavedQueries({ owner: parsed.owner, limit: parsed.limit });
  if (parsed.format === "json") {
    io.stdout.write(`${JSON.stringify(saved, null, 2)}\n`);
  } else {
    io.stdout.write(`${formatSavedQueriesTable(saved)}\n`);
  }
  return 0;
}

interface QueryNaturalArgs {
  question?: string;
  format: QueryOutputFormat;
  async: boolean;
  apiUrl?: string;
  accessClientId?: string;
  accessClientSecret?: string;
}

function parseQueryNaturalArgs(args: string[]): QueryNaturalArgs {
  const parsed: QueryNaturalArgs = { format: "table", async: false };
  const questionParts: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) continue;
    const value = args[index + 1];
    if (arg === "--format") {
      const v = requiredValue(arg, value);
      if (v !== "table" && v !== "json" && v !== "csv") throw new Error("--format must be one of: table, json, csv");
      parsed.format = v;
      index += 1;
    } else if (arg === "--async") {
      parsed.async = true;
    } else if (arg === "--api-url") {
      parsed.apiUrl = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--access-client-id") {
      parsed.accessClientId = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--access-client-secret") {
      parsed.accessClientSecret = requiredValue(arg, value);
      index += 1;
    } else if (arg.startsWith("--")) {
      throw new Error(`Unknown query natural option: ${arg}`);
    } else {
      questionParts.push(arg);
    }
  }
  parsed.question = questionParts.join(" ").trim() || undefined;
  return parsed;
}

async function queryNatural(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseQueryNaturalArgs(args);
  if (!parsed.question) {
    io.stderr.write(`Usage: picket query natural "<question>" [--format table|json|csv] [--async]\n`);
    return 1;
  }
  const adminClient = await requireAdminClient(io, options, parsed);
  if (!adminClient) return 1;

  const renderArgs: QueryArgs = { format: parsed.format, printOnly: false, async: parsed.async, verbose: false };
  try {
    const job = await adminClient.naturalQuery(parsed.question);
    if (job.generated_sql) {
      io.stderr.write(`-- generated SQL${job.rationale ? ` (${job.rationale})` : ""}:\n${job.generated_sql}\n`);
    }
    if (parsed.async) {
      if (job.status === "succeeded") return renderJob(job, renderArgs, io);
      io.stdout.write(
        `${JSON.stringify({ id: job.id, status: job.status, location: job.location ?? `/api/v1/query/${job.id}`, generated_sql: job.generated_sql })}\n`
      );
      return 0;
    }
    if (job.status === "succeeded") return renderJob(job, renderArgs, io);
    if (job.status === "failed") throw new QueryJobFailedError(job);
    const final = await adminClient.waitForJob(job.id);
    return renderJob(final, renderArgs, io);
  } catch (error) {
    return reportQueryError(error, io);
  }
}

async function queryHistory(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseQueryBodyArgs(args);
  const adminClient = await requireAdminClient(io, options, parsed);
  if (!adminClient) return 1;
  const history = await adminClient.listQueryHistory({ owner: parsed.owner, limit: parsed.limit });
  if (parsed.format === "json") {
    io.stdout.write(`${JSON.stringify(history, null, 2)}\n`);
  } else {
    io.stdout.write(`${formatQueryHistoryTable(history)}\n`);
  }
  return 0;
}

function renderJob(job: QueryJob, parsed: QueryArgs, io: CliIo): number {
  if (job.status !== "succeeded" || !job.result) {
    // Async / job-id callers may get a non-terminal job back. Emit a JSON
    // summary so the caller can poll later.
    io.stdout.write(
      `${JSON.stringify({ id: job.id, status: job.status, location: job.location ?? `/api/v1/query/${job.id}` })}\n`
    );
    return 0;
  }
  if (parsed.verbose || job.bytes_scanned !== null || job.row_count !== null) {
    io.stderr.write(
      `job ${job.id}: rows=${job.row_count ?? "?"} bytes=${job.bytes_scanned ?? "?"} files=${job.files_scanned ?? "?"}\n`
    );
  }
  io.stdout.write(`${formatRows(job.result, parsed.format)}\n`);
  return 0;
}

function reportQueryError(error: unknown, io: CliIo): number {
  if (error instanceof QueryJobFailedError) {
    io.stderr.write(`Query failed (${error.job.id}): ${error.job.error ?? "unknown error"}\n`);
    return 1;
  }
  if (error instanceof AdminApiError) {
    io.stderr.write(`Query failed: ${error.message}\n`);
    return 1;
  }
  io.stderr.write(`Query failed: ${errorMessage(error)}\n`);
  return 1;
}

async function resolveAdminClient(
  options: MainOptions,
  env: NodeJS.ProcessEnv,
  parsed: Partial<Pick<QueryArgs, "apiUrl" | "accessClientId" | "accessClientSecret">> = {}
): Promise<AdminClient | undefined> {
  if (options.adminClient) return options.adminClient;
  const baseUrl = parsed.apiUrl ?? env.PICKET_API_URL;
  if (!baseUrl) return undefined;
  const normalized = normalizeApiUrl(baseUrl);
  const resolved = await resolveAuth({
    apiUrl: normalized,
    env,
    flags: {
      accessClientId: parsed.accessClientId,
      accessClientSecret: parsed.accessClientSecret
    },
    cloudflared: options.cloudflared,
    credentialsIo: options.credentialsIo
  });
  return new AdminClient(toAdminClientOptions(normalized, resolved));
}

async function requireAdminClient(
  io: CliIo,
  options: MainOptions,
  parsed: Partial<Pick<QueryArgs, "apiUrl" | "accessClientId" | "accessClientSecret">> = {}
): Promise<AdminClient | undefined> {
  const adminClient = await resolveAdminClient(options, options.env ?? process.env, parsed);
  if (!adminClient) {
    io.stderr.write(`Admin API URL required. Pass --api-url <url> or set PICKET_API_URL.\n`);
    return undefined;
  }
  return adminClient;
}

async function alertsCommand(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const [subcommand, ...rest] = args;
  switch (subcommand) {
    case "list":
      return await alertsList(rest, io, options);
    case "stats":
      return await alertsStats(rest, io, options);
    case "show":
      return await alertsShow(rest, io, options);
    case "ack":
      return await alertsMutate(rest, io, options, "acknowledged");
    case "resolve":
      return await alertsMutate(rest, io, options, "resolved");
    case "reopen":
      return await alertsMutate(rest, io, options, "reopened");
    case "assign":
      return await alertsAssign(rest, io, options);
    case "note":
      return await alertsNote(rest, io, options);
    case undefined:
    case "help":
    case "--help":
    case "-h":
      io.stdout.write(`${alertsUsage()}\n`);
      return subcommand ? 0 : 1;
    default:
      io.stderr.write(`Unknown alerts subcommand: ${subcommand}\n\n${alertsUsage()}\n`);
      return 1;
  }
}

async function alertsList(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseAlertsListArgs(args);
  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  const alerts = await adminClient.listAlerts({ status: parsed.status, severity: parsed.severity, limit: parsed.limit });

  if (parsed.format === "json") {
    io.stdout.write(`${JSON.stringify(alerts, null, 2)}\n`);
  } else {
    io.stdout.write(`${formatAlertsTable(alerts)}\n`);
  }
  return 0;
}

async function alertsStats(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  let format: "table" | "json" = "table";
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--format") {
      const v = requiredValue("--format", args[index + 1]);
      if (v !== "table" && v !== "json") throw new Error("--format must be one of: table, json");
      format = v;
      index += 1;
    } else {
      throw new Error(`Unknown alerts stats option: ${arg}`);
    }
  }

  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  const stats = await adminClient.getAlertStats();

  if (format === "json") {
    io.stdout.write(`${JSON.stringify(stats, null, 2)}\n`);
  } else {
    io.stdout.write(`${formatAlertStats(stats)}\n`);
  }
  return 0;
}

async function alertsShow(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseAlertsShowArgs(args);
  if (!parsed.alertId) {
    io.stderr.write(`Usage: picket alerts show <alert-id> [--format table|json]\n`);
    return 1;
  }

  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  try {
    const detail = await adminClient.getAlert(parsed.alertId);
    if (parsed.format === "json") {
      io.stdout.write(`${JSON.stringify(detail, null, 2)}\n`);
    } else {
      io.stdout.write(`${formatAlertDetail(detail)}\n`);
    }
    return 0;
  } catch (error) {
    if (isNotFound(error)) {
      io.stderr.write(`Alert not found: ${parsed.alertId}\n`);
      return 1;
    }
    throw error;
  }
}

async function alertsMutate(
  args: string[],
  io: CliIo,
  options: MainOptions,
  action: "acknowledged" | "resolved" | "reopened"
): Promise<number> {
  const verb = action === "acknowledged" ? "ack" : action === "resolved" ? "resolve" : "reopen";
  const parsed = parseAlertsActorArgs(args);
  if (!parsed.alertId) {
    io.stderr.write(`Usage: picket alerts ${verb} <alert-id> [--by <name>]\n`);
    return 1;
  }

  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;

  try {
    const result =
      action === "acknowledged"
        ? await adminClient.acknowledgeAlert(parsed.alertId, parsed.by)
        : action === "resolved"
          ? await adminClient.resolveAlert(parsed.alertId, parsed.by)
          : await adminClient.reopenAlert(parsed.alertId, parsed.by);
    const label =
      action === "acknowledged" ? "Acknowledged" : action === "resolved" ? "Resolved" : "Reopened";
    const by =
      "acknowledged_by" in result
        ? result.acknowledged_by
        : "resolved_by" in result
          ? result.resolved_by
          : result.reopened_by;
    io.stdout.write(`${label} alert ${result.alert.id} (status=${result.alert.status}, by=${by}).\n`);
    return 0;
  } catch (error) {
    if (isNotFound(error)) {
      io.stderr.write(`Alert not found: ${parsed.alertId}\n`);
      return 1;
    }
    if (error instanceof AdminApiError && error.status === 409) {
      io.stderr.write(`${error.message}: ${parsed.alertId}\n`);
      return 1;
    }
    throw error;
  }
}

interface AlertsAssignArgs {
  alertId?: string;
  assignee?: string;
  unassign: boolean;
  by?: string;
}

function parseAlertsAssignArgs(args: string[]): AlertsAssignArgs {
  const parsed: AlertsAssignArgs = { unassign: false };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) continue;
    const value = args[index + 1];

    if (arg === "--to") {
      parsed.assignee = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--by") {
      parsed.by = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--unassign") {
      parsed.unassign = true;
    } else if (arg.startsWith("--")) {
      throw new Error(`Unknown option: ${arg}`);
    } else if (parsed.alertId === undefined) {
      parsed.alertId = arg;
    } else if (parsed.assignee === undefined) {
      parsed.assignee = arg;
    } else {
      throw new Error(`Unexpected argument: ${arg}`);
    }
  }

  return parsed;
}

async function alertsAssign(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseAlertsAssignArgs(args);
  if (!parsed.alertId || (parsed.assignee === undefined && !parsed.unassign)) {
    io.stderr.write(`Usage: picket alerts assign <alert-id> <assignee> [--by <name>]\n       picket alerts assign <alert-id> --unassign [--by <name>]\n`);
    return 1;
  }

  const assignee = parsed.unassign ? null : (parsed.assignee ?? null);
  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;

  try {
    const result = await adminClient.assignAlert(parsed.alertId, assignee, parsed.by);
    const label = result.alert.assignee ? `assigned to ${result.alert.assignee}` : "unassigned";
    io.stdout.write(`Alert ${result.alert.id} ${label} (by=${result.updated_by}).\n`);
    return 0;
  } catch (error) {
    if (isNotFound(error)) {
      io.stderr.write(`Alert not found: ${parsed.alertId}\n`);
      return 1;
    }
    throw error;
  }
}

interface AlertsNoteArgs {
  alertId?: string;
  body?: string;
  by?: string;
}

function parseAlertsNoteArgs(args: string[]): AlertsNoteArgs {
  const parsed: AlertsNoteArgs = {};

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) continue;
    const value = args[index + 1];

    if (arg === "--body") {
      parsed.body = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--by") {
      parsed.by = requiredValue(arg, value);
      index += 1;
    } else if (arg.startsWith("--")) {
      throw new Error(`Unknown option: ${arg}`);
    } else if (parsed.alertId === undefined) {
      parsed.alertId = arg;
    } else {
      throw new Error(`Unexpected argument: ${arg}`);
    }
  }

  return parsed;
}

async function alertsNote(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseAlertsNoteArgs(args);
  if (!parsed.alertId || parsed.body === undefined) {
    io.stderr.write(`Usage: picket alerts note <alert-id> --body <text> [--by <name>]\n`);
    return 1;
  }

  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;

  try {
    const result = await adminClient.addAlertNote(parsed.alertId, parsed.body, parsed.by);
    const noteId = result.note && typeof result.note === "object" && "id" in result.note ? String(result.note.id) : "unknown";
    io.stdout.write(`Added note ${noteId} to alert ${parsed.alertId} (by=${result.author}).\n`);
    return 0;
  } catch (error) {
    if (isNotFound(error)) {
      io.stderr.write(`Alert not found: ${parsed.alertId}\n`);
      return 1;
    }
    if (error instanceof AdminApiError && error.status === 400) {
      io.stderr.write(`${error.message}\n`);
      return 1;
    }
    throw error;
  }
}

interface StatusArgs {
  source?: string;
  tenant?: string;
  format: "table" | "json";
}

function parseStatusArgs(args: string[]): StatusArgs {
  const parsed: StatusArgs = { format: "table" };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) continue;
    const value = args[index + 1];

    if (arg === "--source") {
      parsed.source = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--tenant") {
      parsed.tenant = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--format") {
      const formatValue = requiredValue(arg, value);
      if (formatValue !== "table" && formatValue !== "json") {
        throw new Error(`--format must be one of: table, json`);
      }
      parsed.format = formatValue;
      index += 1;
    } else {
      throw new Error(`Unknown status option: ${arg}`);
    }
  }

  return parsed;
}

async function detectionsCommand(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const [subcommand, ...rest] = args;
  switch (subcommand) {
    case "list":
      return await detectionsList(rest, io, options);
    case "scheduled":
      return await detectionsScheduled(rest, io, options);
    case "show":
      return await detectionsShow(rest, io, options);
    case "enable":
      return await detectionsToggle(rest, io, options, true);
    case "disable":
      return await detectionsToggle(rest, io, options, false);
    case undefined:
    case "help":
    case "--help":
    case "-h":
      io.stdout.write(`${detectionsUsage()}\n`);
      return subcommand ? 0 : 1;
    default:
      io.stderr.write(`Unknown detections subcommand: ${subcommand}\n\n${detectionsUsage()}\n`);
      return 1;
  }
}

interface DetectionsListArgs {
  enabled?: boolean;
  source?: string;
  format: "table" | "json";
}

function parseDetectionsListArgs(args: string[]): DetectionsListArgs {
  const parsed: DetectionsListArgs = { format: "table" };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) continue;
    const value = args[index + 1];
    if (arg === "--enabled") {
      const v = requiredValue(arg, value);
      if (v !== "true" && v !== "false") throw new Error("--enabled must be true or false");
      parsed.enabled = v === "true";
      index += 1;
    } else if (arg === "--source") {
      parsed.source = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--format") {
      const v = requiredValue(arg, value);
      if (v !== "table" && v !== "json") throw new Error("--format must be one of: table, json");
      parsed.format = v;
      index += 1;
    } else {
      throw new Error(`Unknown detections list option: ${arg}`);
    }
  }
  return parsed;
}

async function detectionsList(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseDetectionsListArgs(args);
  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  const rules = await adminClient.listDetections({ enabled: parsed.enabled, source: parsed.source });

  if (parsed.format === "json") {
    io.stdout.write(`${JSON.stringify(rules, null, 2)}\n`);
  } else {
    io.stdout.write(`${formatDetectionsTable(rules)}\n`);
  }
  return 0;
}

async function detectionsScheduled(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  let format: "table" | "json" = "table";
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--format") {
      const v = requiredValue("--format", args[index + 1]);
      if (v !== "table" && v !== "json") throw new Error("--format must be one of: table, json");
      format = v;
      index += 1;
    } else {
      throw new Error(`Unknown detections scheduled option: ${args[index]}`);
    }
  }

  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  const scheduled = await adminClient.listScheduledDetections();

  if (format === "json") {
    io.stdout.write(`${JSON.stringify(scheduled, null, 2)}\n`);
  } else {
    io.stdout.write(`${formatScheduledDetectionsTable(scheduled)}\n`);
  }
  return 0;
}

async function detectionsShow(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const [id, ...rest] = args;
  if (!id) {
    io.stderr.write(`Usage: picket detections show <rule-id> [--format table|json]\n`);
    return 1;
  }
  let format: "table" | "json" = "table";
  for (let index = 0; index < rest.length; index += 1) {
    if (rest[index] === "--format") {
      const v = requiredValue("--format", rest[index + 1]);
      if (v !== "table" && v !== "json") throw new Error("--format must be one of: table, json");
      format = v;
      index += 1;
    } else {
      throw new Error(`Unknown detections show option: ${rest[index]}`);
    }
  }

  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  try {
    const rule = await adminClient.getDetection(id);
    if (format === "json") {
      io.stdout.write(`${JSON.stringify(rule, null, 2)}\n`);
    } else {
      io.stdout.write(`${formatDetectionDetail(rule)}\n`);
    }
    return 0;
  } catch (error) {
    if (isNotFound(error)) {
      io.stderr.write(`Detection rule not found: ${id}\n`);
      return 1;
    }
    throw error;
  }
}

async function detectionsToggle(
  args: string[],
  io: CliIo,
  options: MainOptions,
  enabled: boolean
): Promise<number> {
  const [id] = args;
  const verb = enabled ? "enable" : "disable";
  if (!id) {
    io.stderr.write(`Usage: picket detections ${verb} <rule-id>\n`);
    return 1;
  }
  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  try {
    const rule = await adminClient.setDetectionEnabled(id, enabled);
    io.stdout.write(`${enabled ? "Enabled" : "Disabled"} detection rule ${rule.id} (enabled=${rule.enabled}).\n`);
    return 0;
  } catch (error) {
    if (isNotFound(error)) {
      io.stderr.write(`Detection rule not found: ${id}\n`);
      return 1;
    }
    throw error;
  }
}

function formatDetectionsTable(rules: readonly DetectionRuleRow[]): string {
  if (rules.length === 0) return "No detection rules registered.";

  const headers = ["id", "severity", "enabled", "source", "execution", "matches", "last_triggered"] as const;
  const rows: string[][] = rules.map((rule) => [
    rule.id,
    rule.severity,
    rule.enabled ? "yes" : "no",
    rule.source,
    rule.execution,
    String(rule.match_count),
    rule.last_triggered_at ?? "-"
  ]);

  const widths = headers.map((header, columnIndex) => {
    let width = header.length;
    for (const row of rows) {
      const cell = row[columnIndex] ?? "";
      if (cell.length > width) width = cell.length;
    }
    return width;
  });
  const pad = (cells: readonly string[]): string =>
    cells.map((cell, columnIndex) => cell.padEnd(widths[columnIndex] ?? 0)).join("  ");
  const separator = widths.map((width) => "-".repeat(width));
  return [pad(headers), pad(separator), ...rows.map(pad)].join("\n");
}

function formatDetectionDetail(rule: DetectionRuleRow): string {
  const lines: string[] = [];
  lines.push(`Detection rule ${rule.id}`);
  lines.push(`  title:          ${rule.title}`);
  lines.push(`  severity:       ${rule.severity}`);
  lines.push(`  enabled:        ${rule.enabled}`);
  lines.push(`  source:         ${rule.source}`);
  if (rule.class_name) lines.push(`  class_name:     ${rule.class_name}`);
  lines.push(`  execution:      ${rule.execution}`);
  lines.push(`  tags:           ${rule.tags.length > 0 ? rule.tags.join(", ") : "-"}`);
  lines.push(`  match_count:    ${rule.match_count}`);
  lines.push(`  last_triggered: ${rule.last_triggered_at ?? "-"}`);
  if (rule.description) {
    lines.push("");
    lines.push(`  ${rule.description}`);
  }
  lines.push("");
  lines.push("Definition:");
  lines.push(JSON.stringify(rule.definition, null, 2));
  return lines.join("\n");
}

function detectionsUsage(): string {
  return `Usage:
  picket detections list [--enabled true|false] [--source <id>] [--format table|json]
  picket detections scheduled [--format table|json]
  picket detections show <rule-id> [--format table|json]
  picket detections enable <rule-id>
  picket detections disable <rule-id>`;
}

async function enrichmentCommand(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const [subcommand, ...rest] = args;
  switch (subcommand) {
    case "list":
      return await enrichmentList(rest, io, options);
    case "add":
      return await enrichmentAdd(rest, io, options);
    case "import-csv":
      return await enrichmentImportCsv(rest, io, options);
    case "load-assets":
      return await enrichmentLoadAssets(rest, io, options);
    case "load-users":
      return await enrichmentLoadUsers(rest, io, options);
    case "remove":
    case "rm":
      return await enrichmentRemove(rest, io, options);
    case undefined:
    case "help":
    case "--help":
    case "-h":
      io.stdout.write(`${enrichmentUsage()}\n`);
      return subcommand ? 0 : 1;
    default:
      io.stderr.write(`Unknown enrichment subcommand: ${subcommand}\n\n${enrichmentUsage()}\n`);
      return 1;
  }
}

async function enrichmentImportCsv(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const [file, ...rest] = args;
  let feed: string | undefined;
  let threatType: string | undefined;
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--feed") {
      feed = requiredValue(arg, rest[index + 1]);
      index += 1;
    } else if (arg === "--threat-type") {
      threatType = requiredValue(arg, rest[index + 1]);
      index += 1;
    } else {
      throw new Error(`Unknown enrichment import-csv option: ${arg}`);
    }
  }
  if (!file) {
    io.stderr.write(`Usage: picket enrichment import-csv <file> [--feed <name>] [--threat-type <type>]\n`);
    return 1;
  }
  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  const written = await adminClient.importIocCsv(await readFile(file, "utf8"), { feed, threatType });
  io.stdout.write(`Imported ${written} IOC${written === 1 ? "" : "s"}.\n`);
  return 0;
}

async function enrichmentLoadAssets(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const [file] = args;
  if (!file) {
    io.stderr.write(`Usage: picket enrichment load-assets <json-file>\n`);
    return 1;
  }
  const assets = parseAssetFile(await readFile(file, "utf8"));
  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  const written = await adminClient.loadAssets(assets);
  io.stdout.write(`Loaded ${written} asset${written === 1 ? "" : "s"}.\n`);
  return 0;
}

async function enrichmentLoadUsers(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const [file] = args;
  if (!file) {
    io.stderr.write(`Usage: picket enrichment load-users <json-file>\n`);
    return 1;
  }
  const users = parseUserFile(await readFile(file, "utf8"));
  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  const written = await adminClient.loadUsers(users);
  io.stdout.write(`Loaded ${written} user${written === 1 ? "" : "s"}.\n`);
  return 0;
}

function parseAssetFile(raw: string): AssetRecord[] {
  const parsed = JSON.parse(raw) as unknown;
  const assets = Array.isArray(parsed) ? parsed : isRecord(parsed) && Array.isArray(parsed.assets) ? parsed.assets : undefined;
  if (!assets) throw new Error("Asset file must be a JSON array or an object with an assets array.");
  return assets as AssetRecord[];
}

function parseUserFile(raw: string): UserRecord[] {
  const parsed = JSON.parse(raw) as unknown;
  const users = Array.isArray(parsed) ? parsed : isRecord(parsed) && Array.isArray(parsed.users) ? parsed.users : undefined;
  if (!users) throw new Error("User file must be a JSON array or an object with a users array.");
  return users as UserRecord[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function enrichmentList(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  let type: IndicatorType | undefined;
  let limit: number | undefined;
  let format: "table" | "json" = "table";
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--type") {
      const v = requiredValue(arg, args[index + 1]);
      if (!isIndicatorType(v)) throw new Error("--type must be one of: ipv4, ipv6, domain, url, sha256");
      type = v;
      index += 1;
    } else if (arg === "--limit") {
      limit = positiveInteger("--limit", requiredValue(arg, args[index + 1]));
      index += 1;
    } else if (arg === "--format") {
      const v = requiredValue(arg, args[index + 1]);
      if (v !== "table" && v !== "json") throw new Error("--format must be one of: table, json");
      format = v;
      index += 1;
    } else {
      throw new Error(`Unknown enrichment list option: ${arg}`);
    }
  }

  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  const iocs = await adminClient.listIocs({ type, limit });

  if (format === "json") {
    io.stdout.write(`${JSON.stringify(iocs, null, 2)}\n`);
  } else {
    io.stdout.write(`${formatIocTable(iocs)}\n`);
  }
  return 0;
}

async function enrichmentAdd(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const [indicator, ...rest] = args;
  let type: IndicatorType | undefined;
  let feedName: string | undefined;
  let threatType: string | undefined;
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--type") {
      const v = requiredValue(arg, rest[index + 1]);
      if (!isIndicatorType(v)) throw new Error("--type must be one of: ipv4, ipv6, domain, url, sha256");
      type = v;
      index += 1;
    } else if (arg === "--feed") {
      feedName = requiredValue(arg, rest[index + 1]);
      index += 1;
    } else if (arg === "--threat-type") {
      threatType = requiredValue(arg, rest[index + 1]);
      index += 1;
    } else {
      throw new Error(`Unknown enrichment add option: ${arg}`);
    }
  }
  if (!indicator || !type) {
    io.stderr.write(`Usage: picket enrichment add <indicator> --type <type> [--feed <name>] [--threat-type <type>]\n`);
    return 1;
  }

  const ioc: IocRecord = {
    indicator,
    indicator_type: type,
    ...(feedName ? { feed_name: feedName } : {}),
    ...(threatType ? { threat_type: threatType } : {})
  };
  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  const written = await adminClient.addIocs([ioc]);
  io.stdout.write(`Added ${written} IOC${written === 1 ? "" : "s"}.\n`);
  return 0;
}

async function enrichmentRemove(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const [type, indicator] = args;
  if (!type || !indicator) {
    io.stderr.write(`Usage: picket enrichment remove <type> <indicator>\n`);
    return 1;
  }
  if (!isIndicatorType(type)) throw new Error("type must be one of: ipv4, ipv6, domain, url, sha256");

  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  try {
    await adminClient.deleteIoc(type, indicator);
    io.stdout.write(`Removed IOC ${type}/${indicator}.\n`);
    return 0;
  } catch (error) {
    if (isNotFound(error)) {
      io.stderr.write(`IOC not found: ${type}/${indicator}\n`);
      return 1;
    }
    throw error;
  }
}

function enrichmentUsage(): string {
  return `Usage:
  picket enrichment list [--type <type>] [--limit <n>] [--format table|json]
  picket enrichment add <indicator> --type <type> [--feed <name>] [--threat-type <type>]
  picket enrichment import-csv <file> [--feed <name>] [--threat-type <type>]
  picket enrichment load-assets <json-file>
  picket enrichment load-users <json-file>
  picket enrichment remove <type> <indicator>

  <type> is one of: ipv4, ipv6, domain, url, sha256`;
}

async function statusCommand(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseStatusArgs(args);
  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  const now = options.now ? options.now() : new Date();

  let filtered: SourceHealthRow[];
  try {
    filtered = await adminClient.listSources({ tenant: parsed.tenant, source: parsed.source });
  } catch (error) {
    if (parsed.source && isNotFound(error)) {
      io.stderr.write(`Source not found: ${parsed.source}\n`);
      return 1;
    }
    throw error;
  }

  // Detection health is global; only fetch it for the unfiltered overview.
  let detectionHealth: DetectionHealthRow | null = null;
  if (!parsed.source) {
    detectionHealth = await adminClient.getDetectionHealth();
  }

  if (parsed.format === "json") {
    io.stdout.write(
      `${JSON.stringify(
        parsed.source ? { sources: filtered } : { sources: filtered, detection_health: detectionHealth },
        null,
        2
      )}\n`
    );
  } else {
    io.stdout.write(`${formatSourceHealthTable(filtered, { now })}\n`);
    if (!parsed.source) {
      io.stdout.write(`\n${formatDetectionHealth(detectionHealth, { now })}\n`);
    }
  }
  return 0;
}

interface DashboardArgs {
  tenant?: string;
  format: "table" | "json";
}

function parseDashboardArgs(args: string[]): DashboardArgs {
  const parsed: DashboardArgs = { format: "table" };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) continue;
    const value = args[index + 1];
    if (arg === "--tenant") {
      parsed.tenant = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--format") {
      const v = requiredValue(arg, value);
      if (v !== "table" && v !== "json") throw new Error("--format must be one of: table, json");
      parsed.format = v;
      index += 1;
    } else {
      throw new Error(`Unknown dashboard option: ${arg}`);
    }
  }
  return parsed;
}

async function dashboardCommand(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseDashboardArgs(args);
  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  const overview = await adminClient.getDashboardOverview({ tenant: parsed.tenant });

  if (parsed.format === "json") {
    io.stdout.write(`${JSON.stringify(overview, null, 2)}\n`);
  } else {
    io.stdout.write(`${formatDashboardOverview(overview)}\n`);
  }
  return 0;
}

async function sourcesCommand(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const [subcommand, ...rest] = args;
  switch (subcommand) {
    case "status":
      return await sourcesStatus(rest, io, options);
    case "schema":
      return await sourcesSchema(rest, io, options);
    case "sample":
      return await sourcesSample(rest, io, options);
    case undefined:
    case "help":
    case "--help":
    case "-h":
      io.stdout.write(`${sourcesUsage()}\n`);
      return subcommand ? 0 : 1;
    default:
      io.stderr.write(`Unknown sources subcommand: ${subcommand}\n\n${sourcesUsage()}\n`);
      return 1;
  }
}

interface SourcesItemArgs {
  id?: string;
  tenant?: string;
  format: "table" | "json";
}

function parseSourcesItemArgs(args: string[], allowTenant: boolean): SourcesItemArgs {
  const parsed: SourcesItemArgs = { format: "table" };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) continue;
    const value = args[index + 1];
    if (allowTenant && arg === "--tenant") {
      parsed.tenant = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--format") {
      const v = requiredValue(arg, value);
      if (v !== "table" && v !== "json") throw new Error("--format must be one of: table, json");
      parsed.format = v;
      index += 1;
    } else if (arg.startsWith("--")) {
      throw new Error(`Unknown sources option: ${arg}`);
    } else if (parsed.id === undefined) {
      parsed.id = arg;
    } else {
      throw new Error(`Unexpected argument: ${arg}`);
    }
  }
  return parsed;
}

async function sourcesStatus(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseSourcesItemArgs(args, true);
  if (!parsed.id) {
    io.stderr.write(`Usage: picket sources status <source-id> [--tenant <id>] [--format table|json]\n`);
    return 1;
  }
  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  try {
    const status = await adminClient.getSourceStatus(parsed.id, parsed.tenant);
    if (parsed.format === "json") {
      io.stdout.write(`${JSON.stringify(status, null, 2)}\n`);
    } else {
      io.stdout.write(`${formatSourceStatus(status)}\n`);
    }
    return 0;
  } catch (error) {
    if (isNotFound(error)) {
      io.stderr.write(`Source not found: ${parsed.id}\n`);
      return 1;
    }
    throw error;
  }
}

async function sourcesSchema(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseSourcesItemArgs(args, false);
  if (!parsed.id) {
    io.stderr.write(`Usage: picket sources schema <source-id> [--format table|json]\n`);
    return 1;
  }
  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;
  try {
    const schema = await adminClient.getSourceSchema(parsed.id);
    if (parsed.format === "json") {
      io.stdout.write(`${JSON.stringify(schema, null, 2)}\n`);
    } else {
      io.stdout.write(`${formatOcsfSchema(schema)}\n`);
    }
    return 0;
  } catch (error) {
    if (isNotFound(error)) {
      io.stderr.write(`Unknown source: ${parsed.id}\n`);
      return 1;
    }
    throw error;
  }
}

interface SourcesSampleArgs {
  id?: string;
  format: QueryOutputFormat;
  async: boolean;
}

function parseSourcesSampleArgs(args: string[]): SourcesSampleArgs {
  const parsed: SourcesSampleArgs = { format: "table", async: false };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) continue;
    const value = args[index + 1];
    if (arg === "--format") {
      const v = requiredValue(arg, value);
      if (v !== "table" && v !== "json" && v !== "csv") {
        throw new Error("--format must be one of: table, json, csv");
      }
      parsed.format = v;
      index += 1;
    } else if (arg === "--async") {
      parsed.async = true;
    } else if (arg.startsWith("--")) {
      throw new Error(`Unknown sources sample option: ${arg}`);
    } else if (parsed.id === undefined) {
      parsed.id = arg;
    } else {
      throw new Error(`Unexpected argument: ${arg}`);
    }
  }
  return parsed;
}

async function sourcesSample(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const parsed = parseSourcesSampleArgs(args);
  if (!parsed.id) {
    io.stderr.write(`Usage: picket sources sample <source-id> [--format table|json|csv] [--async]\n`);
    return 1;
  }
  const adminClient = await requireAdminClient(io, options);
  if (!adminClient) return 1;

  const renderArgs: QueryArgs = { format: parsed.format, printOnly: false, async: parsed.async, verbose: false };
  try {
    const job = await adminClient.sampleSource(parsed.id);
    if (parsed.async) {
      if (job.status === "succeeded") return renderJob(job, renderArgs, io);
      io.stdout.write(
        `${JSON.stringify({ id: job.id, status: job.status, location: job.location ?? `/api/v1/query/${job.id}` })}\n`
      );
      return 0;
    }
    if (job.status === "succeeded") return renderJob(job, renderArgs, io);
    if (job.status === "failed") throw new QueryJobFailedError(job);
    const final = await adminClient.waitForJob(job.id);
    return renderJob(final, renderArgs, io);
  } catch (error) {
    if (isNotFound(error)) {
      io.stderr.write(`Unknown source: ${parsed.id}\n`);
      return 1;
    }
    return reportQueryError(error, io);
  }
}

function sourcesUsage(): string {
  return `Usage:
  picket sources status <source-id> [--tenant <id>] [--format table|json]
  picket sources schema <source-id> [--format table|json]
  picket sources sample <source-id> [--format table|json|csv] [--async]`;
}

function parseAlertsListArgs(args: string[]): AlertsListArgs {
  const parsed: AlertsListArgs = { limit: 20, format: "table" };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const value = args[index + 1];

    if (arg === "--status") {
      parsed.status = oneOf(arg, requiredValue(arg, value), ALERT_STATUSES);
      index += 1;
    } else if (arg === "--severity") {
      parsed.severity = oneOf(arg, requiredValue(arg, value), ALERT_SEVERITIES);
      index += 1;
    } else if (arg === "--limit") {
      parsed.limit = positiveInteger(arg, requiredValue(arg, value));
      index += 1;
    } else if (arg === "--format") {
      const formatValue = requiredValue(arg, value);
      if (formatValue !== "table" && formatValue !== "json") {
        throw new Error(`--format must be one of: table, json`);
      }
      parsed.format = formatValue;
      index += 1;
    } else {
      throw new Error(`Unknown alerts list option: ${arg}`);
    }
  }

  return parsed;
}

function isNotFound(error: unknown): boolean {
  return error instanceof AlertNotFoundError || (error instanceof AdminApiError && error.status === 404);
}

interface AlertsActorArgs {
  alertId?: string;
  by?: string;
}

function parseAlertsActorArgs(args: string[]): AlertsActorArgs {
  const parsed: AlertsActorArgs = {};

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) continue;
    const value = args[index + 1];

    if (arg === "--by") {
      parsed.by = requiredValue(arg, value);
      index += 1;
    } else if (arg.startsWith("--")) {
      throw new Error(`Unknown option: ${arg}`);
    } else if (parsed.alertId === undefined) {
      parsed.alertId = arg;
    } else {
      throw new Error(`Unexpected argument: ${arg}`);
    }
  }

  return parsed;
}

interface AlertsShowArgs {
  alertId?: string;
  format: "table" | "json";
}

function parseAlertsShowArgs(args: string[]): AlertsShowArgs {
  const parsed: AlertsShowArgs = { format: "table" };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) continue;
    const value = args[index + 1];

    if (arg === "--format") {
      const formatValue = requiredValue(arg, value);
      if (formatValue !== "table" && formatValue !== "json") {
        throw new Error(`--format must be one of: table, json`);
      }
      parsed.format = formatValue;
      index += 1;
    } else if (arg.startsWith("--")) {
      throw new Error(`Unknown alerts show option: ${arg}`);
    } else if (parsed.alertId === undefined) {
      parsed.alertId = arg;
    } else {
      throw new Error(`Unexpected argument: ${arg}`);
    }
  }

  return parsed;
}

function parseQueryArgs(args: string[]): QueryArgs {
  const parsed: QueryArgs = { format: "table", printOnly: false, async: false, verbose: false };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const value = args[index + 1];

    if (arg === "--preset") {
      parsed.preset = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--sql") {
      if (value === undefined) throw new Error(`Missing value for ${arg}.`);
      parsed.sql = value;
      index += 1;
    } else if (arg === "--hours") {
      parsed.hours = positiveInteger(arg, requiredValue(arg, value));
      index += 1;
    } else if (arg === "--limit") {
      parsed.limit = positiveInteger(arg, requiredValue(arg, value));
      index += 1;
    } else if (arg === "--format") {
      const v = requiredValue(arg, value);
      if (v !== "table" && v !== "json" && v !== "csv") {
        throw new Error(`--format must be one of: table, json, csv`);
      }
      parsed.format = v;
      index += 1;
    } else if (arg === "--warehouse") {
      parsed.warehouse = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--table-suffix") {
      parsed.tableSuffix = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--print-only") {
      parsed.printOnly = true;
    } else if (arg === "--async") {
      parsed.async = true;
    } else if (arg === "--job-id") {
      parsed.jobId = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--api-url") {
      parsed.apiUrl = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--access-client-id") {
      parsed.accessClientId = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--access-client-secret") {
      parsed.accessClientSecret = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--idempotency-key") {
      parsed.idempotencyKey = requiredValue(arg, value);
      index += 1;
    } else if (arg === "--verbose") {
      parsed.verbose = true;
    } else {
      throw new Error(`Unknown query option: ${arg}`);
    }
  }

  return parsed;
}

function parseInitArgs(args: string[]): InitArgs {
  const parsed: InitArgs = { directory: "my-picket", force: false };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) continue;

    if (arg === "--force") {
      parsed.force = true;
    } else if (arg === "--dir") {
      parsed.directory = requiredValue(arg, args[index + 1]);
      index += 1;
    } else if (arg.startsWith("--")) {
      throw new Error(`Unknown init option: ${arg}`);
    } else if (parsed.directory === "my-picket") {
      parsed.directory = arg;
    } else {
      throw new Error(`Unexpected argument: ${arg}`);
    }
  }

  return parsed;
}

function parseDeployArgs(args: string[]): DeployArgs {
  const parsed: DeployArgs = { skipTerraform: false, skipBindings: false, skipWorkers: false };

  for (const arg of args) {
    if (arg === "--skip-terraform") {
      parsed.skipTerraform = true;
    } else if (arg === "--skip-bindings") {
      parsed.skipBindings = true;
    } else if (arg === "--skip-workers") {
      parsed.skipWorkers = true;
    } else if (arg !== undefined) {
      throw new Error(`Unknown deploy option: ${arg}`);
    }
  }

  return parsed;
}

function runCommand(command: string, args: string[], options: { cwd?: string } = {}): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      stdio: "inherit",
      shell: false
    });

    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${command} ${args.join(" ")} failed with exit code ${code}`));
    });
  });
}

function requiredValue(option: string, value: string | undefined): string {
  if (!value || value.startsWith("--")) throw new Error(`Missing value for ${option}.`);
  return value;
}

function positiveInteger(option: string, value: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`${option} must be a positive integer.`);
  return parsed;
}

function oneOf<T extends string>(option: string, value: string, allowed: readonly T[]): T {
  if (!(allowed as readonly string[]).includes(value)) {
    throw new Error(`${option} must be one of: ${allowed.join(", ")}`);
  }
  return value as T;
}

function usage(): string {
  return `Usage:
  picket login [--api-url <url>] [--no-browser]
  picket logout [--api-url <url>]
  picket whoami [--api-url <url>]
  picket init [directory|--dir <directory>] [--force]
  picket deploy [--skip-terraform] [--skip-bindings] [--skip-workers]
  picket test <cloudtrail-json-file>
  picket test-event <cloudtrail-json-file>
  picket query (--preset <name> | --sql "<query>" | --job-id <id>) [--hours <n>] [--limit <n>]
              [--format table|json|csv] [--warehouse <name>] [--table-suffix <s>]
              [--api-url <url>] [--access-client-id <id>] [--access-client-secret <s>]
              [--idempotency-key <k>] [--async] [--verbose] [--print-only]
  picket query explain (--preset <name> | --sql "<query>") [--hours <n>] [--limit <n>] [--format table|json]
  picket query natural "<question>" [--format table|json|csv] [--async]
  picket query save --name <name> (--preset <name> | --sql "<query>") [--description <text>]
  picket query saved [--owner <id>] [--limit <n>] [--format table|json]
  picket query history [--owner <id>] [--limit <n>] [--format table|json]
  picket alerts list [--status <s>] [--severity <s>] [--limit <n>] [--format table|json]
  picket alerts stats [--format table|json]
  picket alerts show <alert-id> [--format table|json]
  picket alerts ack <alert-id> [--by <name>]
  picket alerts resolve <alert-id> [--by <name>]
  picket alerts reopen <alert-id> [--by <name>]
  picket alerts assign <alert-id> <assignee> [--by <name>] | --unassign
  picket alerts note <alert-id> --body <text> [--by <name>]
  picket detections list [--enabled true|false] [--source <id>] [--format table|json]
  picket detections scheduled [--format table|json]
  picket detections show <rule-id> [--format table|json]
  picket detections enable|disable <rule-id>
  picket status [--source <name>] [--tenant <id>] [--format table|json]
  picket dashboard [--tenant <id>] [--format table|json]
  picket sources status <source-id> [--tenant <id>] [--format table|json]
  picket sources schema <source-id> [--format table|json]
  picket sources sample <source-id> [--format table|json|csv] [--async]
  picket enrichment list [--type <type>] [--limit <n>] [--format table|json]
  picket enrichment add <indicator> --type <type> [--feed <name>] [--threat-type <type>]
  picket enrichment remove <type> <indicator>

Auth precedence (per-leg, first match wins):
  Access:  --access-client-* flag > CF_ACCESS_JWT env > CF_ACCESS_CLIENT_ID/SECRET env > cloudflared cached token.
  App:     PICKET_API_TOKEN env > credentials file (from picket login) > PICKET_SESSION_COOKIE env (deprecated).
  Skip Access entirely with PICKET_SKIP_ACCESS=1 (only for deployments without Cloudflare Access).

Notes:
  picket query, alerts, status use the admin API. Set PICKET_API_URL or pass --api-url where supported.
  picket login starts the device-authorization flow and stores a bearer token under \$XDG_CONFIG_HOME/picket/credentials.json.
  picket test is currently a local event dry-run alias; historical backtesting is still pending API support.`;
}

function alertsUsage(): string {
  return `Usage:
  picket alerts list [--status open|acknowledged|resolved] [--severity critical|high|medium|low|informational] [--limit <n>] [--format table|json]
  picket alerts stats [--format table|json]
  picket alerts show <alert-id> [--format table|json]
  picket alerts ack <alert-id> [--by <name>]
  picket alerts resolve <alert-id> [--by <name>]
  picket alerts reopen <alert-id> [--by <name>]
  picket alerts assign <alert-id> <assignee> [--by <name>]
  picket alerts assign <alert-id> --unassign [--by <name>]
  picket alerts note <alert-id> --body <text> [--by <name>]`;
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

interface AuthCommandArgs {
  apiUrl?: string;
  noBrowser?: boolean;
}

function parseAuthArgs(args: string[], allowNoBrowser: boolean): AuthCommandArgs {
  const parsed: AuthCommandArgs = {};
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const value = args[index + 1];
    if (arg === "--api-url") {
      parsed.apiUrl = requiredValue(arg, value);
      index += 1;
    } else if (allowNoBrowser && arg === "--no-browser") {
      parsed.noBrowser = true;
    } else if (arg !== undefined) {
      throw new Error(`Unknown option: ${arg}`);
    }
  }
  return parsed;
}

function resolveApiUrl(parsed: AuthCommandArgs, env: NodeJS.ProcessEnv): string | undefined {
  const raw = parsed.apiUrl ?? env.PICKET_API_URL;
  return raw ? normalizeApiUrl(raw) : undefined;
}

async function loginCommand(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const env = options.env ?? process.env;
  const parsed = parseAuthArgs(args, true);
  const apiUrl = resolveApiUrl(parsed, env);
  if (!apiUrl) {
    io.stderr.write(`Admin API URL required. Pass --api-url <url> or set PICKET_API_URL.\n`);
    return 1;
  }

  try {
    await runLogin({
      apiUrl,
      env,
      io,
      fetch: options.fetch,
      sleep: options.sleep,
      cloudflared: options.cloudflared,
      credentialsIo: options.credentialsIo,
      openBrowser: options.openBrowser,
      noBrowser: parsed.noBrowser,
      now: options.now
    });
    return 0;
  } catch (error) {
    if (error instanceof DeviceAuthError) {
      io.stderr.write(`Login failed: ${error.message}\n`);
      return 1;
    }
    throw error;
  }
}

async function logoutCommand(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const env = options.env ?? process.env;
  const parsed = parseAuthArgs(args, false);
  const apiUrl = resolveApiUrl(parsed, env);
  if (!apiUrl) {
    io.stderr.write(`Admin API URL required. Pass --api-url <url> or set PICKET_API_URL.\n`);
    return 1;
  }

  const credIo = options.credentialsIo ?? createCredentialsIo();
  const store = await credIo.read().catch(() => ({ records: {} }));
  if (!lookupCredential(store, apiUrl)) {
    io.stdout.write(`No stored credentials for ${apiUrl}.\n`);
    return 0;
  }
  await credIo.write(removeCredential(store, apiUrl));
  io.stdout.write(`Removed credentials for ${apiUrl}.\n`);
  return 0;
}

interface SessionResponse {
  user?: { id?: string; email?: string; name?: string };
}

async function whoamiCommand(args: string[], io: CliIo, options: MainOptions): Promise<number> {
  const env = options.env ?? process.env;
  const parsed = parseAuthArgs(args, false);
  const apiUrl = resolveApiUrl(parsed, env);
  if (!apiUrl) {
    io.stderr.write(`Admin API URL required. Pass --api-url <url> or set PICKET_API_URL.\n`);
    return 1;
  }

  const resolved = await resolveAuth({
    apiUrl,
    env,
    cloudflared: options.cloudflared,
    credentialsIo: options.credentialsIo
  });
  if (!resolved.bearerToken && !resolved.sessionCookie) {
    io.stderr.write(`Not logged in. Run \`picket login --api-url ${apiUrl}\`.\n`);
    return 1;
  }

  const fetchImpl = options.fetch ?? fetch;
  const headers: Record<string, string> = { accept: "application/json" };
  if (resolved.accessJwt) headers["cf-access-jwt-assertion"] = resolved.accessJwt;
  if (resolved.accessClientId && resolved.accessClientSecret) {
    headers["cf-access-client-id"] = resolved.accessClientId;
    headers["cf-access-client-secret"] = resolved.accessClientSecret;
  }
  if (resolved.bearerToken) headers.authorization = `Bearer ${resolved.bearerToken}`;
  if (resolved.sessionCookie) headers.cookie = resolved.sessionCookie;

  const res = await fetchImpl(`${apiUrl}/api/v1/auth/get-session`, { headers });
  if (!res.ok) {
    io.stderr.write(`Session check failed (HTTP ${res.status}). Try \`picket login\` again.\n`);
    return 1;
  }
  const body = (await res.json()) as SessionResponse | null;
  if (!body || !body.user) {
    io.stderr.write(`Not logged in. Run \`picket login --api-url ${apiUrl}\`.\n`);
    return 1;
  }
  io.stdout.write(
    `${body.user.email ?? body.user.id ?? "unknown"} (api=${apiUrl}, source=${resolved.source.app ?? "?"})\n`
  );
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = await main();
}
