import { Hono } from "hono";
import {
  apiKeyAuth,
  createPicketAuth,
  requestLogger,
  sourceBodyLimit,
  type PicketAuth
} from "@picket/api";
import { flattenOcsfEvent, type OcsfEvent, type SourceId } from "@picket/core";
import type { AlertStateDb } from "@picket/core/alerts";
import { enrichEvents, type IocKvNamespace } from "@picket/core/enrichment";
import { recordIngestBatch, recordIngestError } from "@picket/core/source-health";
import { dispatch, HttpError } from "./dispatch";

export interface IngestEnv {
  DETECTION_WORKER: Fetcher;
  AUTH_DB: D1Database;
  BETTER_AUTH_SECRET: string;
  AWS_CLOUDTRAIL_PIPELINE?: PicketPipeline;
  AWS_VPC_FLOW_PIPELINE?: PicketPipeline;
  AWS_GUARDDUTY_PIPELINE?: PicketPipeline;
  GCP_CLOUD_AUDIT_PIPELINE?: PicketPipeline;
  AZURE_ACTIVITY_PIPELINE?: PicketPipeline;
  AZURE_AD_SIGNIN_PIPELINE?: PicketPipeline;
  GITHUB_AUDIT_PIPELINE?: PicketPipeline;
  M365_MANAGEMENT_PIPELINE?: PicketPipeline;
  KUBERNETES_AUDIT_PIPELINE?: PicketPipeline;
  CLOUDFLARE_AUDIT_PIPELINE?: PicketPipeline;
  ALERT_STATE_DB?: D1Database;
  // Threat-intel IOCs synced for ingest-time enrichment (M4). Optional: when
  // unbound, events flow through unstamped.
  ENRICHMENT_KV?: IocKvNamespace;
}

export interface PicketPipeline {
  send(records: Record<string, unknown>[]): Promise<void>;
}

interface DetectionResult {
  accepted: boolean;
  alert_count: number;
}

export function createApp(opts: { auth: PicketAuth }) {
  const app = new Hono<{ Bindings: IngestEnv }>();

  app.use("*", requestLogger("picket-ingest"));

  app.get("/health", (c) => c.json({ ok: true, worker: "picket-ingest" }));

  app.use("/events", apiKeyAuth(opts.auth));
  app.use("/events", sourceBodyLimit());

  app.post("/events", async (c) => {
    const apiKey = c.get("apiKey");
    const { source } = apiKey;
    const tenantId = apiKey.tenant_id;

    let result;
    try {
      result = await dispatch(source, c.req.raw);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await safelyRecordIngestError(c.env.ALERT_STATE_DB, source, tenantId, message);
      if (error instanceof HttpError) return c.json({ error: error.message }, error.status as 400);
      return c.json({ error: "Invalid request", detail: errorMessage(error) }, 400);
    }

    // Stamp threat_match before events reach detection or the pipeline, so both
    // see enrichment. Best-effort: a KV outage must not fail ingest.
    await safelyEnrichEvents(c.env.ENRICHMENT_KV, source, result.events);

    let detectionResults: DetectionResult[] = [];
    let detectionError: string | undefined;
    try {
      detectionResults = await postToDetection(result.events, c.env.DETECTION_WORKER);
    } catch (error) {
      detectionError = errorMessage(error);
      console.error(JSON.stringify({ message: "detection side effect failed", source, error: detectionError }));
    }

    await writeEventsToPipeline(source, result.events, c.env);

    await safelyRecordIngestBatch(c.env.ALERT_STATE_DB, source, tenantId, result.events);
    if (result.parse_failures > 0) {
      await safelyRecordIngestError(
        c.env.ALERT_STATE_DB,
        source,
        tenantId,
        `${result.parse_failures} record(s) failed to normalize`
      );
    }

    return c.json(
      {
        accepted: true,
        event_count: result.events.length,
        parse_failures: result.parse_failures,
        alert_count: detectionResults.reduce((sum, r) => sum + r.alert_count, 0),
        ...(detectionError ? { detection_error: detectionError } : {})
      },
      202
    );
  });

  app.notFound((c) => c.json({ error: "Not found" }, 404));

  return app;
}

let cachedApp: ReturnType<typeof createApp> | undefined;

export default {
  fetch(request: Request, env: IngestEnv, ctx: ExecutionContext) {
    if (!cachedApp) {
      const auth = createPicketAuth({
        db: env.AUTH_DB,
        baseURL: new URL(request.url).origin,
        secret: env.BETTER_AUTH_SECRET
      });
      cachedApp = createApp({ auth });
    }
    return cachedApp.fetch(request, env, ctx);
  }
} satisfies ExportedHandler<IngestEnv>;

async function postToDetection(events: OcsfEvent[], detectionWorker: Fetcher): Promise<DetectionResult[]> {
  const results: DetectionResult[] = [];
  for (const event of events) {
    const response = await detectionWorker.fetch("https://picket-detection/events", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(event)
    });
    if (!response.ok) {
      throw new Error(`Detection Worker rejected event with status ${response.status}: ${await response.text()}`);
    }
    results.push(await response.json<DetectionResult>());
  }
  return results;
}

export async function writeEventsToPipeline(source: SourceId, events: OcsfEvent[], env: IngestEnv): Promise<void> {
  if (events.length === 0) return;

  const pipeline = pipelineForSource(source, env);
  if (!pipeline) {
    console.warn(JSON.stringify({ message: "no event pipeline configured", source, event_count: events.length }));
    return;
  }

  await pipeline.send(events.map((event) => flattenOcsfEvent(event)));
}

function pipelineForSource(source: SourceId, env: IngestEnv): PicketPipeline | undefined {
  if (source === "aws_cloudtrail") return env.AWS_CLOUDTRAIL_PIPELINE;
  if (source === "aws_vpc_flow") return env.AWS_VPC_FLOW_PIPELINE;
  if (source === "aws_guardduty") return env.AWS_GUARDDUTY_PIPELINE;
  if (source === "gcp_cloud_audit") return env.GCP_CLOUD_AUDIT_PIPELINE;
  if (source === "azure_activity") return env.AZURE_ACTIVITY_PIPELINE;
  if (source === "azure_ad_signin") return env.AZURE_AD_SIGNIN_PIPELINE;
  if (source === "github_audit") return env.GITHUB_AUDIT_PIPELINE;
  if (source === "m365_management") return env.M365_MANAGEMENT_PIPELINE;
  if (source === "kubernetes_audit") return env.KUBERNETES_AUDIT_PIPELINE;
  if (source === "cloudflare_audit") return env.CLOUDFLARE_AUDIT_PIPELINE;
  return undefined;
}

async function safelyEnrichEvents(
  kv: IocKvNamespace | undefined,
  source: SourceId,
  events: OcsfEvent[]
): Promise<void> {
  if (!kv || events.length === 0) return;
  try {
    const { match_count } = await enrichEvents(events, kv);
    if (match_count > 0) {
      console.log(JSON.stringify({ message: "ingest enrichment matched", source, match_count }));
    }
  } catch (error) {
    console.error(JSON.stringify({ message: "ingest enrichment failed", source, error: errorMessage(error) }));
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function maxEventTime(events: readonly OcsfEvent[]): string | null {
  let latest: string | null = null;
  for (const event of events) {
    if (typeof event.time === "string" && event.time.length > 0) {
      if (latest === null || event.time > latest) latest = event.time;
    }
  }
  return latest;
}

async function safelyRecordIngestBatch(
  db: D1Database | undefined,
  source: SourceId,
  tenantId: string,
  events: readonly OcsfEvent[]
): Promise<void> {
  if (!db) return;
  try {
    await recordIngestBatch(db as unknown as AlertStateDb, {
      source,
      tenant_id: tenantId,
      event_count: events.length,
      last_event_at: maxEventTime(events)
    });
  } catch (error) {
    console.error(
      JSON.stringify({
        message: "source_health batch write failed",
        source,
        tenant_id: tenantId,
        error: errorMessage(error)
      })
    );
  }
}

async function safelyRecordIngestError(
  db: D1Database | undefined,
  source: SourceId,
  tenantId: string,
  message: string
): Promise<void> {
  if (!db) return;
  try {
    await recordIngestError(db as unknown as AlertStateDb, {
      source,
      tenant_id: tenantId,
      message
    });
  } catch (error) {
    console.error(
      JSON.stringify({
        message: "source_health error write failed",
        source,
        tenant_id: tenantId,
        error: errorMessage(error)
      })
    );
  }
}
