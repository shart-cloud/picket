import { describe, expect, it, vi } from "vitest";
import type { Alert } from "@picket/core";
import { FakeAlertDb } from "@picket/core/alerts-fake-db";
import cloudflareAuditFixture from "../../../fixtures/cloudflare-audit/user-update.json";
import cloudTrailFixture from "../../../fixtures/cloudtrail/root-console-login.json";
import guardDutyFixture from "../../../fixtures/guardduty/unauthorized-access.json";
import gcpCloudAuditFixture from "../../../fixtures/gcp-cloud-audit/iam-policy-set.json";
import azureActivityFixture from "../../../fixtures/azure-activity/role-assignment-write.json";
import azureAdSigninFixture from "../../../fixtures/azure-ad-signin/failed-mfa.json";
import githubAuditFixture from "../../../fixtures/github-audit/repo-visibility-change.json";
import m365ManagementFixture from "../../../fixtures/m365-management/inbox-rule-created.json";
import k8sFixture from "../../../fixtures/k8s-audit/eks-anonymous-success.json";
import detectionWorker from "../../detection/dist/index.js";
import type { PicketAuth, PicketKeyMetadata } from "@picket/api";
import { createApp, writeEventsToPipeline, type IngestEnv } from "./index";
import { normalizeCloudTrail } from "@picket/normalize";
import { iocKey, type IocKvNamespace, type IocRecord } from "@picket/core/enrichment";

const vpcFlowFixture = "2 123456789012 eni-0abc123def4567890 10.0.1.10 198.51.100.42 44321 443 6 12 840 1716739200 1716739260 ACCEPT OK";

// Read-only KV fake: enrichEvents only ever GETs. put/delete/list are present to
// satisfy the interface but unused on the ingest path.
function fakeEnrichmentKv(iocs: IocRecord[]): IocKvNamespace {
  const store = new Map(iocs.map((ioc) => [iocKey(ioc.indicator_type, ioc.indicator), JSON.stringify(ioc)]));
  return {
    async get(key) {
      return store.get(key) ?? null;
    },
    async put() {},
    async delete() {},
    async list() {
      return { keys: [], list_complete: true };
    }
  };
}

type KeyRecord = {
  id: string;
  userId: string;
  metadata: PicketKeyMetadata;
};

function fakeAuth(keys: Record<string, KeyRecord>): PicketAuth {
  return {
    api: {
      verifyApiKey: async ({ body }: { body: { key: string } }) => {
        const key = keys[body.key];
        if (!key) return { valid: false, key: null };
        return { valid: true, key };
      }
    }
  } as unknown as PicketAuth;
}

function detectionBinding(send: ReturnType<typeof vi.fn>): Fetcher {
  return {
    fetch(input: RequestInfo | URL, init?: RequestInit) {
      const request = input instanceof Request ? input : new Request(input, init);
      return detectionWorker.fetch(request, {
        ALERT_QUEUE: { send } as unknown as Queue<Alert>
      });
    }
  } as unknown as Fetcher;
}

function makeEnv(send: ReturnType<typeof vi.fn>): IngestEnv {
  return {
    DETECTION_WORKER: detectionBinding(send),
    AUTH_DB: {} as D1Database,
    BETTER_AUTH_SECRET: "test"
  };
}

describe("picket-ingest", () => {
  it("rejects requests without an api key", async () => {
    const app = createApp({ auth: fakeAuth({}) });
    const env = makeEnv(vi.fn());
    const res = await app.request("/events", { method: "POST", body: "{}" }, env);
    expect(res.status).toBe(401);
  });

  it("rejects requests with an invalid api key", async () => {
    const app = createApp({ auth: fakeAuth({}) });
    const env = makeEnv(vi.fn());
    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "nope" },
      body: "{}"
    }, env);
    expect(res.status).toBe(401);
  });

  it("accepts cloudtrail events and forwards to detection", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const auth = fakeAuth({
      "ct-key": { id: "k1", userId: "u1", metadata: { source: "aws_cloudtrail", tenant_id: "tenant-a" } }
    });
    const app = createApp({ auth });
    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "ct-key", "Content-Type": "application/json" },
      body: JSON.stringify(cloudTrailFixture)
    }, makeEnv(send));

    expect(res.status).toBe(202);
    const json = await res.json() as { accepted: boolean; event_count: number; alert_count: number };
    expect(json.accepted).toBe(true);
    expect(json.event_count).toBe(1);
    expect(json.alert_count).toBeGreaterThanOrEqual(1);
    expect(send).toHaveBeenCalled();
  });

  it("accepts k8s NDJSON events with a kubernetes_audit key", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const auth = fakeAuth({
      "k8s-key": { id: "k2", userId: "u1", metadata: { source: "kubernetes_audit", tenant_id: "tenant-a" } }
    });
    const app = createApp({ auth });
    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "k8s-key", "Content-Type": "application/x-ndjson" },
      body: JSON.stringify(k8sFixture) + "\n"
    }, makeEnv(send));

    expect(res.status).toBe(202);
    const json = await res.json() as { accepted: boolean; event_count: number };
    expect(json.accepted).toBe(true);
    expect(json.event_count).toBe(1);
  });

  it("accepts VPC Flow Logs text records with an aws_vpc_flow key", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const pipelineSend = vi.fn<(records: Record<string, unknown>[]) => Promise<void>>().mockResolvedValue(undefined);
    const auth = fakeAuth({
      "vpc-key": { id: "k4", userId: "u1", metadata: { source: "aws_vpc_flow", tenant_id: "tenant-a" } }
    });
    const app = createApp({ auth });
    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "vpc-key", "Content-Type": "text/plain" },
      body: vpcFlowFixture
    }, {
      ...makeEnv(send),
      AWS_VPC_FLOW_PIPELINE: { send: pipelineSend }
    });

    expect(res.status).toBe(202);
    const json = await res.json() as { accepted: boolean; event_count: number };
    expect(json.accepted).toBe(true);
    expect(json.event_count).toBe(1);
    expect(pipelineSend).toHaveBeenCalledWith([expect.objectContaining({
      source: "aws_vpc_flow",
      class_name: "network_activity",
      src_endpoint_ip: "10.0.1.10",
      dst_endpoint_ip: "198.51.100.42"
    })]);
  });

  it("accepts GuardDuty findings with an aws_guardduty key", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const pipelineSend = vi.fn<(records: Record<string, unknown>[]) => Promise<void>>().mockResolvedValue(undefined);
    const auth = fakeAuth({
      "gd-key": { id: "k5", userId: "u1", metadata: { source: "aws_guardduty", tenant_id: "tenant-a" } }
    });
    const app = createApp({ auth });
    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "gd-key", "Content-Type": "application/json" },
      body: JSON.stringify(guardDutyFixture)
    }, {
      ...makeEnv(send),
      AWS_GUARDDUTY_PIPELINE: { send: pipelineSend }
    });

    expect(res.status).toBe(202);
    const json = await res.json() as { accepted: boolean; event_count: number };
    expect(json.accepted).toBe(true);
    expect(json.event_count).toBe(1);
    expect(pipelineSend).toHaveBeenCalledWith([expect.objectContaining({
      source: "aws_guardduty",
      class_name: "detection_finding",
      src_endpoint_ip: "198.51.100.66"
    })]);
  });

  it("accepts GCP Cloud Audit NDJSON with a gcp_cloud_audit key", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const pipelineSend = vi.fn<(records: Record<string, unknown>[]) => Promise<void>>().mockResolvedValue(undefined);
    const auth = fakeAuth({
      "gcp-key": { id: "k6", userId: "u1", metadata: { source: "gcp_cloud_audit", tenant_id: "tenant-a" } }
    });
    const app = createApp({ auth });
    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "gcp-key", "Content-Type": "application/x-ndjson" },
      body: JSON.stringify(gcpCloudAuditFixture) + "\n"
    }, {
      ...makeEnv(send),
      GCP_CLOUD_AUDIT_PIPELINE: { send: pipelineSend }
    });

    expect(res.status).toBe(202);
    const json = await res.json() as { accepted: boolean; event_count: number };
    expect(json.accepted).toBe(true);
    expect(json.event_count).toBe(1);
    expect(pipelineSend).toHaveBeenCalledWith([expect.objectContaining({
      source: "gcp_cloud_audit",
      class_name: "api_activity",
      api_operation: "SetIamPolicy"
    })]);
  });

  it("accepts Azure Activity records with an azure_activity key", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const pipelineSend = vi.fn<(records: Record<string, unknown>[]) => Promise<void>>().mockResolvedValue(undefined);
    const auth = fakeAuth({
      "az-key": { id: "k7", userId: "u1", metadata: { source: "azure_activity", tenant_id: "tenant-a" } }
    });
    const app = createApp({ auth });
    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "az-key", "Content-Type": "application/json" },
      body: JSON.stringify({ records: [azureActivityFixture] })
    }, {
      ...makeEnv(send),
      AZURE_ACTIVITY_PIPELINE: { send: pipelineSend }
    });

    expect(res.status).toBe(202);
    const json = await res.json() as { accepted: boolean; event_count: number };
    expect(json.accepted).toBe(true);
    expect(json.event_count).toBe(1);
    expect(pipelineSend).toHaveBeenCalledWith([expect.objectContaining({
      source: "azure_activity",
      class_name: "api_activity",
      actor_user_email: "admin@example.com"
    })]);
  });

  it("accepts Azure AD sign-in records with an azure_ad_signin key", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const pipelineSend = vi.fn<(records: Record<string, unknown>[]) => Promise<void>>().mockResolvedValue(undefined);
    const auth = fakeAuth({
      "aad-key": { id: "k8", userId: "u1", metadata: { source: "azure_ad_signin", tenant_id: "tenant-a" } }
    });
    const app = createApp({ auth });
    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "aad-key", "Content-Type": "application/json" },
      body: JSON.stringify({ value: [azureAdSigninFixture] })
    }, {
      ...makeEnv(send),
      AZURE_AD_SIGNIN_PIPELINE: { send: pipelineSend }
    });

    expect(res.status).toBe(202);
    const json = await res.json() as { accepted: boolean; event_count: number };
    expect(json.accepted).toBe(true);
    expect(json.event_count).toBe(1);
    expect(pipelineSend).toHaveBeenCalledWith([expect.objectContaining({
      source: "azure_ad_signin",
      class_name: "authentication",
      actor_user_email: "alice@example.com",
      src_endpoint_ip: "198.51.100.77"
    })]);
  });

  it("accepts GitHub audit records with a github_audit key", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const pipelineSend = vi.fn<(records: Record<string, unknown>[]) => Promise<void>>().mockResolvedValue(undefined);
    const auth = fakeAuth({
      "gh-key": { id: "k9", userId: "u1", metadata: { source: "github_audit", tenant_id: "tenant-a" } }
    });
    const app = createApp({ auth });
    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "gh-key", "Content-Type": "application/x-ndjson" },
      body: JSON.stringify(githubAuditFixture) + "\n"
    }, {
      ...makeEnv(send),
      GITHUB_AUDIT_PIPELINE: { send: pipelineSend }
    });

    expect(res.status).toBe(202);
    const json = await res.json() as { accepted: boolean; event_count: number };
    expect(json.accepted).toBe(true);
    expect(json.event_count).toBe(1);
    expect(pipelineSend).toHaveBeenCalledWith([expect.objectContaining({
      source: "github_audit",
      class_name: "api_activity",
      actor_user_name: "alice",
      src_endpoint_ip: "203.0.113.88"
    })]);
  });

  it("accepts M365 Management Activity records with a m365_management key", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const pipelineSend = vi.fn<(records: Record<string, unknown>[]) => Promise<void>>().mockResolvedValue(undefined);
    const auth = fakeAuth({
      "m365-key": { id: "k10", userId: "u1", metadata: { source: "m365_management", tenant_id: "tenant-a" } }
    });
    const app = createApp({ auth });
    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "m365-key", "Content-Type": "application/json" },
      body: JSON.stringify({ value: [m365ManagementFixture] })
    }, {
      ...makeEnv(send),
      M365_MANAGEMENT_PIPELINE: { send: pipelineSend }
    });

    expect(res.status).toBe(202);
    const json = await res.json() as { accepted: boolean; event_count: number };
    expect(json.accepted).toBe(true);
    expect(json.event_count).toBe(1);
    expect(pipelineSend).toHaveBeenCalledWith([expect.objectContaining({
      source: "m365_management",
      class_name: "api_activity",
      actor_user_email: "alice@example.com",
      api_operation: "New-InboxRule"
    })]);
  });

  it("accepts Cloudflare audit NDJSON batches with a cloudflare_audit key", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const auth = fakeAuth({
      "cf-key": { id: "k3", userId: "u1", metadata: { source: "cloudflare_audit", tenant_id: "tenant-a" } }
    });
    const app = createApp({ auth });
    const pipelineSend = vi.fn<(records: Record<string, unknown>[]) => Promise<void>>().mockResolvedValue(undefined);
    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "cf-key", "Content-Type": "application/x-ndjson" },
      body: JSON.stringify(cloudflareAuditFixture) + "\n"
    }, {
      ...makeEnv(send),
      CLOUDFLARE_AUDIT_PIPELINE: { send: pipelineSend }
    });

    expect(res.status).toBe(202);
    const json = await res.json() as { accepted: boolean; event_count: number };
    expect(json.accepted).toBe(true);
    expect(json.event_count).toBe(1);
    expect(pipelineSend).toHaveBeenCalledWith([expect.objectContaining({ source: "cloudflare_audit", activity_name: "zone_settings_update" })]);
  });

  it("drops a malformed record in a cloudtrail batch instead of failing the whole batch", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const auth = fakeAuth({
      "ct-key": { id: "k1", userId: "u1", metadata: { source: "aws_cloudtrail", tenant_id: "tenant-a" } }
    });
    const app = createApp({ auth });
    // Second record is a ConsoleLogin with no userIdentity -> fails strict OCSF
    // validation (authentication events require actor.user identity).
    const batch = { Records: [cloudTrailFixture, { eventName: "ConsoleLogin", eventTime: "2026-05-26T12:00:00Z" }] };
    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "ct-key", "Content-Type": "application/json" },
      body: JSON.stringify(batch)
    }, makeEnv(send));

    expect(res.status).toBe(202);
    const json = await res.json() as { accepted: boolean; event_count: number; parse_failures: number };
    expect(json.accepted).toBe(true);
    expect(json.event_count).toBe(1);
    expect(json.parse_failures).toBe(1);
  });

  it("returns 400 when cloudtrail key receives a non-object payload", async () => {
    const auth = fakeAuth({
      "ct-key": { id: "k1", userId: "u1", metadata: { source: "aws_cloudtrail", tenant_id: "tenant-a" } }
    });
    const app = createApp({ auth });
    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "ct-key", "Content-Type": "application/json" },
      body: JSON.stringify([])
    }, makeEnv(vi.fn()));

    expect(res.status).toBe(400);
  });

  it("serves health without auth", async () => {
    const app = createApp({ auth: fakeAuth({}) });
    const res = await app.request("/health", {}, makeEnv(vi.fn()));
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({ ok: true });
  });

  it("records source_health on a successful batch when ALERT_STATE_DB is bound", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const auth = fakeAuth({
      "ct-key": { id: "k1", userId: "u1", metadata: { source: "aws_cloudtrail", tenant_id: "tenant-a" } }
    });
    const db = new FakeAlertDb();
    const env: IngestEnv = {
      ...makeEnv(send),
      ALERT_STATE_DB: db as unknown as D1Database
    };
    const app = createApp({ auth });

    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "ct-key", "Content-Type": "application/json" },
      body: JSON.stringify(cloudTrailFixture)
    }, env);

    expect(res.status).toBe(202);
    expect(db.sourceHealth).toHaveLength(1);
    expect(db.sourceHealth[0]).toMatchObject({
      source: "aws_cloudtrail",
      tenant_id: "tenant-a",
      total_batches: 1,
      total_events: 1,
      total_errors: 0
    });
    expect(db.sourceHealth[0]?.last_event_at).toBeTruthy();
  });

  it("ingest still works when ALERT_STATE_DB is absent", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const auth = fakeAuth({
      "ct-key": { id: "k1", userId: "u1", metadata: { source: "aws_cloudtrail", tenant_id: "tenant-a" } }
    });
    const app = createApp({ auth });
    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "ct-key", "Content-Type": "application/json" },
      body: JSON.stringify(cloudTrailFixture)
    }, makeEnv(send));

    expect(res.status).toBe(202);
  });

  it("stamps threat_match when a source IP matches an IOC in ENRICHMENT_KV", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const pipelineSend = vi.fn<(records: Record<string, unknown>[]) => Promise<void>>().mockResolvedValue(undefined);
    const auth = fakeAuth({
      "ct-key": { id: "k1", userId: "u1", metadata: { source: "aws_cloudtrail", tenant_id: "tenant-a" } }
    });
    const app = createApp({ auth });
    const env: IngestEnv = {
      ...makeEnv(send),
      AWS_CLOUDTRAIL_PIPELINE: { send: pipelineSend },
      // 203.0.113.10 is the sourceIPAddress in the fixture.
      ENRICHMENT_KV: fakeEnrichmentKv([
        { indicator: "203.0.113.10", indicator_type: "ipv4", feed_name: "abuse.ch", threat_type: "c2" }
      ])
    };

    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "ct-key", "Content-Type": "application/json" },
      body: JSON.stringify(cloudTrailFixture)
    }, env);

    expect(res.status).toBe(202);
    expect(pipelineSend).toHaveBeenCalledWith([
      expect.objectContaining({
        threat_match_indicator: "203.0.113.10",
        threat_match_indicator_type: "ipv4",
        threat_match_field: "src_endpoint_ip",
        threat_match_feed_name: "abuse.ch",
        threat_match_threat_type: "c2"
      })
    ]);
  });

  it("leaves events unstamped when no IOC matches", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const pipelineSend = vi.fn<(records: Record<string, unknown>[]) => Promise<void>>().mockResolvedValue(undefined);
    const auth = fakeAuth({
      "ct-key": { id: "k1", userId: "u1", metadata: { source: "aws_cloudtrail", tenant_id: "tenant-a" } }
    });
    const app = createApp({ auth });
    const env: IngestEnv = {
      ...makeEnv(send),
      AWS_CLOUDTRAIL_PIPELINE: { send: pipelineSend },
      ENRICHMENT_KV: fakeEnrichmentKv([{ indicator: "1.1.1.1", indicator_type: "ipv4" }])
    };

    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "ct-key", "Content-Type": "application/json" },
      body: JSON.stringify(cloudTrailFixture)
    }, env);

    expect(res.status).toBe(202);
    const record = pipelineSend.mock.calls[0]?.[0]?.[0] ?? {};
    expect("threat_match_indicator" in record).toBe(false);
  });

  it("ingest succeeds when ENRICHMENT_KV throws", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const auth = fakeAuth({
      "ct-key": { id: "k1", userId: "u1", metadata: { source: "aws_cloudtrail", tenant_id: "tenant-a" } }
    });
    const app = createApp({ auth });
    const brokenKv: IocKvNamespace = {
      get: async () => { throw new Error("KV down"); },
      put: async () => {},
      delete: async () => {},
      list: async () => ({ keys: [], list_complete: true })
    };
    const res = await app.request("/events", {
      method: "POST",
      headers: { "x-api-key": "ct-key", "Content-Type": "application/json" },
      body: JSON.stringify(cloudTrailFixture)
    }, { ...makeEnv(send), ENRICHMENT_KV: brokenKv });

    expect(res.status).toBe(202);
  });

  it("writes normalized events to the source pipeline when configured", async () => {
    const send = vi.fn<(records: Record<string, unknown>[]) => Promise<void>>().mockResolvedValue(undefined);
    const event = normalizeCloudTrail(cloudTrailFixture);

    await writeEventsToPipeline("aws_cloudtrail", [event], {
      ...makeEnv(vi.fn()),
      AWS_CLOUDTRAIL_PIPELINE: { send }
    });

    expect(send).toHaveBeenCalledWith([expect.objectContaining({ source: "aws_cloudtrail", activity_name: "ConsoleLogin" })]);
  });
});
