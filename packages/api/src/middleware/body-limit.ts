import { bodyLimit } from "hono/body-limit";
import type { MiddlewareHandler } from "hono";
import type { SourceId } from "@picket/core";

export const SOURCE_LIMITS: Record<SourceId, number> = {
  aws_cloudtrail: 1_000_000,
  aws_vpc_flow: 5_000_000,
  aws_guardduty: 1_000_000,
  gcp_cloud_audit: 1_000_000,
  azure_activity: 1_000_000,
  azure_ad_signin: 1_000_000,
  github_audit: 1_000_000,
  m365_management: 1_000_000,
  cloudflare_audit: 1_000_000,
  kubernetes_audit: 5_000_000,
  okta_auth: 1_000_000
};

const DEFAULT_LIMIT = 1_000_000;

export function sourceBodyLimit(): MiddlewareHandler {
  return async (c, next) => {
    const source = c.get("apiKey")?.source;
    const maxSize = source ? SOURCE_LIMITS[source] ?? DEFAULT_LIMIT : DEFAULT_LIMIT;
    return bodyLimit({ maxSize, onError: (ctx) => ctx.json({ error: "Request body too large" }, 413) })(c, next);
  };
}
