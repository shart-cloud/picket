import type { Hono } from "hono";

import { buildDashboardOverview } from "@picket/core/dashboard";

import type { AdminEnv } from "./index";

export interface DashboardRoutesOptions {
  now?: () => Date;
}

// Dashboard overview (Milestone 1): a single aggregation endpoint over the
// existing source_health, alerts, and detection registries. UI-ready and useful
// for CLI/automation today.
export function registerDashboardRoutes(
  app: Hono<{ Bindings: AdminEnv }>,
  options: DashboardRoutesOptions = {}
): void {
  const now = options.now ?? (() => new Date());

  app.get("/api/v1/dashboard/overview", async (c) => {
    const url = new URL(c.req.url);
    const tenant = url.searchParams.get("tenant") ?? undefined;
    const overview = await buildDashboardOverview(c.env.ALERT_STATE_DB, {
      now: now(),
      tenant_id: tenant
    });
    return c.json({ overview });
  });
}
