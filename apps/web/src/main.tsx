import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createRootRoute, createRoute, createRouter, Link, Outlet } from "@tanstack/react-router";

import { AlertDetailPage } from "./pages/alert-detail";
import { AlertsPage } from "./pages/alerts";
import { DashboardPage } from "./pages/dashboard";
import { DetectionDetailPage } from "./pages/detection-detail";
import { DetectionsPage } from "./pages/detections";
import { EnrichmentPage } from "./pages/enrichment";
import { QueryPage } from "./pages/query";
import { SourcesPage } from "./pages/sources";
import { SourceDetailPage } from "./pages/source-detail";
import { SessionStatus } from "./session";
import "./styles.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 10_000
    }
  }
});

function AppShell() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">P</span>
          <div>
            <strong>Picket</strong>
            <small>Serverless SIEM</small>
          </div>
        </div>
        <nav className="nav-links">
          <Link to="/" activeProps={{ className: "active" }} activeOptions={{ exact: true }}>Dashboard</Link>
          <Link to="/alerts" activeProps={{ className: "active" }}>Alerts</Link>
          <Link to="/detections" activeProps={{ className: "active" }}>Detections</Link>
          <Link to="/sources" activeProps={{ className: "active" }}>Sources</Link>
          <Link to="/enrichment" activeProps={{ className: "active" }}>Enrichment</Link>
          <Link to="/query" activeProps={{ className: "active" }}>Query</Link>
        </nav>
      </aside>
      <main className="content">
        <header className="topbar">
          <div>
            <p className="eyebrow">Analyst console</p>
            <h1>Security operations</h1>
          </div>
          <SessionStatus />
        </header>
        <Outlet />
      </main>
    </div>
  );
}

const rootRoute = createRootRoute({ component: AppShell });
const indexRoute = createRoute({ getParentRoute: () => rootRoute, path: "/", component: DashboardPage });
const alertsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/alerts", component: AlertsPage });
const alertDetailRoute = createRoute({ getParentRoute: () => rootRoute, path: "/alerts/$alertId", component: AlertDetailPage });
const detectionsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/detections", component: DetectionsPage });
const detectionDetailRoute = createRoute({ getParentRoute: () => rootRoute, path: "/detections/$ruleId", component: DetectionDetailPage });
const sourcesRoute = createRoute({ getParentRoute: () => rootRoute, path: "/sources", component: SourcesPage });
const enrichmentRoute = createRoute({ getParentRoute: () => rootRoute, path: "/enrichment", component: EnrichmentPage });
const sourceDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sources/$sourceId",
  validateSearch: (search: Record<string, unknown>): { tenant?: string } => ({
    tenant: typeof search.tenant === "string" && search.tenant.length > 0 ? search.tenant : undefined
  }),
  component: SourceDetailPage
});
const queryRoute = createRoute({ getParentRoute: () => rootRoute, path: "/query", component: QueryPage });

const routeTree = rootRoute.addChildren([indexRoute, alertsRoute, alertDetailRoute, detectionsRoute, detectionDetailRoute, sourcesRoute, sourceDetailRoute, enrichmentRoute, queryRoute]);
const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

const root = document.getElementById("root");
if (!root) throw new Error("Missing #root element");

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>
);
