import type { Context, Hono } from "hono";

import type { PicketAuth } from "@picket/api";

import type { AdminEnv } from "./index";

export interface DeviceRoutesOptions {
  resolveAuth: (c: Context<{ Bindings: AdminEnv }>) => PicketAuth;
}

// HTML approval page for the device-authorization flow. The user reaches this
// page after the CLI prints the verification URL; Access has already verified
// them at the edge, and this Worker extracts their identity from the Access
// JWT. The page shows the user code and two POST forms (approve / deny) that
// submit back to handlers on this Worker.
//
// We bypass better-auth's own /device/approve and /device/deny endpoints
// because those require an existing better-auth session — and the MVP has no
// human login flow to produce one. Instead the handlers find-or-create a
// better-auth user keyed on the Access email and write the deviceCode row
// directly. When human login lands, we'll add a sessionUser branch alongside
// the Access branch in `resolveDeviceActor`.
export function registerDeviceRoutes(
  app: Hono<{ Bindings: AdminEnv }>,
  options: DeviceRoutesOptions
): void {
  app.get("/device", (c) => {
    const userCode = (c.req.query("user_code") ?? "").trim();
    const errorMsg = c.req.query("error");
    const status = c.req.query("status");
    return c.html(renderDevicePage({ userCode, error: errorMsg, status }));
  });

  app.post("/device/approve", async (c) => decideDevice(c, options, "approved"));
  app.post("/device/deny", async (c) => decideDevice(c, options, "denied"));
}

async function decideDevice(
  c: Context<{ Bindings: AdminEnv }>,
  options: DeviceRoutesOptions,
  decision: "approved" | "denied"
): Promise<Response> {
  const body = await readFormOrJson(c);
  const userCode = typeof body.user_code === "string" ? body.user_code.trim() : "";
  if (userCode.length === 0) {
    return redirectBack(c, "", "Missing user code.");
  }

  const access = c.get("accessUser");
  const email = access?.email;
  if (!email) {
    return redirectBack(c, userCode, "Could not determine your identity from the Access token.");
  }

  const auth = options.resolveAuth(c);
  const user = await auth.findOrCreateUserByEmail(email);
  const result = await auth.decideDeviceCode(userCode, user.id, decision);

  if (!result.ok) {
    const message =
      result.reason === "not_found"
        ? "That code isn't valid."
        : result.reason === "expired"
          ? "That code has expired. Restart the login flow in your CLI."
          : "That code was already used.";
    return redirectBack(c, userCode, message);
  }

  // Accept-driven content negotiation: JSON for fetch callers, redirect for
  // form posts.
  const accept = c.req.header("accept") ?? "";
  if (accept.includes("application/json")) {
    return c.json({ status: result.status, user_code: userCode });
  }
  return redirectBack(c, userCode, undefined, result.status);
}

async function readFormOrJson(
  c: Context<{ Bindings: AdminEnv }>
): Promise<Record<string, string>> {
  const contentType = c.req.header("content-type") ?? "";
  try {
    if (contentType.includes("application/json")) {
      const parsed = (await c.req.raw.clone().json()) as Record<string, unknown>;
      return Object.fromEntries(
        Object.entries(parsed).map(([k, v]) => [k, typeof v === "string" ? v : ""])
      );
    }
    if (contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data")) {
      const form = await c.req.raw.clone().formData();
      const out: Record<string, string> = {};
      for (const [k, v] of form.entries()) {
        if (typeof v === "string") out[k] = v;
      }
      return out;
    }
  } catch {
    // fallthrough
  }
  return {};
}

function redirectBack(
  c: Context<{ Bindings: AdminEnv }>,
  userCode: string,
  error: string | undefined,
  status: "approved" | "denied" | undefined = undefined
): Response {
  const url = new URL("/device", new URL(c.req.url));
  if (userCode) url.searchParams.set("user_code", userCode);
  if (status) url.searchParams.set("status", status);
  if (error) url.searchParams.set("error", error);
  return c.redirect(url.pathname + url.search, 303);
}

interface RenderArgs {
  userCode: string;
  error?: string;
  status?: string;
}

// Inline HTML. No framework, no static assets — keeps the Worker self-contained
// and avoids the asset pipeline for one page. All interpolated values are
// escaped via escapeHtml; user_code is also constrained to A–Z0–9 + dash before
// rendering so even an escape-bypass would produce a no-op.
function renderDevicePage({ userCode, error, status }: RenderArgs): string {
  const safeCode = escapeHtml(sanitizeCode(userCode));
  const safeError = error ? escapeHtml(error) : "";
  const safeStatus = status === "approved" || status === "denied" ? status : "";

  const banner = safeStatus
    ? safeStatus === "approved"
      ? `<div class="ok">Device approved. You can close this window and return to your terminal.</div>`
      : `<div class="warn">Device denied. The CLI session will not be issued.</div>`
    : safeError
      ? `<div class="err">${safeError}</div>`
      : "";

  const formSection =
    safeStatus === "approved" || safeStatus === "denied"
      ? ""
      : `
    <p class="lead">A device is requesting access to Picket. If you started this on your own machine just now, approve it.</p>
    <div class="code-block"><span class="label">User code</span><code>${formatUserCodeForDisplay(safeCode)}</code></div>
    <form method="post" action="/device/approve" class="actions">
      <input type="hidden" name="user_code" value="${safeCode}">
      <button type="submit" class="primary">Approve</button>
    </form>
    <form method="post" action="/device/deny" class="actions">
      <input type="hidden" name="user_code" value="${safeCode}">
      <button type="submit" class="secondary">Deny</button>
    </form>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Picket — Device authorization</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1.5rem; }
  h1 { font-size: 1.4rem; margin: 0 0 0.5rem; }
  .lead { color: #555; }
  .code-block { background: #f4f4f4; border-radius: 8px; padding: 1rem 1.25rem; margin: 1.5rem 0; }
  .code-block .label { display: block; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; color: #666; margin-bottom: 0.25rem; }
  .code-block code { font: 600 1.6rem/1 ui-monospace,Menlo,Consolas,monospace; letter-spacing: 0.15em; }
  .actions { display: inline-block; margin: 0 0.5rem 0 0; }
  button { font: 500 0.95rem/1 inherit; padding: 0.6rem 1.1rem; border-radius: 6px; border: 1px solid transparent; cursor: pointer; }
  button.primary { background: #1a73e8; color: white; }
  button.secondary { background: transparent; border-color: #ccc; color: inherit; }
  .ok { background: #e6f4ea; color: #1e8e3e; padding: 0.75rem 1rem; border-radius: 6px; }
  .warn { background: #fef7e0; color: #b06000; padding: 0.75rem 1rem; border-radius: 6px; }
  .err { background: #fce8e6; color: #c5221f; padding: 0.75rem 1rem; border-radius: 6px; }
  @media (prefers-color-scheme: dark) {
    body { background: #1a1a1a; color: #e4e4e4; }
    .lead { color: #aaa; }
    .code-block { background: #2a2a2a; }
    .code-block .label { color: #999; }
    button.secondary { border-color: #555; }
    .ok { background: #1e3a26; color: #81c995; }
    .warn { background: #3a2e1a; color: #fdd663; }
    .err { background: #3a1e1c; color: #f28b82; }
  }
</style>
</head>
<body>
<h1>Picket — Device authorization</h1>
${banner}
${formSection}
</body>
</html>`;
}

function sanitizeCode(code: string): string {
  return code.replace(/[^A-Z0-9-]/gi, "").slice(0, 32);
}

function formatUserCodeForDisplay(code: string): string {
  const clean = code.replace(/-/g, "");
  if (clean.length === 8) return `${clean.slice(0, 4)}-${clean.slice(4)}`;
  return code;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
