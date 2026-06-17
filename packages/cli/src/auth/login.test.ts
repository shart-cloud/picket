import { describe, expect, it } from "vitest";

import { runLogin } from "./login.js";
import type { CredentialRecord, CredentialsIo, CredentialsStore } from "./credentials.js";
import type { CloudflaredRunner } from "./cloudflared.js";

interface FakeReq {
  url: string;
  method: string;
  body?: Record<string, unknown>;
  headers: Record<string, string>;
}

interface FakeRes {
  status: number;
  body?: unknown;
}

function fakeFetch(handler: (req: FakeReq) => FakeRes | Promise<FakeRes>) {
  const calls: FakeReq[] = [];
  const fn: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const method = init?.method ?? "GET";
    const headers: Record<string, string> = {};
    if (init?.headers && !(init.headers instanceof Headers) && !Array.isArray(init.headers)) {
      for (const [k, v] of Object.entries(init.headers)) headers[k.toLowerCase()] = String(v);
    }
    const bodyText = typeof init?.body === "string" ? init.body : undefined;
    const body = bodyText ? (JSON.parse(bodyText) as Record<string, unknown>) : undefined;
    calls.push({ url, method, body, headers });
    const res = await handler({ url, method, body, headers });
    return new Response(JSON.stringify(res.body ?? null), {
      status: res.status,
      headers: { "content-type": "application/json" }
    });
  };
  return { fetch: fn, calls };
}

function fakeCredentialsIo(): CredentialsIo & { latest: () => CredentialsStore } {
  let store: CredentialsStore = { records: {} };
  return {
    filePath: "/tmp/fake-creds.json",
    read: async () => store,
    write: async (next) => {
      store = next;
    },
    delete: async () => {
      store = { records: {} };
    },
    latest: () => store
  };
}

function fakeCloudflared(token: string | undefined): CloudflaredRunner {
  return {
    run: async (args: string[]) => {
      if (args[0] === "access" && args[1] === "token") {
        return { stdout: token ?? "", stderr: "", code: token ? 0 : 1 };
      }
      if (args[0] === "access" && args[1] === "login") {
        return { stdout: "", stderr: "", code: 0 };
      }
      return { stdout: "", stderr: "unknown", code: 1 };
    }
  };
}

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: {
      stdout: { write: (s: string) => { out.push(s); return true; } },
      stderr: { write: (s: string) => { err.push(s); return true; } }
    },
    out: () => out.join(""),
    err: () => err.join("")
  };
}

const VALID_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature";

describe("runLogin", () => {
  it("runs the full device flow and persists credentials", async () => {
    const { fetch: f } = fakeFetch(async (req) => {
      if (req.url.endsWith("/api/v1/meta")) return { status: 200, body: { access_required: true } };
      if (req.url.endsWith("/api/v1/auth/device/code")) {
        return {
          status: 200,
          body: {
            device_code: "DEV-1",
            user_code: "AAAA-BBBB",
            verification_uri: "https://api.test/device",
            verification_uri_complete: "https://api.test/device?user_code=AAAA-BBBB",
            expires_in: 900,
            interval: 5
          }
        };
      }
      if (req.url.endsWith("/api/v1/auth/device/token")) {
        // First call: pending. Second: approved.
        return req.headers["x-test-attempt"] === "2"
          ? { status: 200, body: { access_token: "session-token", token_type: "Bearer", expires_in: 3600 } }
          : { status: 400, body: { error: "authorization_pending", error_description: "wait" } };
      }
      return { status: 404, body: { error: "not found" } };
    });

    // Wrap to inject attempt header on token polls.
    let attempt = 0;
    const fetchWithAttempt: typeof fetch = (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.endsWith("/api/v1/auth/device/token")) {
        attempt += 1;
        return f(input, { ...init, headers: { ...(init?.headers as Record<string, string>), "x-test-attempt": String(attempt) } });
      }
      return f(input, init);
    };

    const credIo = fakeCredentialsIo();
    const cap = capture();
    const record = await runLogin({
      apiUrl: "https://api.test/",
      io: cap.io,
      env: {},
      fetch: fetchWithAttempt,
      sleep: async () => undefined,
      cloudflared: fakeCloudflared(VALID_JWT),
      credentialsIo: credIo,
      noBrowser: true,
      pollIntervalMs: 1,
      pollDeadlineMs: 5_000
    });

    expect(record.access_token).toBe("session-token");
    expect(record.api_url).toBe("https://api.test");
    const stored = Object.values(credIo.latest().records);
    expect(stored).toHaveLength(1);
    expect(stored[0]?.access_token).toBe("session-token");
    expect(cap.out()).toContain("AAAA-BBBB");
  });

  it("skips the Access leg when meta says access_required is false", async () => {
    const accessHeaders: string[] = [];
    const { fetch: f } = fakeFetch(async (req) => {
      // Track whether device endpoints saw an Access JWT.
      if (req.url.includes("/api/v1/auth/device")) {
        if (req.headers["cf-access-jwt-assertion"]) accessHeaders.push("present");
      }
      if (req.url.endsWith("/api/v1/meta")) return { status: 200, body: { access_required: false } };
      if (req.url.endsWith("/api/v1/auth/device/code")) {
        return { status: 200, body: { device_code: "D", user_code: "C", verification_uri: "u", verification_uri_complete: "u?c=1", expires_in: 60, interval: 1 } };
      }
      if (req.url.endsWith("/api/v1/auth/device/token")) {
        return { status: 200, body: { access_token: "tok", token_type: "Bearer", expires_in: 60 } };
      }
      return { status: 404, body: {} };
    });

    const credIo = fakeCredentialsIo();
    const cap = capture();
    await runLogin({
      apiUrl: "https://api.test",
      io: cap.io,
      env: {},
      fetch: f,
      sleep: async () => undefined,
      cloudflared: fakeCloudflared(undefined),
      credentialsIo: credIo,
      noBrowser: true,
      pollIntervalMs: 1
    });
    expect(accessHeaders).toEqual([]); // never attached
  });

  it("throws when device code is denied", async () => {
    const { fetch: f } = fakeFetch(async (req) => {
      if (req.url.endsWith("/api/v1/meta")) return { status: 200, body: { access_required: false } };
      if (req.url.endsWith("/api/v1/auth/device/code")) {
        return { status: 200, body: { device_code: "D", user_code: "C", verification_uri: "u", verification_uri_complete: "u", expires_in: 60, interval: 1 } };
      }
      return { status: 400, body: { error: "access_denied", error_description: "User denied" } };
    });

    const cap = capture();
    await expect(
      runLogin({
        apiUrl: "https://api.test",
        io: cap.io,
        env: {},
        fetch: f,
        sleep: async () => undefined,
        credentialsIo: fakeCredentialsIo(),
        noBrowser: true,
        pollIntervalMs: 1,
        pollDeadlineMs: 5_000
      })
    ).rejects.toThrow(/denied/i);
  });
});

describe("runLogin: credential record shape", () => {
  it("populates expires_at and obtained_at from clock", async () => {
    const fixedNow = new Date("2026-05-27T12:00:00.000Z");
    const { fetch: f } = fakeFetch(async (req) => {
      if (req.url.endsWith("/api/v1/meta")) return { status: 200, body: { access_required: false } };
      if (req.url.endsWith("/api/v1/auth/device/code")) {
        return { status: 200, body: { device_code: "D", user_code: "C", verification_uri: "u", verification_uri_complete: "u", expires_in: 60, interval: 1 } };
      }
      return { status: 200, body: { access_token: "t", token_type: "Bearer", expires_in: 3600 } };
    });

    const record = await runLogin({
      apiUrl: "https://api.test",
      io: capture().io,
      env: {},
      fetch: f,
      sleep: async () => undefined,
      now: () => fixedNow,
      credentialsIo: fakeCredentialsIo(),
      noBrowser: true,
      pollIntervalMs: 1
    });
    expect(record.obtained_at).toBe(fixedNow.toISOString());
    const expectedExpiry = new Date(fixedNow.getTime() + 3600 * 1000).toISOString();
    expect(record.expires_at).toBe(expectedExpiry);
  });
});

describe("runLogin matches typed contract", () => {
  it("returns a CredentialRecord shape", async () => {
    const { fetch: f } = fakeFetch(async (req) => {
      if (req.url.endsWith("/api/v1/meta")) return { status: 200, body: { access_required: false } };
      if (req.url.endsWith("/api/v1/auth/device/code")) {
        return { status: 200, body: { device_code: "D", user_code: "C", verification_uri: "u", verification_uri_complete: "u", expires_in: 60, interval: 1 } };
      }
      return { status: 200, body: { access_token: "t", token_type: "Bearer", expires_in: 60 } };
    });
    const rec: CredentialRecord = await runLogin({
      apiUrl: "https://api.test",
      io: capture().io,
      env: {},
      fetch: f,
      sleep: async () => undefined,
      credentialsIo: fakeCredentialsIo(),
      noBrowser: true,
      pollIntervalMs: 1
    });
    expect(typeof rec.access_token).toBe("string");
  });
});
