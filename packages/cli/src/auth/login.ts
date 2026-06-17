import {
  cloudflaredAccessLogin,
  cloudflaredAccessToken,
  CloudflaredNotInstalledError,
  defaultCloudflaredRunner,
  type CloudflaredRunner
} from "./cloudflared.js";
import {
  createCredentialsIo,
  normalizeApiUrl,
  upsertCredential,
  type CredentialRecord,
  type CredentialsIo
} from "./credentials.js";

// Device-authorization login flow. Orchestrates:
//   1. GET /api/v1/meta — figure out whether Access is in front.
//   2. (optional) ensure a cloudflared-cached Access JWT.
//   3. POST /api/v1/auth/device/code — get user_code + device_code.
//   4. Show the user the verification URL; poll /device/token until success.
//   5. Persist the bearer token to the credentials file.

export const DEFAULT_CLIENT_ID = "picket-cli";

export interface LoginIo {
  stdout: Pick<NodeJS.WriteStream, "write">;
  stderr: Pick<NodeJS.WriteStream, "write">;
}

export interface LoginOptions {
  apiUrl: string;
  io: LoginIo;
  env: NodeJS.ProcessEnv;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  cloudflared?: CloudflaredRunner;
  credentialsIo?: CredentialsIo;
  openBrowser?: (url: string) => Promise<void> | void;
  noBrowser?: boolean;
  // Override polling cadence in tests.
  pollIntervalMs?: number;
  pollDeadlineMs?: number;
  clientId?: string;
  now?: () => Date;
}

export interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

export interface DeviceTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

export class DeviceAuthError extends Error {
  constructor(message: string, public readonly code?: string) {
    super(message);
    this.name = "DeviceAuthError";
  }
}

export async function runLogin(options: LoginOptions): Promise<CredentialRecord> {
  const apiUrl = normalizeApiUrl(options.apiUrl);
  const fetchImpl = options.fetch ?? fetch;
  const sleep = options.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
  const clientId = options.clientId ?? DEFAULT_CLIENT_ID;
  const now = options.now ?? (() => new Date());

  // 1. Discover whether Access is in front.
  const meta = await fetchMeta(fetchImpl, apiUrl);

  // 2. Access leg, if required.
  const accessJwt = meta.access_required ? await ensureAccessJwt(apiUrl, options) : undefined;
  if (meta.access_required && !accessJwt) {
    throw new DeviceAuthError(
      "Could not obtain a Cloudflare Access token. Install cloudflared or set CF_ACCESS_JWT."
    );
  }

  // 3. Request device + user codes.
  const deviceCode = await postJson<DeviceCodeResponse>(
    fetchImpl,
    `${apiUrl}/api/v1/auth/device/code`,
    { client_id: clientId },
    accessJwt
  );

  // 4. Tell the user what to do.
  const verificationUri = deviceCode.verification_uri_complete || deviceCode.verification_uri;
  options.io.stdout.write(
    `To finish signing in, visit:\n  ${verificationUri}\n\n` +
      `Code: ${deviceCode.user_code}\n\n` +
      `Waiting for approval (expires in ${Math.round(deviceCode.expires_in / 60)}m)...\n`
  );
  if (!options.noBrowser && options.openBrowser) {
    try {
      await options.openBrowser(verificationUri);
    } catch {
      // best-effort
    }
  }

  // 5. Poll /device/token.
  const pollInterval = Math.max(
    1,
    options.pollIntervalMs ?? deviceCode.interval * 1000
  );
  const deadline = now().getTime() + (options.pollDeadlineMs ?? deviceCode.expires_in * 1000);
  let currentInterval = pollInterval;

  while (now().getTime() < deadline) {
    await sleep(currentInterval);
    const result = await pollOnce(fetchImpl, apiUrl, deviceCode.device_code, clientId, accessJwt);
    if (result.kind === "ok") {
      const record: CredentialRecord = {
        api_url: apiUrl,
        access_token: result.token.access_token,
        expires_at: new Date(now().getTime() + result.token.expires_in * 1000).toISOString(),
        obtained_at: now().toISOString()
      };
      const io = options.credentialsIo ?? createCredentialsIo();
      const existing = await io.read().catch(() => ({ records: {} }));
      await io.write(upsertCredential(existing, record));
      options.io.stdout.write(`Signed in. Credentials written to ${io.filePath}\n`);
      return record;
    }
    if (result.kind === "pending") continue;
    if (result.kind === "slow_down") {
      currentInterval = Math.min(currentInterval + 5_000, 30_000);
      continue;
    }
    if (result.kind === "denied") throw new DeviceAuthError("Access denied at the approval page.", result.code);
    if (result.kind === "expired") throw new DeviceAuthError("Device code expired before approval.", result.code);
    throw new DeviceAuthError(result.message ?? "Device authorization failed.", result.code);
  }

  throw new DeviceAuthError("Device code expired before approval.");
}

interface MetaResponse {
  access_required: boolean;
  verification_uri?: string;
  api_url?: string;
}

async function fetchMeta(fetchImpl: typeof fetch, apiUrl: string): Promise<MetaResponse> {
  // Two flavors of "meta unreachable" both fall back to access_required=true:
  //   1. Older servers without /api/v1/meta → non-2xx
  //   2. Access app gates /api/v1/meta itself → 200 but Content-Type is HTML
  //      after following the redirect chain to the IdP login page
  // Either way the right move is to assume Access is in front and let the
  // cloudflared leg run.
  let res: Response;
  try {
    res = await fetchImpl(`${apiUrl}/api/v1/meta`);
  } catch {
    return { access_required: true };
  }
  if (!res.ok) return { access_required: true };
  const contentType = res.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) return { access_required: true };
  try {
    const body = (await res.json()) as MetaResponse;
    return { access_required: body.access_required !== false, verification_uri: body.verification_uri };
  } catch {
    return { access_required: true };
  }
}

async function ensureAccessJwt(apiUrl: string, options: LoginOptions): Promise<string | undefined> {
  if (options.env.CF_ACCESS_JWT) return options.env.CF_ACCESS_JWT;
  const runner = options.cloudflared ?? defaultCloudflaredRunner();

  try {
    let token = await cloudflaredAccessToken(runner, apiUrl);
    if (token) return token;

    options.io.stderr.write(`Opening browser to sign in to Cloudflare Access for ${apiUrl}...\n`);
    const login = await cloudflaredAccessLogin(runner, apiUrl);
    if (!login.ok) {
      options.io.stderr.write(`cloudflared login failed: ${login.stderr.trim()}\n`);
      return undefined;
    }
    token = await cloudflaredAccessToken(runner, apiUrl);
    return token;
  } catch (error) {
    if (error instanceof CloudflaredNotInstalledError) {
      options.io.stderr.write(`${error.message}\n`);
      return undefined;
    }
    throw error;
  }
}

async function postJson<T>(
  fetchImpl: typeof fetch,
  url: string,
  body: unknown,
  accessJwt: string | undefined
): Promise<T> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (accessJwt) headers["cf-access-jwt-assertion"] = accessJwt;
  const res = await fetchImpl(url, { method: "POST", headers, body: JSON.stringify(body) });
  const text = await res.text();
  let parsed: unknown;
  try {
    parsed = text.length === 0 ? null : JSON.parse(text);
  } catch {
    throw new DeviceAuthError(`Non-JSON response from ${url} (HTTP ${res.status}): ${text.slice(0, 200)}`);
  }
  if (!res.ok) {
    const errCode = parsed && typeof parsed === "object" && "error" in parsed ? String((parsed as { error: unknown }).error) : undefined;
    const errDesc = parsed && typeof parsed === "object" && "error_description" in parsed
      ? String((parsed as { error_description: unknown }).error_description)
      : `HTTP ${res.status}`;
    throw new DeviceAuthError(errDesc, errCode);
  }
  return parsed as T;
}

type PollResult =
  | { kind: "ok"; token: DeviceTokenResponse }
  | { kind: "pending" }
  | { kind: "slow_down" }
  | { kind: "denied"; code: string }
  | { kind: "expired"; code: string }
  | { kind: "error"; code?: string; message?: string };

async function pollOnce(
  fetchImpl: typeof fetch,
  apiUrl: string,
  deviceCode: string,
  clientId: string,
  accessJwt: string | undefined
): Promise<PollResult> {
  try {
    const token = await postJson<DeviceTokenResponse>(
      fetchImpl,
      `${apiUrl}/api/v1/auth/device/token`,
      {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: deviceCode,
        client_id: clientId
      },
      accessJwt
    );
    return { kind: "ok", token };
  } catch (error) {
    if (!(error instanceof DeviceAuthError)) throw error;
    switch (error.code) {
      case "authorization_pending":
        return { kind: "pending" };
      case "slow_down":
        return { kind: "slow_down" };
      case "access_denied":
        return { kind: "denied", code: error.code };
      case "expired_token":
        return { kind: "expired", code: error.code };
      default:
        return { kind: "error", code: error.code, message: error.message };
    }
  }
}
