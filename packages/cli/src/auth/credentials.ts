import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

// Picket CLI credential store. One file, one record per API URL — keyed so a
// user with both staging and prod accounts doesn't clobber one with the other.
// Mode 0600; never committed.

export interface CredentialRecord {
  api_url: string;
  access_token: string;
  expires_at: string;
  obtained_at: string;
  // Free-form user info captured at login (email/name from whoami) so
  // `picket whoami` can render without an extra round-trip when the token is
  // still valid. Optional; not load-bearing.
  user?: { id?: string; email?: string; name?: string };
}

export interface CredentialsStore {
  records: Record<string, CredentialRecord>;
}

export interface CredentialsIo {
  filePath: string;
  read: () => Promise<CredentialsStore>;
  write: (store: CredentialsStore) => Promise<void>;
  delete: () => Promise<void>;
}

export interface CredentialsIoOptions {
  filePath?: string;
}

export function defaultCredentialsPath(env: NodeJS.ProcessEnv = process.env): string {
  if (env.PICKET_CREDENTIALS_FILE && env.PICKET_CREDENTIALS_FILE.length > 0) {
    return env.PICKET_CREDENTIALS_FILE;
  }
  const xdg = env.XDG_CONFIG_HOME;
  const base = xdg && xdg.length > 0 ? xdg : join(homedir(), ".config");
  return join(base, "picket", "credentials.json");
}

export function createCredentialsIo(options: CredentialsIoOptions = {}): CredentialsIo {
  const filePath = options.filePath ?? defaultCredentialsPath();

  return {
    filePath,
    async read() {
      try {
        const raw = await readFile(filePath, "utf8");
        const parsed = JSON.parse(raw) as Partial<CredentialsStore>;
        if (parsed && typeof parsed === "object" && parsed.records && typeof parsed.records === "object") {
          return { records: parsed.records as Record<string, CredentialRecord> };
        }
      } catch (error) {
        if (isNodeError(error) && error.code === "ENOENT") return { records: {} };
        throw error;
      }
      return { records: {} };
    },
    async write(store: CredentialsStore) {
      await mkdir(dirname(filePath), { recursive: true, mode: 0o700 });
      await writeFile(filePath, JSON.stringify(store, null, 2), { encoding: "utf8", mode: 0o600 });
      // On some platforms (macOS, Linux with restrictive umask) the mode arg
      // is ANDed with umask. Force 0600 explicitly so a permissive umask
      // can't leak the file world-readable.
      await chmod(filePath, 0o600).catch(() => undefined);
    },
    async delete() {
      try {
        await rm(filePath);
      } catch (error) {
        if (isNodeError(error) && error.code === "ENOENT") return;
        throw error;
      }
    }
  };
}

export function lookupCredential(
  store: CredentialsStore,
  apiUrl: string
): CredentialRecord | undefined {
  const key = normalizeApiUrl(apiUrl);
  return store.records[key];
}

export function upsertCredential(
  store: CredentialsStore,
  record: CredentialRecord
): CredentialsStore {
  const key = normalizeApiUrl(record.api_url);
  return { records: { ...store.records, [key]: { ...record, api_url: key } } };
}

export function removeCredential(store: CredentialsStore, apiUrl: string): CredentialsStore {
  const key = normalizeApiUrl(apiUrl);
  const { [key]: _removed, ...rest } = store.records;
  return { records: rest };
}

export function isExpired(record: CredentialRecord, now: Date = new Date()): boolean {
  const expiresAt = new Date(record.expires_at);
  if (Number.isNaN(expiresAt.getTime())) return false;
  // 30s grace so a clock skew or in-flight request doesn't tip us over.
  return expiresAt.getTime() - now.getTime() < 30_000;
}

export function normalizeApiUrl(url: string): string {
  return url.replace(/\/+$/, "");
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
