import { gunzipSync } from 'node:zlib';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

const INGEST_URL = new URL('/events', requireEnv('INGEST_URL')).toString();
const INGEST_TOKEN_SECRET_ARN = requireEnv('INGEST_TOKEN_SECRET_ARN');
const CLUSTER_NAME = requireEnv('CLUSTER_NAME');
const CLUSTER_REGION = process.env.CLUSTER_REGION ?? '';
const CLOUD_ACCOUNT = process.env.CLOUD_ACCOUNT ?? '';
const STREAM_PREFIXES = (process.env.FORWARDED_STREAM_PREFIXES ?? 'kube-apiserver-audit-')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const secretsClient = new SecretsManagerClient({});
let cachedToken;

async function getIngestToken() {
  if (cachedToken) return cachedToken;
  const res = await secretsClient.send(
    new GetSecretValueCommand({ SecretId: INGEST_TOKEN_SECRET_ARN }),
  );
  cachedToken = res.SecretString;
  if (!cachedToken) throw new Error('ingest token secret is empty');
  return cachedToken;
}

export const handler = async (event) => {
  const payload = JSON.parse(
    gunzipSync(Buffer.from(event.awslogs.data, 'base64')).toString('utf8'),
  );

  if (payload.messageType !== 'DATA_MESSAGE') {
    return { ok: true, skipped: payload.messageType };
  }

  const stream = payload.logStream ?? '';
  if (!STREAM_PREFIXES.some((p) => stream.startsWith(p))) {
    return { ok: true, skipped_stream: stream };
  }

  const ndjson = payload.logEvents
    .map((e) => JSON.stringify({
      ...safeJson(e.message),
      cluster_name: CLUSTER_NAME,
      cluster_region: CLUSTER_REGION,
      cloud_provider: 'aws',
      cloud_account: CLOUD_ACCOUNT,
      log_stream: stream,
      cloudwatch_event_id: e.id,
      cloudwatch_timestamp: e.timestamp,
    }))
    .join('\n');

  const token = await getIngestToken();

  const res = await fetch(INGEST_URL, {
    method: 'POST',
    headers: {
      'x-api-key': token,
      'content-type': 'application/x-ndjson',
    },
    body: ndjson,
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`ingest POST failed: ${res.status} ${body}`);
  }

  return { ok: true, count: payload.logEvents.length };
};

function safeJson(s) {
  try {
    return JSON.parse(s);
  } catch {
    return { _raw: s };
  }
}

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`missing required env: ${name}`);
  return v;
}
