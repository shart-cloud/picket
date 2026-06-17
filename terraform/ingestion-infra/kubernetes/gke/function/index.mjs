import functions from '@google-cloud/functions-framework';

const INGEST_URL = new URL('/events', requireEnv('INGEST_URL')).toString();
const INGEST_TOKEN = requireEnv('INGEST_TOKEN');
const CLUSTER_NAME = requireEnv('CLUSTER_NAME');
const CLUSTER_REGION = process.env.CLUSTER_REGION ?? '';
const CLOUD_ACCOUNT = process.env.CLOUD_ACCOUNT ?? '';

functions.cloudEvent('forwardAudit', async (cloudEvent) => {
  const message = cloudEvent?.data?.message;
  if (!message?.data) {
    return;
  }

  const decoded = Buffer.from(message.data, 'base64').toString('utf8');
  const logEntry = safeJson(decoded);

  // Emit a single NDJSON record (object + trailing newline) so the
  // application/x-ndjson content-type is accurate and the body stays
  // batch-compatible if GKE ever forwards multiple records per invocation.
  const body =
    JSON.stringify({
      ...logEntry,
      cluster_name: CLUSTER_NAME,
      cluster_region: CLUSTER_REGION,
      cloud_provider: 'gcp',
      cloud_account: CLOUD_ACCOUNT,
      pubsub_message_id: message.messageId,
      pubsub_publish_time: message.publishTime,
    }) + '\n';

  const res = await fetch(INGEST_URL, {
    method: 'POST',
    headers: {
      'x-api-key': INGEST_TOKEN,
      'content-type': 'application/x-ndjson',
    },
    body,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`ingest POST failed: ${res.status} ${text}`);
  }
});

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
