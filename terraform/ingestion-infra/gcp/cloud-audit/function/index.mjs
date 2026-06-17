import functions from '@google-cloud/functions-framework';

const INGEST_URL = new URL('/events', requireEnv('INGEST_URL')).toString();
const INGEST_TOKEN = requireEnv('INGEST_TOKEN');
const CLOUD_ACCOUNT = process.env.CLOUD_ACCOUNT ?? '';

functions.cloudEvent('forwardAudit', async (cloudEvent) => {
  const message = cloudEvent?.data?.message;
  if (!message?.data) return;

  const decoded = Buffer.from(message.data, 'base64').toString('utf8');
  const logEntry = safeJson(decoded);
  const body = JSON.stringify({
    ...logEntry,
    cloud_account: CLOUD_ACCOUNT,
    pubsub_message_id: message.messageId,
    pubsub_publish_time: message.publishTime,
  });

  const res = await fetch(INGEST_URL, {
    method: 'POST',
    headers: {
      'x-api-key': INGEST_TOKEN,
      'content-type': 'application/json',
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
