import { app } from '@azure/functions';

const INGEST_URL = new URL('/events', requireEnv('INGEST_URL')).toString();
const INGEST_TOKEN = requireEnv('INGEST_TOKEN');
const CLUSTER_NAME = requireEnv('CLUSTER_NAME');
const CLUSTER_REGION = process.env.CLUSTER_REGION ?? '';
const CLOUD_ACCOUNT = process.env.CLOUD_ACCOUNT ?? '';

app.eventHub('forwardAudit', {
  connection: 'EventHubConnection',
  eventHubName: process.env.EVENT_HUB_NAME,
  consumerGroup: process.env.EVENT_HUB_CONSUMER_GROUP ?? '$Default',
  cardinality: 'many',
  handler: async (events, context) => {
    const records = (Array.isArray(events) ? events : [events])
      .flatMap(unwrapAzureDiagnosticEnvelope);

    if (records.length === 0) return;

    const ndjson = records
      .map((r) => JSON.stringify({
        ...r,
        cluster_name: CLUSTER_NAME,
        cluster_region: CLUSTER_REGION,
        cloud_provider: 'azure',
        cloud_account: CLOUD_ACCOUNT,
      }))
      .join('\n');

    const res = await fetch(INGEST_URL, {
      method: 'POST',
      headers: {
        'x-api-key': INGEST_TOKEN,
        'content-type': 'application/x-ndjson',
      },
      body: ndjson,
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`ingest POST failed: ${res.status} ${text}`);
    }

    context.log(`forwarded ${records.length} record(s)`);
  },
});

function unwrapAzureDiagnosticEnvelope(event) {
  if (event && Array.isArray(event.records)) {
    return event.records;
  }
  return [event];
}

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`missing required env: ${name}`);
  return v;
}
