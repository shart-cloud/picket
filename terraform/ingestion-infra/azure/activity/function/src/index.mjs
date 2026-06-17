import { app } from '@azure/functions';

const INGEST_URL = new URL('/events', requireEnv('INGEST_URL')).toString();
const INGEST_TOKEN = requireEnv('INGEST_TOKEN');

app.eventHub('forwardActivity', {
  connection: 'EventHubConnection',
  eventHubName: process.env.EVENT_HUB_NAME,
  consumerGroup: process.env.EVENT_HUB_CONSUMER_GROUP ?? '$Default',
  cardinality: 'many',
  handler: async (events, context) => {
    const records = (Array.isArray(events) ? events : [events])
      .flatMap(unwrapAzureDiagnosticEnvelope)
      .filter(Boolean);

    if (records.length === 0) return;

    const body = JSON.stringify({ records });
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

    context.log(`forwarded ${records.length} Azure Activity record(s)`);
  },
});

function unwrapAzureDiagnosticEnvelope(event) {
  if (event && Array.isArray(event.records)) return event.records;
  if (event && Array.isArray(event.Records)) return event.Records;
  return [event];
}

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`missing required env: ${name}`);
  return v;
}
