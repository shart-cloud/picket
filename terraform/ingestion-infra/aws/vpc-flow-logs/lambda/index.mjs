import { gunzipSync } from 'node:zlib';

let defaultForwarder;

export const handler = async (event) => {
  if (!defaultForwarder) defaultForwarder = await createDefaultForwarder();
  return defaultForwarder(event);
};

export function createVpcFlowLogsForwarder({
  s3Client,
  secretsClient,
  getObjectCommand,
  getSecretValueCommand,
  ingestUrl,
  ingestTokenSecretArn,
  fetchFn = fetch,
}) {
  const ingestEvents = ingestEventsUrl(ingestUrl);
  let cachedToken;

  async function getIngestToken() {
    if (cachedToken) return cachedToken;
    const res = await secretsClient.send(getSecretValueCommand({ SecretId: ingestTokenSecretArn }));
    cachedToken = res.SecretString;
    if (!cachedToken) throw new Error('ingest token secret is empty');
    return cachedToken;
  }

  async function flowLogTextFromS3Event(event) {
    const bucket = event.s3.bucket.name;
    const key = decodeS3ObjectKey(event.s3.object.key);
    const object = await s3Client.send(getObjectCommand({ Bucket: bucket, Key: key }));
    const bytes = Buffer.from(await object.Body.transformToByteArray());
    const text = isGzip(bytes, key) ? gunzipSync(bytes).toString('utf8') : bytes.toString('utf8');
    const body = compactFlowLogLines(text).join('\n');

    console.log(JSON.stringify({
      message: 'vpc flow log object parsed',
      bucket,
      key,
      line_count: body.length === 0 ? 0 : body.split('\n').length,
    }));

    return body;
  }

  async function postFlowLogText(body) {
    if (body.length === 0) return;
    const token = await getIngestToken();
    const res = await fetchFn(ingestEvents, {
      method: 'POST',
      headers: {
        'x-api-key': token,
        'content-type': 'text/plain',
      },
      body,
    });

    if (!res.ok) {
      const responseBody = await res.text().catch(() => '');
      throw new Error(`ingest POST failed: ${res.status} ${responseBody}`);
    }
  }

  return async (event) => {
    const batchItemFailures = [];
    let processedMessages = 0;
    let processedObjects = 0;
    let forwardedLines = 0;

    for (const record of event.Records ?? []) {
      try {
        const s3Events = s3EventsFromSqsRecord(record);
        for (const s3Event of s3Events) {
          const body = await flowLogTextFromS3Event(s3Event);
          if (body.length === 0) continue;
          await postFlowLogText(body);
          processedObjects += 1;
          forwardedLines += body.split('\n').length;
        }
        processedMessages += 1;
      } catch (error) {
        batchItemFailures.push({ itemIdentifier: record.messageId });
        console.error(JSON.stringify({
          message: 'vpc flow log forward failed',
          sqs_message_id: record.messageId,
          error: errorMessage(error),
        }));
      }
    }

    console.log(JSON.stringify({
      message: 'vpc flow log forward summary',
      processed_messages: processedMessages,
      failed_messages: batchItemFailures.length,
      processed_objects: processedObjects,
      forwarded_lines: forwardedLines,
    }));

    return { batchItemFailures };
  };
}

async function createDefaultForwarder() {
  const [{ GetObjectCommand, S3Client }, { GetSecretValueCommand, SecretsManagerClient }] = await Promise.all([
    import('@aws-sdk/client-s3'),
    import('@aws-sdk/client-secrets-manager'),
  ]);

  return createVpcFlowLogsForwarder({
    s3Client: new S3Client({}),
    secretsClient: new SecretsManagerClient({}),
    getObjectCommand: (input) => new GetObjectCommand(input),
    getSecretValueCommand: (input) => new GetSecretValueCommand(input),
    ingestUrl: requireEnv('INGEST_URL'),
    ingestTokenSecretArn: requireEnv('INGEST_TOKEN_SECRET_ARN'),
  });
}

function compactFlowLogLines(text) {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function s3EventsFromSqsRecord(record) {
  const body = JSON.parse(record.body);
  if (body.Event === 's3:TestEvent') return [];
  if (!Array.isArray(body.Records)) return [];
  return body.Records.filter((r) => r?.s3?.bucket?.name && r?.s3?.object?.key);
}

function decodeS3ObjectKey(key) {
  return decodeURIComponent(key.replace(/\+/g, ' '));
}

function ingestEventsUrl(rawUrl) {
  const url = new URL(rawUrl);
  if (url.pathname.endsWith('/events')) return url.toString();
  url.pathname = `${url.pathname.replace(/\/$/, '')}/events`;
  return url.toString();
}

function isGzip(bytes, key) {
  return key.endsWith('.gz') || (bytes[0] === 0x1f && bytes[1] === 0x8b);
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`missing required env: ${name}`);
  return v;
}
