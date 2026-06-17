let defaultForwarder;

export const handler = async (event) => {
  if (!defaultForwarder) defaultForwarder = await createDefaultForwarder();
  return defaultForwarder(event);
};

export function createGuardDutyForwarder({
  secretsClient,
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

  return async (event) => {
    const token = await getIngestToken();
    const res = await fetchFn(ingestEvents, {
      method: 'POST',
      headers: {
        'x-api-key': token,
        'content-type': 'application/json',
      },
      body: JSON.stringify(event),
    });

    if (!res.ok) {
      const responseBody = await res.text().catch(() => '');
      throw new Error(`ingest POST failed: ${res.status} ${responseBody}`);
    }

    console.log(JSON.stringify({
      message: 'guardduty finding forwarded',
      id: event?.detail?.id ?? event?.id,
      type: event?.detail?.type,
    }));
  };
}

async function createDefaultForwarder() {
  const { GetSecretValueCommand, SecretsManagerClient } = await import('@aws-sdk/client-secrets-manager');

  return createGuardDutyForwarder({
    secretsClient: new SecretsManagerClient({}),
    getSecretValueCommand: (input) => new GetSecretValueCommand(input),
    ingestUrl: requireEnv('INGEST_URL'),
    ingestTokenSecretArn: requireEnv('INGEST_TOKEN_SECRET_ARN'),
  });
}

function ingestEventsUrl(rawUrl) {
  const url = new URL(rawUrl);
  if (url.pathname.endsWith('/events')) return url.toString();
  url.pathname = `${url.pathname.replace(/\/$/, '')}/events`;
  return url.toString();
}

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`missing required env: ${name}`);
  return v;
}
