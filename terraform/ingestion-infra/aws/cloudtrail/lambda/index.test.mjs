import { gzipSync } from 'node:zlib';
import { describe, expect, it, vi } from 'vitest';

import { createCloudTrailForwarder } from './index.mjs';

function sqsRecord(body, messageId = 'msg-1') {
  return { messageId, body: JSON.stringify(body) };
}

function s3Event(bucket = 'cloudtrail-bucket', key = 'AWSLogs/file.json.gz') {
  return {
    Records: [
      {
        eventSource: 'aws:s3',
        s3: {
          bucket: { name: bucket },
          object: { key }
        }
      }
    ]
  };
}

function bodyFromBytes(bytes) {
  return {
    transformToByteArray: async () => bytes
  };
}

function forwarderForObject(bytes, fetchFn = vi.fn().mockResolvedValue(new Response(null, { status: 202 }))) {
  const sentS3Commands = [];
  const sentSecretCommands = [];
  const s3Client = {
    send: async (command) => {
      sentS3Commands.push(command);
      return { Body: bodyFromBytes(bytes) };
    }
  };
  const secretsClient = {
    send: async (command) => {
      sentSecretCommands.push(command);
      return { SecretString: 'ingest-token' };
    }
  };

  return {
    sentS3Commands,
    sentSecretCommands,
    fetchFn,
    handler: createCloudTrailForwarder({
      s3Client,
      secretsClient,
      getObjectCommand: (input) => ({ type: 'GetObject', input }),
      getSecretValueCommand: (input) => ({ type: 'GetSecretValue', input }),
      ingestUrl: 'https://ingest.example',
      ingestTokenSecretArn: 'secret-arn',
      fetchFn
    })
  };
}

describe('CloudTrail Lambda forwarder', () => {
  it('reads an S3 event inside SQS, gunzips CloudTrail Records, and posts to /events with x-api-key', async () => {
    const payload = { Records: [{ eventID: 'one' }, { eventID: 'two' }] };
    const { fetchFn, handler, sentS3Commands, sentSecretCommands } = forwarderForObject(
      gzipSync(JSON.stringify(payload))
    );

    const result = await handler({ Records: [sqsRecord(s3Event('logs', 'AWSLogs%2Ffile.json.gz'))] });

    expect(result).toEqual({ batchItemFailures: [] });
    expect(sentS3Commands[0]).toEqual({ type: 'GetObject', input: { Bucket: 'logs', Key: 'AWSLogs/file.json.gz' } });
    expect(sentSecretCommands[0]).toEqual({ type: 'GetSecretValue', input: { SecretId: 'secret-arn' } });
    expect(fetchFn).toHaveBeenCalledWith(
      'https://ingest.example/events',
      expect.objectContaining({
        method: 'POST',
        headers: { 'x-api-key': 'ingest-token', 'content-type': 'application/json' },
        body: JSON.stringify(payload)
      })
    );
  });

  it('posts a direct single-record CloudTrail object as the record payload', async () => {
    const record = { eventID: 'single', eventName: 'CreateUser' };
    const { fetchFn, handler } = forwarderForObject(Buffer.from(JSON.stringify(record)));

    await handler({ Records: [sqsRecord(s3Event('logs', 'AWSLogs/file.json'))] });

    expect(fetchFn).toHaveBeenCalledWith(
      'https://ingest.example/events',
      expect.objectContaining({ body: JSON.stringify(record) })
    );
  });

  it('skips S3 test events', async () => {
    const { fetchFn, handler, sentS3Commands } = forwarderForObject(Buffer.from('{}'));

    const result = await handler({ Records: [sqsRecord({ Event: 's3:TestEvent' })] });

    expect(result).toEqual({ batchItemFailures: [] });
    expect(sentS3Commands).toHaveLength(0);
    expect(fetchFn).not.toHaveBeenCalled();
  });
});
