import { gzipSync } from 'node:zlib';
import { describe, expect, it, vi } from 'vitest';

import { createVpcFlowLogsForwarder } from './index.mjs';

function sqsRecord(body, messageId = 'msg-1') {
  return { messageId, body: JSON.stringify(body) };
}

function s3Event(bucket = 'flow-bucket', key = 'AWSLogs/file.log.gz') {
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
    handler: createVpcFlowLogsForwarder({
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

describe('VPC Flow Logs Lambda forwarder', () => {
  it('reads an S3 event inside SQS, gunzips log text, and posts to /events with x-api-key', async () => {
    const text = 'version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status\n' +
      '2 123456789012 eni-1 10.0.1.10 198.51.100.42 44321 443 6 12 840 1716739200 1716739260 ACCEPT OK\n';
    const { fetchFn, handler, sentS3Commands, sentSecretCommands } = forwarderForObject(gzipSync(text));

    const result = await handler({ Records: [sqsRecord(s3Event('logs', 'AWSLogs%2Ffile.log.gz'))] });

    expect(result).toEqual({ batchItemFailures: [] });
    expect(sentS3Commands[0]).toEqual({ type: 'GetObject', input: { Bucket: 'logs', Key: 'AWSLogs/file.log.gz' } });
    expect(sentSecretCommands[0]).toEqual({ type: 'GetSecretValue', input: { SecretId: 'secret-arn' } });
    expect(fetchFn).toHaveBeenCalledWith(
      'https://ingest.example/events',
      expect.objectContaining({
        method: 'POST',
        headers: { 'x-api-key': 'ingest-token', 'content-type': 'text/plain' },
        body: text.trim()
      })
    );
  });

  it('posts plain text log objects without gunzip', async () => {
    const text = '2 123456789012 eni-1 10.0.1.10 198.51.100.42 44321 443 6 12 840 1716739200 1716739260 ACCEPT OK\n';
    const { fetchFn, handler } = forwarderForObject(Buffer.from(text));

    await handler({ Records: [sqsRecord(s3Event('logs', 'AWSLogs/file.log'))] });

    expect(fetchFn).toHaveBeenCalledWith(
      'https://ingest.example/events',
      expect.objectContaining({ body: text.trim() })
    );
  });

  it('skips S3 test events', async () => {
    const { fetchFn, handler, sentS3Commands } = forwarderForObject(Buffer.from(''));

    const result = await handler({ Records: [sqsRecord({ Event: 's3:TestEvent' })] });

    expect(result).toEqual({ batchItemFailures: [] });
    expect(sentS3Commands).toHaveLength(0);
    expect(fetchFn).not.toHaveBeenCalled();
  });
});
