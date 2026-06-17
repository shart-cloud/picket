import {
  failQueryJob,
  getQueryJob,
  markQueryJobRunning,
  pruneQueryJobs,
  succeedQueryJob,
  type QueryJobRow
} from "@picket/core/query-jobs";
import { createR2SqlHttpExecutor, type R2SqlExecutor } from "@picket/query";

export interface QueryRunnerEnv {
  ALERT_STATE_DB: D1Database;
  R2_SQL_TOKEN: string;
}

interface QueryJobMessage {
  job_id: string;
}

// 14 days. Matches the retention budget — pair with the scheduled trigger.
const PRUNE_AGE_DAYS = 14;

export interface RunnerHooks {
  /** Inject a fake R2 SQL executor in tests. */
  executorFactory?: (warehouse: string, token: string) => R2SqlExecutor;
  /** Inject deterministic time in tests. */
  now?: () => Date;
}

export function createRunner(hooks: RunnerHooks = {}) {
  const now = hooks.now ?? (() => new Date());
  const buildExecutor =
    hooks.executorFactory ??
    ((warehouse: string, token: string) => createR2SqlHttpExecutor({ warehouse, token }));

  async function processOne(env: QueryRunnerEnv, jobId: string): Promise<void> {
    const job = await getQueryJob(env.ALERT_STATE_DB, jobId);
    if (!job) {
      console.warn(JSON.stringify({ worker: "picket-query-runner", message: "job not found", job_id: jobId }));
      return;
    }
    if (job.status !== "pending") {
      // Already picked up (could be a redelivery). Idempotent: just skip.
      console.log(JSON.stringify({ worker: "picket-query-runner", message: "job already started", job_id: jobId, status: job.status }));
      return;
    }

    await markQueryJobRunning(env.ALERT_STATE_DB, jobId, now().toISOString());

    if (!env.R2_SQL_TOKEN) {
      await failQueryJob(env.ALERT_STATE_DB, {
        id: jobId,
        now: now().toISOString(),
        error: "R2_SQL_TOKEN binding missing on picket-query-runner"
      });
      return;
    }

    try {
      const executor = buildExecutor(job.warehouse, env.R2_SQL_TOKEN);
      const result = await executor.execute(job.sql);
      const resultJson = JSON.stringify(result);
      // bytes_scanned / files_scanned aren't on R2SqlResult yet; the
      // executor would need to surface them from the API response. Pass
      // null for now; populating them is a TODO once the executor changes.
      await succeedQueryJob(env.ALERT_STATE_DB, {
        id: jobId,
        now: now().toISOString(),
        result_json: resultJson,
        row_count: result.rows.length,
        bytes_scanned: null,
        files_scanned: null
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      await failQueryJob(env.ALERT_STATE_DB, {
        id: jobId,
        now: now().toISOString(),
        error: msg
      });
    }
  }

  return {
    async queue(batch: MessageBatch<QueryJobMessage>, env: QueryRunnerEnv): Promise<void> {
      for (const message of batch.messages) {
        try {
          await processOne(env, message.body.job_id);
          message.ack();
        } catch (error) {
          console.error(
            JSON.stringify({
              worker: "picket-query-runner",
              message: "unhandled runner error",
              job_id: message.body.job_id,
              error: error instanceof Error ? error.message : String(error)
            })
          );
          // Don't retry — the job row is already in a terminal failed state
          // if processOne caught the error, and an uncaught error here means
          // something deeper is broken that retries won't fix.
          message.ack();
        }
      }
    },

    async scheduled(_event: ScheduledController, env: QueryRunnerEnv): Promise<void> {
      const cutoff = new Date(now().getTime() - PRUNE_AGE_DAYS * 86_400_000).toISOString();
      const pruned = await pruneQueryJobs(env.ALERT_STATE_DB, cutoff);
      console.log(JSON.stringify({
        worker: "picket-query-runner",
        message: "pruned query_jobs",
        pruned,
        older_than: cutoff
      }));
    },

    // Re-exported for tests.
    processOne
  };
}

const runner = createRunner();

export default {
  queue: runner.queue,
  scheduled: runner.scheduled
} satisfies ExportedHandler<QueryRunnerEnv, QueryJobMessage>;

// Used by index.test.ts to drive runs deterministically.
export type { QueryJobRow };
