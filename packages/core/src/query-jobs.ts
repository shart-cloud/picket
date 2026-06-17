// Storage layer for the async query queue. Shared between picket-admin (the
// producer + status reader) and picket-query-runner (the consumer).
//
// Results are stored as JSON in D1. D1 has an effective ~1 MiB row limit so
// we cap result payloads — oversized results fail the job with a clear
// error rather than silently truncating.

export type QueryJobStatus = "pending" | "running" | "succeeded" | "failed";

export interface QueryJobRow {
  id: string;
  idempotency_key: string | null;
  status: QueryJobStatus;
  sql: string;
  warehouse: string;
  requested_by: string | null;
  tenant_id: string | null;
  preset: string | null;
  table_suffix: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  result_json: string | null;
  error_message: string | null;
  bytes_scanned: number | null;
  files_scanned: number | null;
  row_count: number | null;
}

export interface CreateQueryJobInput {
  id: string;
  idempotency_key: string | null;
  sql: string;
  warehouse: string;
  requested_by: string | null;
  tenant_id: string | null;
  preset: string | null;
  table_suffix: string | null;
  now: string;
}

export const MAX_RESULT_JSON_BYTES = 900_000; // ~900KB to leave room for row metadata

/**
 * Inserts a new job, OR returns the existing job that matches
 * `idempotency_key` if one is already in flight. Idempotency window is
 * permanent (lookup happens on every POST); pair with the 14-day cleanup
 * to bound storage growth.
 */
export async function createOrGetQueryJob(
  db: D1Database,
  input: CreateQueryJobInput
): Promise<{ job: QueryJobRow; created: boolean }> {
  if (input.idempotency_key) {
    const existing = await db
      .prepare("SELECT * FROM query_jobs WHERE idempotency_key = ? LIMIT 1")
      .bind(input.idempotency_key)
      .first<QueryJobRow>();
    if (existing) return { job: existing, created: false };
  }

  await db
    .prepare(
      `INSERT INTO query_jobs (
        id, idempotency_key, status, sql, warehouse, requested_by, tenant_id,
        preset, table_suffix, created_at
      ) VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      input.id,
      input.idempotency_key,
      input.sql,
      input.warehouse,
      input.requested_by,
      input.tenant_id,
      input.preset,
      input.table_suffix,
      input.now
    )
    .run();

  const job = await db
    .prepare("SELECT * FROM query_jobs WHERE id = ?")
    .bind(input.id)
    .first<QueryJobRow>();
  if (!job) throw new Error(`Failed to insert query job ${input.id}`);
  return { job, created: true };
}

export async function getQueryJob(db: D1Database, id: string): Promise<QueryJobRow | null> {
  return db
    .prepare("SELECT * FROM query_jobs WHERE id = ?")
    .bind(id)
    .first<QueryJobRow>();
}

export async function markQueryJobRunning(db: D1Database, id: string, now: string): Promise<void> {
  await db
    .prepare("UPDATE query_jobs SET status = 'running', started_at = ? WHERE id = ? AND status = 'pending'")
    .bind(now, id)
    .run();
}

export interface SucceedQueryJobInput {
  id: string;
  now: string;
  result_json: string;
  row_count: number;
  bytes_scanned: number | null;
  files_scanned: number | null;
}

export async function succeedQueryJob(db: D1Database, input: SucceedQueryJobInput): Promise<void> {
  if (input.result_json.length > MAX_RESULT_JSON_BYTES) {
    await failQueryJob(db, {
      id: input.id,
      now: input.now,
      error: `Result exceeds ${MAX_RESULT_JSON_BYTES} byte D1 cap (got ${input.result_json.length}). Add a LIMIT or narrow the query.`
    });
    return;
  }

  await db
    .prepare(
      `UPDATE query_jobs
         SET status = 'succeeded',
             finished_at = ?,
             result_json = ?,
             row_count = ?,
             bytes_scanned = ?,
             files_scanned = ?
       WHERE id = ?`
    )
    .bind(
      input.now,
      input.result_json,
      input.row_count,
      input.bytes_scanned,
      input.files_scanned,
      input.id
    )
    .run();
}

export interface FailQueryJobInput {
  id: string;
  now: string;
  error: string;
}

export async function failQueryJob(db: D1Database, input: FailQueryJobInput): Promise<void> {
  await db
    .prepare(
      `UPDATE query_jobs
         SET status = 'failed',
             finished_at = ?,
             error_message = ?
       WHERE id = ?`
    )
    .bind(input.now, input.error, input.id)
    .run();
}

/** Returns the number of rows pruned. */
export async function pruneQueryJobs(
  db: D1Database,
  olderThan: string
): Promise<number> {
  const result = await db
    .prepare("DELETE FROM query_jobs WHERE created_at < ?")
    .bind(olderThan)
    .run();
  return result.meta?.changes ?? 0;
}
