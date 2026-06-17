-- Async query jobs. POST /api/v1/query enqueues a row here and pushes the id
-- onto the picket-query-jobs queue; the picket-query-runner Worker consumes,
-- executes against R2 SQL, and updates the row in place. Clients poll via
-- GET /api/v1/query/<id>. Rows older than 14 days are pruned by the scheduled
-- task on the runner.

CREATE TABLE IF NOT EXISTS query_jobs (
  id TEXT PRIMARY KEY,
  idempotency_key TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
  sql TEXT NOT NULL,
  warehouse TEXT NOT NULL,
  requested_by TEXT,
  tenant_id TEXT,
  preset TEXT,
  table_suffix TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  -- Result is the {columns, rows} JSON. D1 row limit is ~1MB; oversized
  -- results write `null` here and set error to the size cap message.
  result_json TEXT,
  error_message TEXT,
  bytes_scanned INTEGER,
  files_scanned INTEGER,
  row_count INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS query_jobs_idempotency_key_idx
  ON query_jobs (idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS query_jobs_status_idx ON query_jobs (status);
CREATE INDEX IF NOT EXISTS query_jobs_created_at_idx ON query_jobs (created_at);
