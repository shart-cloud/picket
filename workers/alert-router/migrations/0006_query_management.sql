-- Query management (Milestone 1). Two tables backing the analyst query surface:
--   saved_queries  — named, reusable queries an analyst stores (upsert by owner+name)
--   query_history  — an append-only log of submitted queries (best-effort, written
--                    from the POST /api/v1/query submit path; never blocks a request)
-- Both live in the shared picket-alert-state D1 DB alongside query_jobs (0003).

CREATE TABLE IF NOT EXISTS saved_queries (
  id TEXT PRIMARY KEY,
  owner TEXT,
  name TEXT NOT NULL,
  description TEXT,
  sql TEXT NOT NULL,
  preset TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Saving with an existing (owner, name) overwrites it (see saveQuery upsert).
-- NULL owners are distinct under SQLite UNIQUE semantics; that's acceptable for
-- the MVP (anonymous saves don't collide).
CREATE UNIQUE INDEX IF NOT EXISTS idx_saved_queries_owner_name ON saved_queries (owner, name);
CREATE INDEX IF NOT EXISTS idx_saved_queries_owner_updated_at ON saved_queries (owner, updated_at DESC);

CREATE TABLE IF NOT EXISTS query_history (
  id TEXT PRIMARY KEY,
  owner TEXT,
  sql TEXT NOT NULL,
  preset TEXT,
  job_id TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_query_history_created_at ON query_history (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_query_history_owner_created_at ON query_history (owner, created_at DESC);
