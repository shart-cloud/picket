-- Detection rule registry (Milestone 1). Rules are embedded in the detection
-- worker bundle at build time; this table mirrors them in D1 so the API/CLI can
-- list rules, show detail, toggle enable/disable at runtime, and track per-rule
-- match stats. The detection worker seeds static metadata (idempotently) and
-- updates match_count / last_triggered_at; operators own the `enabled` override.
CREATE TABLE IF NOT EXISTS detection_rules (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT,
  severity TEXT NOT NULL,
  source TEXT NOT NULL,
  class_name TEXT,
  execution TEXT NOT NULL,
  tags_json TEXT NOT NULL DEFAULT '[]',
  enabled INTEGER NOT NULL DEFAULT 1,
  definition_json TEXT NOT NULL,
  match_count INTEGER NOT NULL DEFAULT 0,
  last_triggered_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_detection_rules_enabled ON detection_rules (enabled);
CREATE INDEX IF NOT EXISTS idx_detection_rules_source ON detection_rules (source);
