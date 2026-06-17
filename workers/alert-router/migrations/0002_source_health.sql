CREATE TABLE IF NOT EXISTS source_health (
  source TEXT NOT NULL,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  last_event_at TEXT,
  last_event_count INTEGER NOT NULL DEFAULT 0,
  total_events INTEGER NOT NULL DEFAULT 0,
  total_batches INTEGER NOT NULL DEFAULT 0,
  total_errors INTEGER NOT NULL DEFAULT 0,
  last_error_at TEXT,
  last_error_message TEXT,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  PRIMARY KEY (source, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_source_health_updated_at ON source_health (updated_at DESC);
