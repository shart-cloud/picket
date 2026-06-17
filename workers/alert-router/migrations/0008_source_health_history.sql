CREATE TABLE IF NOT EXISTS source_health_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  kind TEXT NOT NULL CHECK (kind IN ('batch', 'error')),
  event_count INTEGER NOT NULL DEFAULT 0,
  last_event_at TEXT,
  error_message TEXT,
  recorded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_source_health_history_source_time
  ON source_health_history (source, tenant_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_source_health_history_errors
  ON source_health_history (source, tenant_id, kind, recorded_at DESC);

-- Keep the timeline useful without allowing a noisy source to grow D1 forever.
CREATE TRIGGER IF NOT EXISTS source_health_history_cap
AFTER INSERT ON source_health_history
BEGIN
  DELETE FROM source_health_history
  WHERE source = NEW.source
    AND tenant_id = NEW.tenant_id
    AND id NOT IN (
      SELECT id
      FROM source_health_history
      WHERE source = NEW.source AND tenant_id = NEW.tenant_id
      ORDER BY recorded_at DESC, id DESC
      LIMIT 500
    );
END;
