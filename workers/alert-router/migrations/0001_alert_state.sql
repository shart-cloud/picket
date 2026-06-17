CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
  source TEXT NOT NULL CHECK (source IN ('aws_cloudtrail', 'okta_system', 'cloudflare_audit', 'kubernetes_audit')),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
  dedupe_key TEXT,
  match_count INTEGER NOT NULL DEFAULT 1 CHECK (match_count > 0),
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  acknowledged_at TEXT,
  acknowledged_by TEXT,
  resolved_at TEXT,
  resolved_by TEXT,
  assignee TEXT,
  event_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_status_updated_at ON alerts (status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity_status ON alerts (severity, status);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_last_seen ON alerts (rule_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_source_last_seen ON alerts (source, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_dedupe_status_last_seen ON alerts (rule_id, dedupe_key, status, last_seen DESC)
  WHERE dedupe_key IS NOT NULL AND status IN ('open', 'acknowledged');

CREATE TABLE IF NOT EXISTS alert_notes (
  id TEXT PRIMARY KEY,
  alert_id TEXT NOT NULL,
  body TEXT NOT NULL CHECK (length(body) > 0),
  author TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (alert_id) REFERENCES alerts (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_alert_notes_alert_created_at ON alert_notes (alert_id, created_at DESC);

CREATE TABLE IF NOT EXISTS alert_timeline (
  id TEXT PRIMARY KEY,
  alert_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('created', 'matched', 'acknowledged', 'resolved', 'reopened', 'assigned', 'note_added', 'delivery_attempted', 'delivery_failed', 'delivery_succeeded')),
  actor TEXT,
  body TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (alert_id) REFERENCES alerts (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_alert_timeline_alert_created_at ON alert_timeline (alert_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_timeline_action_created_at ON alert_timeline (action, created_at DESC);
