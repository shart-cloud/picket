-- Scheduled SQL detections (Milestone 3). One row per `execution: sql` rule,
-- tracking when it last ran and the outcome. The scheduled-detection worker
-- reads last_run_at to decide which rules are due on each cron tick, and writes
-- the result so `picket detections` / the API can surface per-rule run health.

CREATE TABLE IF NOT EXISTS scheduled_detection_state (
  rule_id TEXT PRIMARY KEY,
  last_run_at TEXT,
  -- 'ok' | 'error' | 'skipped'
  last_status TEXT,
  last_row_count INTEGER,
  last_alert_count INTEGER,
  last_error TEXT,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
