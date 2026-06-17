-- Detection-engine heartbeat (Milestone 0.4). Singleton row updated by
-- picket-detection each time it evaluates an event, so `picket status` and the
-- API can report whether the detection engine is live and how many rules it runs.
CREATE TABLE IF NOT EXISTS detection_health (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  last_eval_at TEXT,
  total_events_evaluated INTEGER NOT NULL DEFAULT 0,
  total_alerts_created INTEGER NOT NULL DEFAULT 0,
  stateless_rule_count INTEGER NOT NULL DEFAULT 0,
  stateful_rule_count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT
);
