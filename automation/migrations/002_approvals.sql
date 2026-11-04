-- A request reviews one persisted result; approval never replays live side effects.
CREATE TABLE IF NOT EXISTS approval_requests (
  id TEXT PRIMARY KEY,
  workflow_id TEXT NOT NULL,
  job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id),
  checkpoint_type TEXT NOT NULL DEFAULT 'pipeline_review',
  status TEXT NOT NULL DEFAULT 'pending',
  data TEXT NOT NULL,
  requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at TEXT,
  resolved_by TEXT,
  reason TEXT,
  timeout_hours INTEGER NOT NULL DEFAULT 24
);
CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_requests(status, requested_at);
