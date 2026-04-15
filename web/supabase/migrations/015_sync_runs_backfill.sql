-- Backfill one bootstrap sync run so dashboard has immediate status
-- Idempotent: only inserts if sync_runs currently has zero rows
INSERT INTO sync_runs (
  source_type,
  started_at,
  completed_at,
  detections_added,
  detections_updated,
  detections_total,
  status,
  error
)
SELECT
  'bootstrap',
  now(),
  now(),
  0,
  0,
  (SELECT COUNT(*) FROM detections),
  'completed',
  NULL
WHERE NOT EXISTS (SELECT 1 FROM sync_runs);
