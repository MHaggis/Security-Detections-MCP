-- Migration: Add Job Queue and Feed Management Tables
-- Purpose: Enable autonomous detection engineering workflows
-- Apply to: dedicated AUTOMATION_DB_PATH SQLite database (never the MCP cache)

-- ═══════════════════════════════════════════════════════════════════════════
-- JOBS TABLE - Core job queue management
-- ═══════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  job_type TEXT NOT NULL,  -- threat_analysis, detection_creation, validation, pr_creation, etc.
  status TEXT DEFAULT 'pending',  -- pending, running, completed, failed, cancelled
  priority INTEGER DEFAULT 5,  -- 1 (highest) to 10 (lowest)
  payload TEXT,  -- JSON: input data for the job
  result TEXT,   -- JSON: output from job execution
  error TEXT,    -- Error message if job failed
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  started_at TEXT,
  completed_at TEXT,
  retry_count INTEGER DEFAULT 0,
  max_retries INTEGER DEFAULT 3,
  parent_job_id TEXT,  -- For job chaining and dependencies
  workflow_id TEXT,    -- Group related jobs
  FOREIGN KEY (parent_job_id) REFERENCES jobs(id)
);

CREATE INDEX IF NOT EXISTS idx_jobs_status_priority ON jobs(status, priority DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_type ON jobs(job_type);
CREATE INDEX IF NOT EXISTS idx_jobs_workflow ON jobs(workflow_id);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at);

-- ═══════════════════════════════════════════════════════════════════════════
-- JOB SCHEDULE TABLE - Cron-based scheduled jobs
-- ═══════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS job_schedule (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  cron_expression TEXT NOT NULL,  -- e.g., "0 */6 * * *" (every 6 hours)
  job_type TEXT NOT NULL,
  payload TEXT,  -- JSON: default payload for scheduled jobs
  enabled INTEGER DEFAULT 1,
  last_run TEXT,
  next_run TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_schedule_enabled ON job_schedule(enabled, next_run);

-- ═══════════════════════════════════════════════════════════════════════════
-- FEED ITEMS TABLE - Threat intelligence feed ingestion
-- ═══════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS feed_items (
  id TEXT PRIMARY KEY,
  feed_source TEXT NOT NULL,  -- cisa_alerts, cisa_kev, mitre_attack, vendor_blog, etc.
  title TEXT NOT NULL,
  content TEXT,
  url TEXT,
  published_at TEXT,
  ingested_at TEXT DEFAULT CURRENT_TIMESTAMP,
  status TEXT DEFAULT 'pending',  -- pending, processing, completed, failed, skipped
  job_id TEXT,  -- Reference to the job that processes this feed item
  metadata TEXT,  -- JSON: extracted IOCs, techniques, confidence scores
  FOREIGN KEY (job_id) REFERENCES jobs(id)
);

CREATE INDEX IF NOT EXISTS idx_feed_items_status ON feed_items(status);
CREATE INDEX IF NOT EXISTS idx_feed_items_source ON feed_items(feed_source);
CREATE INDEX IF NOT EXISTS idx_feed_items_published ON feed_items(published_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════
-- CAMPAIGN OBSERVATIONS TABLE - Temporal threat campaign tracking
-- ═══════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS campaign_observations (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,  -- References kg_entities
  observed_at TEXT NOT NULL,
  observation_type TEXT NOT NULL,  -- 'technique', 'tool', 'infrastructure', 'target', 'tactic'
  content TEXT NOT NULL,           -- JSON: the actual observation details
  source TEXT NOT NULL,            -- threat intel source URL/reference
  confidence REAL,                 -- 0.0 to 1.0 confidence score
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY (campaign_id) REFERENCES kg_entities(id)
);

CREATE INDEX IF NOT EXISTS idx_campaign_obs_campaign ON campaign_observations(campaign_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_campaign_obs_type ON campaign_observations(observation_type);

-- ═══════════════════════════════════════════════════════════════════════════
-- CAMPAIGN COVERAGE TABLE - Track coverage evolution over time
-- ═══════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS campaign_coverage (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  assessed_at TEXT NOT NULL,
  techniques_observed INTEGER,
  techniques_covered INTEGER,
  coverage_percentage REAL,
  gap_details TEXT,  -- JSON: specific techniques and gaps
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY (campaign_id) REFERENCES kg_entities(id)
);

CREATE INDEX IF NOT EXISTS idx_campaign_coverage_campaign ON campaign_coverage(campaign_id, assessed_at);

-- ═══════════════════════════════════════════════════════════════════════════
-- VALIDATION RESULTS TABLE - Track atomic test validation outcomes
-- ═══════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS validation_results (
  id TEXT PRIMARY KEY,
  detection_id TEXT NOT NULL,
  detection_path TEXT NOT NULL,
  technique_id TEXT NOT NULL,
  atomic_test_id TEXT,
  validation_date TEXT DEFAULT CURRENT_TIMESTAMP,
  status TEXT NOT NULL,  -- passed, failed, skipped
  event_count INTEGER,
  execution_time_seconds INTEGER,
  attack_data_path TEXT,  -- Path to dumped attack data
  notes TEXT,
  
  FOREIGN KEY (detection_id) REFERENCES detections(id)
);

CREATE INDEX IF NOT EXISTS idx_validation_detection ON validation_results(detection_id);
CREATE INDEX IF NOT EXISTS idx_validation_technique ON validation_results(technique_id);
CREATE INDEX IF NOT EXISTS idx_validation_date ON validation_results(validation_date DESC);
