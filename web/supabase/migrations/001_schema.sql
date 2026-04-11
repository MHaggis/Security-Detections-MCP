-- =============================================================================
-- 001_schema.sql — Consolidated Schema
-- All CREATE TABLE, CREATE INDEX, CREATE TRIGGER, CREATE FUNCTION (trigger only)
-- Merged from: 001_core_schema, 002_attack_tables, 003_user_tables, 009 indexes
-- =============================================================================

-- ─── Core Detections Table ──────────────────────────────────────────────────

CREATE TABLE detections (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  query TEXT,
  source_type TEXT NOT NULL,
  mitre_ids JSONB DEFAULT '[]',
  mitre_tactics JSONB DEFAULT '[]',
  severity TEXT,
  author TEXT,
  logsource_category TEXT,
  logsource_product TEXT,
  logsource_service TEXT,
  status TEXT,
  date_created TEXT,
  date_modified TEXT,
  refs JSONB DEFAULT '[]',
  tags JSONB DEFAULT '[]',
  cves JSONB DEFAULT '[]',
  data_sources JSONB DEFAULT '[]',
  process_names JSONB DEFAULT '[]',
  file_paths JSONB DEFAULT '[]',
  registry_paths JSONB DEFAULT '[]',
  platforms JSONB DEFAULT '[]',
  detection_type TEXT,
  asset_type TEXT,
  security_domain TEXT,
  raw_yaml TEXT,
  -- Source-specific fields
  analytic_stories JSONB DEFAULT '[]',
  falsepositives JSONB DEFAULT '[]',
  kql_category TEXT,
  kql_tags JSONB DEFAULT '[]',
  kql_keywords JSONB DEFAULT '[]',
  sublime_attack_types JSONB DEFAULT '[]',
  sublime_detection_methods JSONB DEFAULT '[]',
  sublime_tactics JSONB DEFAULT '[]',
  -- Full-text search
  search_vector TSVECTOR GENERATED ALWAYS AS (
    to_tsvector('english', coalesce(name,'') || ' ' || coalesce(description,'') || ' ' || coalesce(query,''))
  ) STORED,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_detections_search ON detections USING GIN (search_vector);
CREATE INDEX IF NOT EXISTS idx_detections_source ON detections (source_type);
CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections (severity);
CREATE INDEX IF NOT EXISTS idx_detections_mitre ON detections USING GIN (mitre_ids);
CREATE INDEX IF NOT EXISTS idx_detections_type ON detections (detection_type);
CREATE INDEX IF NOT EXISTS idx_detections_asset ON detections (asset_type);
CREATE INDEX IF NOT EXISTS idx_detections_domain ON detections (security_domain);
CREATE INDEX IF NOT EXISTS idx_detections_product ON detections (logsource_product);
CREATE INDEX IF NOT EXISTS idx_detections_category ON detections (logsource_category);
CREATE INDEX IF NOT EXISTS idx_detections_source_severity ON detections(source_type, severity);

-- ─── Junction Tables ────────────────────────────────────────────────────────

CREATE TABLE detection_techniques (
  detection_id TEXT NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
  technique_id TEXT NOT NULL,
  PRIMARY KEY (detection_id, technique_id)
);
CREATE INDEX IF NOT EXISTS idx_dt_technique ON detection_techniques(technique_id);
CREATE INDEX IF NOT EXISTS idx_dt_detection ON detection_techniques(detection_id);

CREATE TABLE technique_tactics (
  technique_id TEXT NOT NULL,
  tactic_name TEXT NOT NULL,
  source TEXT DEFAULT 'detection',
  PRIMARY KEY (technique_id, tactic_name)
);
CREATE INDEX IF NOT EXISTS idx_tt_tactic ON technique_tactics(tactic_name);

-- ─── Procedure Reference ────────────────────────────────────────────────────

CREATE TABLE procedure_reference (
  id TEXT PRIMARY KEY,
  technique_id TEXT NOT NULL,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  source TEXT DEFAULT 'auto',
  indicators JSONB NOT NULL DEFAULT '{}',
  detection_count INTEGER DEFAULT 0,
  confidence REAL DEFAULT 1.0,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_procedure_technique ON procedure_reference(technique_id);

-- ─── Stories (Splunk Analytic Stories) ───────────────────────────────────────

CREATE TABLE stories (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  narrative TEXT,
  author TEXT,
  date TEXT,
  version INTEGER,
  status TEXT,
  refs JSONB DEFAULT '[]',
  category TEXT,
  usecase TEXT,
  detection_names JSONB DEFAULT '[]',
  created_at TIMESTAMPTZ DEFAULT now()
);

-- ─── ATT&CK Techniques ─────────────────────────────────────────────────────

CREATE TABLE attack_techniques (
  technique_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  platforms JSONB DEFAULT '[]',
  data_sources JSONB DEFAULT '[]',
  is_subtechnique BOOLEAN DEFAULT false,
  parent_technique_id TEXT,
  url TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_attack_tech_parent ON attack_techniques(parent_technique_id);
CREATE INDEX IF NOT EXISTS idx_attack_tech_sub ON attack_techniques(is_subtechnique);

-- ─── ATT&CK Actors (Threat Groups) ─────────────────────────────────────────

CREATE TABLE attack_actors (
  actor_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  aliases JSONB DEFAULT '[]',
  description TEXT,
  external_references JSONB DEFAULT '[]',
  created TIMESTAMPTZ,
  modified TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_actor_name ON attack_actors(name);

-- ─── ATT&CK Software (Malware + Tools) ─────────────────────────────────────

CREATE TABLE attack_software (
  software_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  software_type TEXT,
  description TEXT,
  platforms JSONB DEFAULT '[]',
  aliases JSONB DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_software_name ON attack_software(name);
CREATE INDEX IF NOT EXISTS idx_software_type ON attack_software(software_type);

-- ─── Actor-Technique Relationships ──────────────────────────────────────────

CREATE TABLE actor_techniques (
  actor_id TEXT NOT NULL REFERENCES attack_actors(actor_id) ON DELETE CASCADE,
  technique_id TEXT NOT NULL,
  description TEXT,
  PRIMARY KEY (actor_id, technique_id)
);
CREATE INDEX IF NOT EXISTS idx_at_technique ON actor_techniques(technique_id);
CREATE INDEX IF NOT EXISTS idx_at_actor ON actor_techniques(actor_id);

-- ─── Software-Technique Relationships ───────────────────────────────────────

CREATE TABLE software_techniques (
  software_id TEXT NOT NULL REFERENCES attack_software(software_id) ON DELETE CASCADE,
  technique_id TEXT NOT NULL,
  description TEXT,
  PRIMARY KEY (software_id, technique_id)
);
CREATE INDEX IF NOT EXISTS idx_st_technique ON software_techniques(technique_id);
CREATE INDEX IF NOT EXISTS idx_st_software ON software_techniques(software_id);

-- ─── User Profiles (extends Supabase auth.users) ───────────────────────────

CREATE TABLE profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  display_name TEXT,
  avatar_url TEXT,
  tier TEXT DEFAULT 'free' CHECK (tier IN ('free', 'pro', 'admin', 'blocked')),
  role TEXT DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  openrouter_api_key_encrypted TEXT,
  claude_api_key_encrypted TEXT,
  openai_api_key_encrypted TEXT,
  preferred_model TEXT DEFAULT 'auto',
  chat_count_today INTEGER DEFAULT 0,
  chat_count_reset_at TIMESTAMPTZ DEFAULT now(),
  openrouter_usage_usd REAL DEFAULT 0.0,
  openrouter_usage_limit_usd REAL DEFAULT 25.0,
  openrouter_usage_reset_at TIMESTAMPTZ DEFAULT now(),
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_profiles_tier ON profiles(tier);
CREATE INDEX IF NOT EXISTS idx_profiles_role ON profiles(role);

-- Auto-create profile on signup (trigger function)
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, display_name, avatar_url)
  VALUES (
    NEW.id,
    COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'user_name', split_part(NEW.email, '@', 1)),
    COALESCE(NEW.raw_user_meta_data->>'avatar_url', NULL)
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_user();

-- ─── Chat Conversations ────────────────────────────────────────────────────

CREATE TABLE conversations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  title TEXT,
  model_used TEXT,
  message_count INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id, updated_at DESC);

-- ─── Chat Messages ─────────────────────────────────────────────────────────

CREATE TABLE messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
  content TEXT NOT NULL,
  model TEXT,
  tokens_used INTEGER,
  tool_calls JSONB,
  tool_results JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, created_at);

-- ─── Threat Reports ────────────────────────────────────────────────────────

CREATE TABLE threat_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  source_url TEXT,
  extracted_techniques JSONB DEFAULT '[]',
  extracted_actors JSONB DEFAULT '[]',
  extracted_iocs JSONB DEFAULT '[]',
  analysis_result JSONB,
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'analyzing', 'complete', 'failed')),
  is_public BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_reports_user ON threat_reports(user_id);
CREATE INDEX IF NOT EXISTS idx_reports_status ON threat_reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_is_public ON threat_reports(is_public);

-- ─── Coverage Snapshots ────────────────────────────────────────────────────

CREATE TABLE coverage_snapshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  actor_name TEXT,
  technique_ids JSONB NOT NULL DEFAULT '[]',
  coverage_data JSONB NOT NULL DEFAULT '{}',
  navigator_layer JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_snapshots_user ON coverage_snapshots(user_id);

-- ─── Sync Run Tracking ─────────────────────────────────────────────────────

CREATE TABLE sync_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_type TEXT NOT NULL,
  started_at TIMESTAMPTZ DEFAULT now(),
  completed_at TIMESTAMPTZ,
  detections_added INTEGER DEFAULT 0,
  detections_updated INTEGER DEFAULT 0,
  detections_total INTEGER DEFAULT 0,
  status TEXT DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed')),
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_sync_runs_status ON sync_runs(status, started_at DESC);
