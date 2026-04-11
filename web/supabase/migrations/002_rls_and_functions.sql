-- =============================================================================
-- 002_rls_and_functions.sql — Consolidated RLS Policies + All RPC/SQL Functions
-- Merged from: 004_rls_policies, 005_rpc_functions, 006_ai_context_functions,
--   007_advanced_intelligence (with 007_hotfix applied), 008_search_actors,
--   009_hardened_rpcs (functions only), 010_profile_insert_policy
-- Note: Recursive admin policies (profiles_admin_read, profiles_admin_update)
--   from 004 are intentionally excluded per 011_fix_recursive_rls.
-- =============================================================================


-- =============================================================================
-- SECTION 1: ROW LEVEL SECURITY POLICIES
-- =============================================================================

-- ─── Public Data (read-only for everyone) ───────────────────────────────────

-- Detections: public read
ALTER TABLE detections ENABLE ROW LEVEL SECURITY;
CREATE POLICY detections_select ON detections FOR SELECT USING (true);

-- Detection techniques: public read
ALTER TABLE detection_techniques ENABLE ROW LEVEL SECURITY;
CREATE POLICY dt_select ON detection_techniques FOR SELECT USING (true);

-- Technique tactics: public read
ALTER TABLE technique_tactics ENABLE ROW LEVEL SECURITY;
CREATE POLICY tt_select ON technique_tactics FOR SELECT USING (true);

-- Procedure reference: public read
ALTER TABLE procedure_reference ENABLE ROW LEVEL SECURITY;
CREATE POLICY proc_select ON procedure_reference FOR SELECT USING (true);

-- Stories: public read
ALTER TABLE stories ENABLE ROW LEVEL SECURITY;
CREATE POLICY stories_select ON stories FOR SELECT USING (true);

-- ATT&CK tables: public read
ALTER TABLE attack_techniques ENABLE ROW LEVEL SECURITY;
CREATE POLICY attack_tech_select ON attack_techniques FOR SELECT USING (true);

ALTER TABLE attack_actors ENABLE ROW LEVEL SECURITY;
CREATE POLICY actors_select ON attack_actors FOR SELECT USING (true);

ALTER TABLE attack_software ENABLE ROW LEVEL SECURITY;
CREATE POLICY software_select ON attack_software FOR SELECT USING (true);

ALTER TABLE actor_techniques ENABLE ROW LEVEL SECURITY;
CREATE POLICY at_select ON actor_techniques FOR SELECT USING (true);

ALTER TABLE software_techniques ENABLE ROW LEVEL SECURITY;
CREATE POLICY st_select ON software_techniques FOR SELECT USING (true);

-- ─── User Data (per-user isolation) ─────────────────────────────────────────

-- Profiles: own data only (no admin policies — admin uses service client)
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY profiles_select ON profiles FOR SELECT USING (auth.uid() = id);
CREATE POLICY profiles_update ON profiles FOR UPDATE USING (auth.uid() = id);
CREATE POLICY profiles_insert ON profiles FOR INSERT WITH CHECK (auth.uid() = id);

-- Conversations: own data only
ALTER TABLE conversations ENABLE ROW LEVEL SECURITY;
CREATE POLICY convos_select ON conversations FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY convos_insert ON conversations FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY convos_update ON conversations FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY convos_delete ON conversations FOR DELETE USING (auth.uid() = user_id);

-- Messages: own conversations only
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
CREATE POLICY msgs_select ON messages FOR SELECT USING (
  conversation_id IN (SELECT id FROM conversations WHERE user_id = auth.uid())
);
CREATE POLICY msgs_insert ON messages FOR INSERT WITH CHECK (
  conversation_id IN (SELECT id FROM conversations WHERE user_id = auth.uid())
);

-- Threat reports: own + public read
ALTER TABLE threat_reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY reports_own ON threat_reports FOR ALL USING (auth.uid() = user_id);
CREATE POLICY reports_public_read ON threat_reports FOR SELECT USING (is_public = true);

-- Coverage snapshots: own data only
ALTER TABLE coverage_snapshots ENABLE ROW LEVEL SECURITY;
CREATE POLICY snapshots_select ON coverage_snapshots FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY snapshots_insert ON coverage_snapshots FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY snapshots_delete ON coverage_snapshots FOR DELETE USING (auth.uid() = user_id);

-- Sync runs: public read (no user writes — service role only)
ALTER TABLE sync_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY sync_select ON sync_runs FOR SELECT USING (true);


-- =============================================================================
-- SECTION 2: RPC FUNCTIONS — Basic Aggregation Queries
-- (from 005_rpc_functions)
-- =============================================================================

-- Count detections per tactic
CREATE OR REPLACE FUNCTION get_tactic_counts()
RETURNS TABLE(tactic_name TEXT, count BIGINT) AS $$
  SELECT tactic_name, COUNT(*)::BIGINT
  FROM technique_tactics
  GROUP BY tactic_name
  ORDER BY count DESC;
$$ LANGUAGE sql STABLE;

-- Count detections per source type
CREATE OR REPLACE FUNCTION get_source_counts()
RETURNS TABLE(source_type TEXT, count BIGINT) AS $$
  SELECT source_type, COUNT(*)::BIGINT
  FROM detections
  GROUP BY source_type
  ORDER BY count DESC;
$$ LANGUAGE sql STABLE;

-- Count unique covered technique IDs
CREATE OR REPLACE FUNCTION get_covered_technique_count()
RETURNS BIGINT AS $$
  SELECT COUNT(DISTINCT technique_id)::BIGINT FROM detection_techniques;
$$ LANGUAGE sql STABLE;

-- Count techniques per actor
CREATE OR REPLACE FUNCTION get_actor_technique_counts()
RETURNS TABLE(actor_id TEXT, count BIGINT) AS $$
  SELECT actor_id, COUNT(*)::BIGINT
  FROM actor_techniques
  GROUP BY actor_id;
$$ LANGUAGE sql STABLE;

-- Search actors by name OR aliases (from 008_search_actors, supersedes 005 version)
CREATE OR REPLACE FUNCTION search_actors(p_query TEXT)
RETURNS TABLE(actor_id TEXT, name TEXT, aliases JSONB, description TEXT) AS $$
  SELECT aa.actor_id, aa.name, aa.aliases, aa.description
  FROM attack_actors aa
  WHERE aa.name ILIKE '%' || p_query || '%'
     OR EXISTS (
       SELECT 1 FROM jsonb_array_elements_text(aa.aliases) alias
       WHERE alias ILIKE '%' || p_query || '%'
     )
  ORDER BY aa.name;
$$ LANGUAGE sql STABLE;

-- Get coverage for a specific actor (techniques + which are covered)
CREATE OR REPLACE FUNCTION get_actor_coverage(p_actor_id TEXT)
RETURNS TABLE(technique_id TEXT, is_covered BOOLEAN) AS $$
  SELECT
    at.technique_id,
    EXISTS(SELECT 1 FROM detection_techniques dt WHERE dt.technique_id = at.technique_id) as is_covered
  FROM actor_techniques at
  WHERE at.actor_id = p_actor_id;
$$ LANGUAGE sql STABLE;

-- Get detection count by source for a technique
CREATE OR REPLACE FUNCTION get_technique_source_counts(p_technique_id TEXT)
RETURNS TABLE(source_type TEXT, count BIGINT) AS $$
  SELECT d.source_type, COUNT(*)::BIGINT
  FROM detection_techniques dt
  JOIN detections d ON d.id = dt.detection_id
  WHERE dt.technique_id = p_technique_id
  GROUP BY d.source_type
  ORDER BY count DESC;
$$ LANGUAGE sql STABLE;


-- =============================================================================
-- SECTION 3: AI Context Functions — Deep Intelligence Queries for AI Chat
-- (from 006_ai_context_functions)
-- =============================================================================

-- Full technique intelligence: detections by source, detection names, gaps
CREATE OR REPLACE FUNCTION get_technique_intelligence(p_technique_id TEXT)
RETURNS JSON AS $$
  SELECT json_build_object(
    'technique_id', p_technique_id,
    'technique_name', (SELECT name FROM attack_techniques WHERE technique_id = p_technique_id),
    'description', (SELECT LEFT(description, 500) FROM attack_techniques WHERE technique_id = p_technique_id),
    'platforms', (SELECT platforms FROM attack_techniques WHERE technique_id = p_technique_id),
    'total_detections', (SELECT COUNT(*) FROM detection_techniques WHERE technique_id = p_technique_id),
    'by_source', (
      SELECT json_agg(json_build_object('source', source_type, 'count', cnt, 'detections', det_names))
      FROM (
        SELECT d.source_type, COUNT(*) as cnt,
               json_agg(json_build_object('name', d.name, 'severity', d.severity) ORDER BY d.name) FILTER (WHERE d.name IS NOT NULL) as det_names
        FROM detection_techniques dt
        JOIN detections d ON d.id = dt.detection_id
        WHERE dt.technique_id = p_technique_id
        GROUP BY d.source_type
        ORDER BY cnt DESC
      ) sub
    ),
    'sources_with_coverage', (
      SELECT array_agg(DISTINCT d.source_type)
      FROM detection_techniques dt JOIN detections d ON d.id = dt.detection_id
      WHERE dt.technique_id = p_technique_id
    ),
    'sources_without_coverage', (
      SELECT array_agg(s.source_type)
      FROM (VALUES ('sigma'), ('splunk_escu'), ('elastic'), ('kql'), ('sublime'), ('crowdstrike_cql')) AS s(source_type)
      WHERE s.source_type NOT IN (
        SELECT DISTINCT d.source_type
        FROM detection_techniques dt JOIN detections d ON d.id = dt.detection_id
        WHERE dt.technique_id = p_technique_id
      )
    ),
    'actors_using', (
      SELECT json_agg(json_build_object('name', aa.name, 'actor_id', aa.actor_id))
      FROM actor_techniques at2
      JOIN attack_actors aa ON aa.actor_id = at2.actor_id
      WHERE at2.technique_id = p_technique_id
    ),
    'related_techniques', (
      SELECT json_agg(DISTINCT at3.technique_id)
      FROM attack_techniques at3
      WHERE at3.parent_technique_id = SPLIT_PART(p_technique_id, '.', 1)
        AND at3.technique_id != p_technique_id
    )
  );
$$ LANGUAGE sql STABLE;

-- Full actor intelligence: all techniques with coverage status and detection counts
CREATE OR REPLACE FUNCTION get_actor_intelligence(p_actor_name TEXT)
RETURNS JSON AS $$
  WITH actor AS (
    SELECT actor_id, name, aliases, description
    FROM attack_actors
    WHERE name ILIKE '%' || p_actor_name || '%'
    LIMIT 1
  ),
  actor_techs AS (
    SELECT at.technique_id,
           atk.name as technique_name,
           EXISTS(SELECT 1 FROM detection_techniques dt WHERE dt.technique_id = at.technique_id) as is_covered,
           (SELECT COUNT(*) FROM detection_techniques dt WHERE dt.technique_id = at.technique_id) as detection_count,
           (SELECT array_agg(DISTINCT d.source_type) FROM detection_techniques dt JOIN detections d ON d.id = dt.detection_id WHERE dt.technique_id = at.technique_id) as covered_sources
    FROM actor_techniques at
    JOIN actor a ON a.actor_id = at.actor_id
    LEFT JOIN attack_techniques atk ON atk.technique_id = at.technique_id
  )
  SELECT json_build_object(
    'actor_name', (SELECT name FROM actor),
    'aliases', (SELECT aliases FROM actor),
    'description', (SELECT LEFT(description, 500) FROM actor),
    'total_techniques', (SELECT COUNT(*) FROM actor_techs),
    'covered', (SELECT COUNT(*) FILTER (WHERE is_covered) FROM actor_techs),
    'gaps', (SELECT COUNT(*) FILTER (WHERE NOT is_covered) FROM actor_techs),
    'coverage_pct', CASE
      WHEN (SELECT COUNT(*) FROM actor_techs) > 0
      THEN ROUND(((SELECT COUNT(*) FILTER (WHERE is_covered) FROM actor_techs)::NUMERIC / (SELECT COUNT(*) FROM actor_techs)) * 100)
      ELSE 0
    END,
    'covered_techniques', (
      SELECT json_agg(json_build_object(
        'id', technique_id, 'name', technique_name,
        'detection_count', detection_count, 'sources', covered_sources
      ) ORDER BY detection_count DESC)
      FROM actor_techs WHERE is_covered
    ),
    'gap_techniques', (
      SELECT json_agg(json_build_object('id', technique_id, 'name', technique_name) ORDER BY technique_id)
      FROM actor_techs WHERE NOT is_covered
    ),
    'tactic_breakdown', (
      SELECT json_agg(json_build_object('tactic', tactic_name, 'total', total, 'covered', cov))
      FROM (
        SELECT tt.tactic_name, COUNT(DISTINCT at2.technique_id) as total,
               COUNT(DISTINCT at2.technique_id) FILTER (
                 WHERE EXISTS(SELECT 1 FROM detection_techniques dt WHERE dt.technique_id = at2.technique_id)
               ) as cov
        FROM actor_techs at2
        JOIN technique_tactics tt ON tt.technique_id = at2.technique_id
        GROUP BY tt.tactic_name
        ORDER BY total DESC
      ) sub
    )
  );
$$ LANGUAGE sql STABLE;

-- Search detections with full context
CREATE OR REPLACE FUNCTION search_detections_full(p_query TEXT, p_limit INT DEFAULT 15)
RETURNS JSON AS $$
  SELECT json_build_object(
    'query', p_query,
    'total_results', (
      SELECT COUNT(*) FROM detections
      WHERE search_vector @@ to_tsquery('english', regexp_replace(p_query, '\s+', ' & ', 'g'))
    ),
    'results', (
      SELECT json_agg(json_build_object(
        'name', d.name,
        'source_type', d.source_type,
        'severity', d.severity,
        'description', LEFT(d.description, 200),
        'mitre_ids', d.mitre_ids,
        'detection_type', d.detection_type,
        'data_sources', d.data_sources
      ))
      FROM (
        SELECT * FROM detections
        WHERE search_vector @@ to_tsquery('english', regexp_replace(p_query, '\s+', ' & ', 'g'))
        ORDER BY
          CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
          name
        LIMIT p_limit
      ) d
    )
  );
$$ LANGUAGE sql STABLE;

-- Overall coverage summary for AI context
CREATE OR REPLACE FUNCTION get_coverage_summary()
RETURNS JSON AS $$
  SELECT json_build_object(
    'total_detections', (SELECT COUNT(*) FROM detections),
    'total_techniques', (SELECT COUNT(*) FROM attack_techniques),
    'covered_techniques', (SELECT COUNT(DISTINCT technique_id) FROM detection_techniques),
    'total_actors', (SELECT COUNT(*) FROM attack_actors),
    'coverage_pct', ROUND(
      (SELECT COUNT(DISTINCT technique_id) FROM detection_techniques)::NUMERIC /
      NULLIF((SELECT COUNT(*) FROM attack_techniques), 0) * 100
    ),
    'by_source', (
      SELECT json_object_agg(source_type, cnt)
      FROM (SELECT source_type, COUNT(*) as cnt FROM detections GROUP BY source_type ORDER BY cnt DESC) sub
    ),
    'by_tactic', (
      SELECT json_object_agg(tactic_name, cnt)
      FROM (SELECT tactic_name, COUNT(*) as cnt FROM technique_tactics GROUP BY tactic_name ORDER BY cnt DESC) sub
    ),
    'weakest_tactics', (
      SELECT json_agg(tactic_name ORDER BY cnt)
      FROM (SELECT tactic_name, COUNT(*) as cnt FROM technique_tactics GROUP BY tactic_name ORDER BY cnt LIMIT 3) sub
    ),
    'strongest_tactics', (
      SELECT json_agg(tactic_name ORDER BY cnt DESC)
      FROM (SELECT tactic_name, COUNT(*) as cnt FROM technique_tactics GROUP BY tactic_name ORDER BY cnt DESC LIMIT 3) sub
    )
  );
$$ LANGUAGE sql STABLE;


-- =============================================================================
-- SECTION 4: Advanced Intelligence Functions
-- (from 007_advanced_intelligence with 007_hotfix applied)
-- =============================================================================

-- Gap analysis by threat profile (ransomware, apt, initial-access, etc.)
CREATE OR REPLACE FUNCTION get_threat_profile_gaps(p_profile TEXT DEFAULT 'apt')
RETURNS JSON AS $$
  WITH profile_tactics AS (
    SELECT unnest(CASE p_profile
      WHEN 'ransomware' THEN ARRAY['initial-access','execution','persistence','privilege-escalation','defense-evasion','credential-access','lateral-movement','impact']
      WHEN 'apt' THEN ARRAY['reconnaissance','resource-development','initial-access','execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','lateral-movement','collection','command-and-control','exfiltration']
      WHEN 'initial-access' THEN ARRAY['initial-access','reconnaissance','resource-development']
      WHEN 'credential-access' THEN ARRAY['credential-access','lateral-movement','privilege-escalation']
      WHEN 'defense-evasion' THEN ARRAY['defense-evasion','execution','persistence']
      WHEN 'exfiltration' THEN ARRAY['exfiltration','collection','command-and-control']
      ELSE ARRAY['initial-access','execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','lateral-movement','collection','command-and-control','exfiltration','impact']
    END) as tactic
  ),
  tactic_coverage AS (
    SELECT pt.tactic,
           COUNT(DISTINCT tt.technique_id) as total_techniques,
           COUNT(DISTINCT tt.technique_id) FILTER (
             WHERE EXISTS(SELECT 1 FROM detection_techniques dt WHERE dt.technique_id = tt.technique_id)
           ) as covered
    FROM profile_tactics pt
    LEFT JOIN technique_tactics tt ON tt.tactic_name = pt.tactic
    GROUP BY pt.tactic
  ),
  uncovered_techniques AS (
    SELECT tt.tactic_name, tt.technique_id, at.name as technique_name
    FROM technique_tactics tt
    JOIN profile_tactics pt ON pt.tactic = tt.tactic_name
    LEFT JOIN attack_techniques at ON at.technique_id = tt.technique_id
    WHERE NOT EXISTS(SELECT 1 FROM detection_techniques dt WHERE dt.technique_id = tt.technique_id)
    ORDER BY tt.tactic_name, tt.technique_id
  )
  SELECT json_build_object(
    'profile', p_profile,
    'total_techniques', (SELECT SUM(total_techniques) FROM tactic_coverage),
    'covered', (SELECT SUM(covered) FROM tactic_coverage),
    'gaps', (SELECT SUM(total_techniques - covered) FROM tactic_coverage),
    'coverage_pct', CASE WHEN (SELECT SUM(total_techniques) FROM tactic_coverage) > 0
      THEN ROUND((SELECT SUM(covered) FROM tactic_coverage)::NUMERIC / (SELECT SUM(total_techniques) FROM tactic_coverage) * 100)
      ELSE 0 END,
    'by_tactic', (SELECT json_agg(json_build_object('tactic', tactic, 'total', total_techniques, 'covered', covered, 'gaps', total_techniques - covered)) FROM tactic_coverage),
    'top_gaps', (SELECT json_agg(json_build_object('tactic', tactic_name, 'technique_id', technique_id, 'name', technique_name)) FROM (SELECT * FROM uncovered_techniques LIMIT 25) sub)
  );
$$ LANGUAGE sql STABLE;

-- Compare two actors side-by-side with shared gaps (FIXED version from 007_hotfix)
CREATE OR REPLACE FUNCTION compare_actors(p_actor_names TEXT[])
RETURNS JSON AS $$
  WITH actor_data AS (
    SELECT aa.actor_id, aa.name,
           (SELECT json_agg(at.technique_id) FROM actor_techniques at WHERE at.actor_id = aa.actor_id) as all_techs,
           (SELECT COUNT(*) FROM actor_techniques at WHERE at.actor_id = aa.actor_id) as total,
           (SELECT COUNT(*) FROM actor_techniques at WHERE at.actor_id = aa.actor_id
            AND EXISTS(SELECT 1 FROM detection_techniques dt WHERE dt.technique_id = at.technique_id)) as covered
    FROM attack_actors aa
    WHERE aa.name ILIKE ANY(SELECT '%' || unnest(p_actor_names) || '%')
  ),
  all_gap_techs AS (
    SELECT ad.name as actor_name, at.technique_id
    FROM actor_data ad
    JOIN actor_techniques at ON at.actor_id = ad.actor_id
    WHERE NOT EXISTS(SELECT 1 FROM detection_techniques dt WHERE dt.technique_id = at.technique_id)
  )
  SELECT json_build_object(
    'actors', (SELECT json_agg(json_build_object(
      'name', name, 'total_techniques', total, 'covered', covered,
      'gaps', total - covered,
      'coverage_pct', CASE WHEN total > 0 THEN ROUND(covered::NUMERIC / total * 100) ELSE 0 END
    )) FROM actor_data),
    'shared_gaps', (
      SELECT json_agg(row_to_json(sub))
      FROM (
        SELECT DISTINCT t.technique_id, atk.name
        FROM all_gap_techs t
        JOIN attack_techniques atk ON atk.technique_id = t.technique_id
        WHERE t.technique_id IN (
          SELECT technique_id FROM all_gap_techs
          GROUP BY technique_id
          HAVING COUNT(DISTINCT actor_name) = (SELECT COUNT(*) FROM actor_data)
        )
        ORDER BY t.technique_id
      ) sub
    ),
    'unique_gaps', (
      SELECT json_agg(json_build_object('actor', actor_name, 'technique_id', technique_id))
      FROM all_gap_techs t
      WHERE t.technique_id NOT IN (
        SELECT technique_id FROM all_gap_techs
        GROUP BY technique_id
        HAVING COUNT(DISTINCT actor_name) > 1
      )
      LIMIT 20
    )
  );
$$ LANGUAGE sql STABLE;

-- Cross-source comparison for a technique
CREATE OR REPLACE FUNCTION compare_sources_for_technique(p_technique_id TEXT)
RETURNS JSON AS $$
  WITH all_sources AS (
    SELECT unnest(ARRAY['sigma','splunk_escu','elastic','kql','sublime','crowdstrike_cql']) as source_type
  ),
  source_dets AS (
    SELECT d.source_type, COUNT(*) as count,
           json_agg(json_build_object('name', d.name, 'severity', d.severity) ORDER BY d.name) as detections
    FROM detection_techniques dt
    JOIN detections d ON d.id = dt.detection_id
    WHERE dt.technique_id = p_technique_id
    GROUP BY d.source_type
  )
  SELECT json_build_object(
    'technique_id', p_technique_id,
    'technique_name', (SELECT name FROM attack_techniques WHERE technique_id = p_technique_id),
    'sources', (
      SELECT json_agg(json_build_object(
        'source', s.source_type,
        'count', COALESCE(sd.count, 0),
        'has_coverage', sd.count IS NOT NULL,
        'detections', COALESCE(sd.detections, '[]'::json)
      ) ORDER BY COALESCE(sd.count, 0) DESC)
      FROM all_sources s
      LEFT JOIN source_dets sd ON sd.source_type = s.source_type
    ),
    'total_detections', (SELECT COALESCE(SUM(count), 0) FROM source_dets),
    'sources_with_coverage', (SELECT COUNT(*) FROM source_dets),
    'sources_without_coverage', 6 - (SELECT COUNT(*) FROM source_dets)
  );
$$ LANGUAGE sql STABLE;

-- Procedure-level coverage for a technique
CREATE OR REPLACE FUNCTION get_procedure_coverage(p_technique_id TEXT)
RETURNS JSON AS $$
  SELECT json_build_object(
    'technique_id', p_technique_id,
    'technique_name', (SELECT name FROM attack_techniques WHERE technique_id = p_technique_id),
    'total_procedures', (SELECT COUNT(*) FROM procedure_reference WHERE technique_id = p_technique_id),
    'procedures', (
      SELECT json_agg(json_build_object(
        'name', pr.name,
        'category', pr.category,
        'description', LEFT(pr.description, 200),
        'detection_count', pr.detection_count,
        'confidence', pr.confidence,
        'source', pr.source
      ) ORDER BY pr.detection_count DESC)
      FROM procedure_reference pr
      WHERE pr.technique_id = p_technique_id
    ),
    'total_detections', (SELECT COUNT(*) FROM detection_techniques WHERE technique_id = p_technique_id),
    'by_source', (
      SELECT json_agg(json_build_object('source', source_type, 'count', cnt))
      FROM (
        SELECT d.source_type, COUNT(*) as cnt
        FROM detection_techniques dt
        JOIN detections d ON d.id = dt.detection_id
        WHERE dt.technique_id = p_technique_id
        GROUP BY d.source_type ORDER BY cnt DESC
      ) sub
    )
  );
$$ LANGUAGE sql STABLE;

-- Search detections by filter (process name, CVE, data source, etc.)
CREATE OR REPLACE FUNCTION search_detections_by_filter(
  p_filter_type TEXT,  -- 'process_name', 'cve', 'data_source', 'detection_type', 'severity'
  p_filter_value TEXT,
  p_limit INT DEFAULT 15
)
RETURNS JSON AS $$
  SELECT json_build_object(
    'filter', p_filter_type,
    'value', p_filter_value,
    'total', (
      SELECT COUNT(*) FROM detections WHERE
        CASE p_filter_type
          WHEN 'process_name' THEN process_names::TEXT ILIKE '%' || p_filter_value || '%'
          WHEN 'cve' THEN cves::TEXT ILIKE '%' || p_filter_value || '%'
          WHEN 'data_source' THEN data_sources::TEXT ILIKE '%' || p_filter_value || '%'
          WHEN 'detection_type' THEN detection_type ILIKE p_filter_value
          WHEN 'severity' THEN severity ILIKE p_filter_value
          ELSE FALSE
        END
    ),
    'results', (
      SELECT json_agg(json_build_object(
        'name', d.name, 'source_type', d.source_type, 'severity', d.severity,
        'description', LEFT(d.description, 200), 'mitre_ids', d.mitre_ids,
        'detection_type', d.detection_type
      ))
      FROM (
        SELECT * FROM detections WHERE
          CASE p_filter_type
            WHEN 'process_name' THEN process_names::TEXT ILIKE '%' || p_filter_value || '%'
            WHEN 'cve' THEN cves::TEXT ILIKE '%' || p_filter_value || '%'
            WHEN 'data_source' THEN data_sources::TEXT ILIKE '%' || p_filter_value || '%'
            WHEN 'detection_type' THEN detection_type ILIKE p_filter_value
            WHEN 'severity' THEN severity ILIKE p_filter_value
            ELSE FALSE
          END
        ORDER BY name LIMIT p_limit
      ) d
    )
  );
$$ LANGUAGE sql STABLE;


-- =============================================================================
-- SECTION 5: Hardened RPC Functions — Page-level aggregation RPCs
-- (from 009_hardened_rpcs, functions only — indexes are in 001_schema.sql)
-- =============================================================================

-- Dashboard Stats (3 queries merged into 1 RPC)
CREATE OR REPLACE FUNCTION get_dashboard_stats()
RETURNS JSON AS $$
  SELECT json_build_object(
    'detections', (SELECT COUNT(*) FROM detections),
    'techniques', (SELECT COUNT(*) FROM attack_techniques),
    'actors', (SELECT COUNT(*) FROM attack_actors),
    'software', (SELECT COUNT(*) FROM attack_software),
    'covered_techniques', (SELECT COUNT(DISTINCT technique_id) FROM detection_techniques),
    'procedures', (SELECT COUNT(*) FROM procedure_reference),
    'by_source', (
      SELECT json_agg(json_build_object('source', source_type, 'count', cnt) ORDER BY cnt DESC)
      FROM (SELECT source_type, COUNT(*) as cnt FROM detections GROUP BY source_type) sub
    ),
    'last_sync', (
      SELECT json_build_object(
        'started_at', started_at, 'status', status,
        'detections_added', detections_added, 'detections_updated', detections_updated
      )
      FROM sync_runs ORDER BY started_at DESC LIMIT 1
    )
  );
$$ LANGUAGE sql STABLE;

-- Actor Profile Full (5 queries merged into 1 RPC)
CREATE OR REPLACE FUNCTION get_actor_profile_full(p_actor_name TEXT)
RETURNS JSON AS $$
  WITH actor AS (
    SELECT * FROM attack_actors WHERE name ILIKE p_actor_name LIMIT 1
  ),
  techs AS (
    SELECT at.technique_id,
           COALESCE(atk.name, at.technique_id) as technique_name,
           EXISTS(SELECT 1 FROM detection_techniques dt WHERE dt.technique_id = at.technique_id) as is_covered,
           (SELECT COUNT(*) FROM detection_techniques dt WHERE dt.technique_id = at.technique_id) as detection_count
    FROM actor_techniques at
    JOIN actor a ON a.actor_id = at.actor_id
    LEFT JOIN attack_techniques atk ON atk.technique_id = at.technique_id
  )
  SELECT json_build_object(
    'actor', (SELECT row_to_json(a) FROM actor a),
    'total_techniques', (SELECT COUNT(*) FROM techs),
    'covered', (SELECT COUNT(*) FROM techs WHERE is_covered),
    'gaps', (SELECT COUNT(*) FROM techs WHERE NOT is_covered),
    'coverage_pct', CASE
      WHEN (SELECT COUNT(*) FROM techs) > 0
      THEN ROUND((SELECT COUNT(*) FROM techs WHERE is_covered)::NUMERIC / (SELECT COUNT(*) FROM techs) * 100)
      ELSE 0 END,
    'covered_techniques', (
      SELECT json_agg(json_build_object(
        'technique_id', technique_id, 'name', technique_name, 'detection_count', detection_count
      ) ORDER BY technique_id)
      FROM techs WHERE is_covered
    ),
    'gap_techniques', (
      SELECT json_agg(json_build_object(
        'technique_id', technique_id, 'name', technique_name
      ) ORDER BY technique_id)
      FROM techs WHERE NOT is_covered
    )
  );
$$ LANGUAGE sql STABLE;

-- Technique Full (7 queries merged into 1 RPC)
CREATE OR REPLACE FUNCTION get_technique_full(p_technique_id TEXT, p_detection_limit INT DEFAULT 200)
RETURNS JSON AS $$
  SELECT json_build_object(
    'technique', (SELECT row_to_json(t) FROM attack_techniques t WHERE t.technique_id = p_technique_id),
    'total_detections', (SELECT COUNT(*) FROM detection_techniques WHERE technique_id = p_technique_id),
    'by_source', (
      SELECT json_agg(json_build_object('source', source_type, 'count', cnt) ORDER BY cnt DESC)
      FROM (
        SELECT d.source_type, COUNT(*) as cnt
        FROM detection_techniques dt
        JOIN detections d ON d.id = dt.detection_id
        WHERE dt.technique_id = p_technique_id
        GROUP BY d.source_type
      ) sub
    ),
    'detections', (
      SELECT json_agg(json_build_object(
        'id', d.id, 'name', d.name, 'source_type', d.source_type,
        'severity', d.severity, 'description', LEFT(d.description, 200)
      ) ORDER BY d.name)
      FROM (
        SELECT d.* FROM detection_techniques dt
        JOIN detections d ON d.id = dt.detection_id
        WHERE dt.technique_id = p_technique_id
        ORDER BY d.name LIMIT p_detection_limit
      ) d
    ),
    'actors', (
      SELECT json_agg(json_build_object('actor_id', aa.actor_id, 'name', aa.name) ORDER BY aa.name)
      FROM actor_techniques at
      JOIN attack_actors aa ON aa.actor_id = at.actor_id
      WHERE at.technique_id = p_technique_id
    ),
    'total_actors', (SELECT COUNT(*) FROM actor_techniques WHERE technique_id = p_technique_id),
    'procedures', (
      SELECT json_agg(json_build_object(
        'id', pr.id, 'name', pr.name, 'category', pr.category,
        'description', pr.description, 'detection_count', pr.detection_count,
        'confidence', pr.confidence, 'source', pr.source
      ) ORDER BY pr.detection_count DESC)
      FROM procedure_reference pr WHERE pr.technique_id = p_technique_id
    ),
    'total_procedures', (SELECT COUNT(*) FROM procedure_reference WHERE technique_id = p_technique_id)
  );
$$ LANGUAGE sql STABLE;
