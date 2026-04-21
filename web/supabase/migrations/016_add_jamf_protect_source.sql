-- Re-create functions from 002_rls_and_functions.sql to include the new
-- 'jamf_protect' source type. The hardcoded source arrays in these functions
-- drive the "sources_without_coverage" gap analysis and the
-- compare_sources_for_technique output — without this, Jamf Protect would
-- never show up as a source, even after its rows are seeded.

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
      FROM (VALUES ('sigma'), ('splunk_escu'), ('elastic'), ('kql'), ('sublime'), ('crowdstrike_cql'), ('jamf_protect')) AS s(source_type)
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


CREATE OR REPLACE FUNCTION compare_sources_for_technique(p_technique_id TEXT)
RETURNS JSON AS $$
  WITH all_sources AS (
    SELECT unnest(ARRAY['sigma','splunk_escu','elastic','kql','sublime','crowdstrike_cql','jamf_protect']) as source_type
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
    'sources_without_coverage', 7 - (SELECT COUNT(*) FROM source_dets)
  );
$$ LANGUAGE sql STABLE;
