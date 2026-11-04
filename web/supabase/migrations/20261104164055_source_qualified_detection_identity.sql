-- Global catalog identity: retain upstream IDs and qualify by source format.
-- Pause old sync writers before applying; deploy composite-aware readers/writers before resuming.
BEGIN;
LOCK TABLE public.detections, public.detection_techniques IN ACCESS EXCLUSIVE MODE;
ALTER TABLE public.detection_techniques ADD COLUMN source_type TEXT;
UPDATE public.detection_techniques dt SET source_type = d.source_type
FROM public.detections d WHERE d.id = dt.detection_id;
ALTER TABLE public.detection_techniques ALTER COLUMN source_type SET NOT NULL;
ALTER TABLE public.detection_techniques DROP CONSTRAINT detection_techniques_detection_id_fkey;
ALTER TABLE public.detection_techniques DROP CONSTRAINT detection_techniques_pkey;
ALTER TABLE public.detections DROP CONSTRAINT detections_pkey;
ALTER TABLE public.detections ADD CONSTRAINT detections_pkey PRIMARY KEY (source_type, id);
ALTER TABLE public.detection_techniques ADD CONSTRAINT detection_techniques_pkey
  PRIMARY KEY (source_type, detection_id, technique_id);
ALTER TABLE public.detection_techniques ADD CONSTRAINT detection_techniques_detection_fkey
  FOREIGN KEY (source_type, detection_id) REFERENCES public.detections(source_type, id)
  ON DELETE CASCADE ON UPDATE CASCADE;
CREATE INDEX idx_detections_upstream_id ON public.detections(id);
-- RLS does not apply to TRUNCATE. Public readers must not inherit that privilege.
REVOKE TRUNCATE ON public.detections, public.detection_techniques FROM PUBLIC, anon, authenticated;

-- Updating mitre_ids replaces exactly this source's edges in the same transaction.
CREATE FUNCTION public.reconcile_detection_techniques() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = '' AS $$
BEGIN
  IF NEW.mitre_ids IS NULL OR jsonb_typeof(NEW.mitre_ids) <> 'array' THEN
    RAISE EXCEPTION 'mitre_ids must be an array of technique strings';
  END IF;
  IF EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.mitre_ids) item
             WHERE jsonb_typeof(item) <> 'string' OR item #>> '{}' = '') THEN
    RAISE EXCEPTION 'mitre_ids must contain nonempty strings';
  END IF;
  DELETE FROM public.detection_techniques
    WHERE source_type = NEW.source_type AND detection_id = NEW.id;
  INSERT INTO public.detection_techniques(source_type, detection_id, technique_id)
    SELECT NEW.source_type, NEW.id, value FROM jsonb_array_elements_text(NEW.mitre_ids)
    ON CONFLICT DO NOTHING;
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION public.reconcile_detection_techniques() FROM PUBLIC, anon, authenticated;
CREATE TRIGGER reconcile_detection_techniques
AFTER INSERT OR UPDATE OF mitre_ids, source_type, id ON public.detections
FOR EACH ROW EXECUTE FUNCTION public.reconcile_detection_techniques();

CREATE OR REPLACE FUNCTION get_technique_source_counts(p_technique_id TEXT)
RETURNS TABLE(source_type TEXT, count BIGINT) AS $$
  SELECT d.source_type, COUNT(*)::BIGINT
  FROM detection_techniques dt
  JOIN detections d ON d.id = dt.detection_id AND d.source_type = dt.source_type
  WHERE dt.technique_id = p_technique_id
  GROUP BY d.source_type
  ORDER BY count DESC;
$$ LANGUAGE sql STABLE;

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
        JOIN detections d ON d.id = dt.detection_id AND d.source_type = dt.source_type
        WHERE dt.technique_id = p_technique_id
        GROUP BY d.source_type
        ORDER BY cnt DESC
      ) sub
    ),
    'sources_with_coverage', (
      SELECT array_agg(DISTINCT d.source_type)
      FROM detection_techniques dt JOIN detections d ON d.id = dt.detection_id AND d.source_type = dt.source_type
      WHERE dt.technique_id = p_technique_id
    ),
    'sources_without_coverage', (
      SELECT array_agg(s.source_type)
      FROM (VALUES ('sigma'), ('splunk_escu'), ('elastic'), ('kql'), ('sublime'), ('crowdstrike_cql'), ('jamf_protect')) AS s(source_type)
      WHERE s.source_type NOT IN (
        SELECT DISTINCT d.source_type
        FROM detection_techniques dt JOIN detections d ON d.id = dt.detection_id AND d.source_type = dt.source_type
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
           (SELECT array_agg(DISTINCT d.source_type) FROM detection_techniques dt JOIN detections d ON d.id = dt.detection_id AND d.source_type = dt.source_type WHERE dt.technique_id = at.technique_id) as covered_sources
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

CREATE OR REPLACE FUNCTION compare_sources_for_technique(p_technique_id TEXT)
RETURNS JSON AS $$
  WITH all_sources AS (
    SELECT unnest(ARRAY['sigma','splunk_escu','elastic','kql','sublime','crowdstrike_cql','jamf_protect']) as source_type
  ),
  source_dets AS (
    SELECT d.source_type, COUNT(*) as count,
           json_agg(json_build_object('name', d.name, 'severity', d.severity) ORDER BY d.name) as detections
    FROM detection_techniques dt
    JOIN detections d ON d.id = dt.detection_id AND d.source_type = dt.source_type
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
        JOIN detections d ON d.id = dt.detection_id AND d.source_type = dt.source_type
        WHERE dt.technique_id = p_technique_id
        GROUP BY d.source_type ORDER BY cnt DESC
      ) sub
    )
  );
$$ LANGUAGE sql STABLE;

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
        JOIN detections d ON d.id = dt.detection_id AND d.source_type = dt.source_type
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
        JOIN detections d ON d.id = dt.detection_id AND d.source_type = dt.source_type
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

NOTIFY pgrst, 'reload schema';
COMMIT;
