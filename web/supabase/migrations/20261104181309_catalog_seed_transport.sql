-- Lossless bounded transport for catalog rule text through the hosted Data API.
BEGIN;
CREATE FUNCTION public.seed_catalog_batch(p_table text, p_payload text)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path = '' AS $$
DECLARE
  allowed_columns text[];
  conflict_columns text[];
  input_columns text[];
  row_columns text[];
  decoded bytea;
  payload jsonb;
  item jsonb;
  key text;
  insert_columns text;
  conflict_sql text;
  update_sql text;
  row_total integer;
BEGIN
  CASE p_table
    WHEN 'detections' THEN allowed_columns := ARRAY['id','name','description','query','source_type','mitre_ids','mitre_tactics','severity','author','logsource_category','logsource_product','logsource_service','status','date_created','date_modified','refs','tags','cves','data_sources','process_names','file_paths','registry_paths','platforms','detection_type','asset_type','security_domain','raw_yaml','analytic_stories','falsepositives','kql_category','kql_tags','kql_keywords','sublime_attack_types','sublime_detection_methods','sublime_tactics']; conflict_columns := ARRAY['source_type','id'];
    WHEN 'technique_tactics' THEN allowed_columns := ARRAY['technique_id','tactic_name','source']; conflict_columns := ARRAY['technique_id','tactic_name'];
    WHEN 'attack_techniques' THEN allowed_columns := ARRAY['technique_id','name','description','platforms','data_sources','is_subtechnique','parent_technique_id','url']; conflict_columns := ARRAY['technique_id'];
    WHEN 'attack_actors' THEN allowed_columns := ARRAY['actor_id','name','aliases','description','external_references','created','modified']; conflict_columns := ARRAY['actor_id'];
    WHEN 'attack_software' THEN allowed_columns := ARRAY['software_id','name','software_type','description','platforms','aliases']; conflict_columns := ARRAY['software_id'];
    WHEN 'actor_techniques' THEN allowed_columns := ARRAY['actor_id','technique_id','description']; conflict_columns := ARRAY['actor_id','technique_id'];
    WHEN 'software_techniques' THEN allowed_columns := ARRAY['software_id','technique_id','description']; conflict_columns := ARRAY['software_id','technique_id'];
    WHEN 'procedure_reference' THEN allowed_columns := ARRAY['id','technique_id','name','category','description','source','indicators','detection_count','confidence']; conflict_columns := ARRAY['id'];
    WHEN 'stories' THEN allowed_columns := ARRAY['id','name','description','narrative','author','date','version','status','refs','category','usecase','detection_names']; conflict_columns := ARRAY['id'];
    ELSE RAISE EXCEPTION 'Unsupported catalog table' USING ERRCODE = '22023';
  END CASE;
  IF p_payload IS NULL OR octet_length(p_payload) > 2796204 THEN
    RAISE EXCEPTION 'Encoded catalog payload exceeds limit' USING ERRCODE = '22023';
  END IF;
  decoded := decode(p_payload, 'base64');
  IF octet_length(decoded) > 2097152 OR replace(encode(decoded, 'base64'), E'\n', '') <> p_payload THEN
    RAISE EXCEPTION 'Invalid or oversized catalog encoding' USING ERRCODE = '22023';
  END IF;
  payload := convert_from(decoded, 'UTF8')::jsonb;
  IF jsonb_typeof(payload) <> 'array' THEN
    RAISE EXCEPTION 'Catalog payload must be an array' USING ERRCODE = '22023';
  END IF;
  row_total := jsonb_array_length(payload);
  IF row_total < 1 OR row_total > 100 THEN
    RAISE EXCEPTION 'Catalog batch requires 1..100 rows' USING ERRCODE = '22023';
  END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(payload) LOOP
    IF jsonb_typeof(item) <> 'object' THEN
      RAISE EXCEPTION 'Catalog rows must be objects' USING ERRCODE = '22023';
    END IF;
    SELECT array_agg(column_name ORDER BY column_name) INTO row_columns
      FROM jsonb_object_keys(item) AS keys(column_name);
    IF row_columns IS NULL OR NOT row_columns <@ allowed_columns THEN
      RAISE EXCEPTION 'Unsupported catalog column' USING ERRCODE = '22023';
    END IF;
    IF input_columns IS NULL THEN input_columns := row_columns;
    ELSIF input_columns <> row_columns THEN
      RAISE EXCEPTION 'Catalog rows require matching columns' USING ERRCODE = '22023';
    END IF;
    FOREACH key IN ARRAY conflict_columns LOOP
      IF NOT item ? key OR jsonb_typeof(item -> key) <> 'string' OR item ->> key = '' THEN
        RAISE EXCEPTION 'Missing or invalid catalog conflict key' USING ERRCODE = '22023';
      END IF;
    END LOOP;
  END LOOP;
  SELECT string_agg(format('%I', column_name), ',') INTO insert_columns FROM unnest(input_columns) AS columns(column_name);
  SELECT string_agg(format('%I', column_name), ',') INTO conflict_sql FROM unnest(conflict_columns) AS columns(column_name);
  SELECT string_agg(format('%I = EXCLUDED.%I', column_name, column_name), ',') INTO update_sql
    FROM unnest(input_columns) AS columns(column_name) WHERE NOT column_name = ANY(conflict_columns);
  -- Identifiers originate from fixed allowlists. Rule values remain a bound JSON parameter.
  EXECUTE format('INSERT INTO public.%I (%s) SELECT %s FROM jsonb_populate_recordset(NULL::public.%I, $1) ON CONFLICT (%s) %s',
    p_table, insert_columns, insert_columns, p_table, conflict_sql,
    CASE WHEN update_sql IS NULL THEN 'DO NOTHING' ELSE 'DO UPDATE SET ' || update_sql END)
    USING payload;
  -- Acknowledges accepted input rows, including an already-present key-only row.
  -- It does not claim every row was newly inserted or physically changed.
  RETURN jsonb_build_object('processed', row_total);
END;
$$;
REVOKE ALL ON FUNCTION public.seed_catalog_batch(text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.seed_catalog_batch(text, text) TO service_role;
NOTIFY pgrst, 'reload schema';
COMMIT;
