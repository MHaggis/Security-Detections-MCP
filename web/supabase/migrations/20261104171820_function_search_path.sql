-- Pin resolution for the twenty application functions reported by Supabase's
-- function_search_path_mutable advisor. ALTER preserves bodies, ownership,
-- grants and SECURITY INVOKER/DEFINER. pg_temp must follow trusted schemas.
ALTER FUNCTION public.get_coverage_summary() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.search_detections_full(text, integer) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.handle_new_user() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.get_technique_intelligence(text) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.get_threat_profile_gaps(text) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.compare_actors(text[]) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.search_detections_by_filter(text, text, integer) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.get_tactic_counts() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.get_source_counts() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.get_covered_technique_count() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.get_actor_technique_counts() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.search_actors(text) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.get_actor_coverage(text) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.get_dashboard_stats() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.get_actor_profile_full(text) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.get_technique_full(text, integer) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.get_technique_source_counts(text) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.get_actor_intelligence(text) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.compare_sources_for_technique(text) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.get_procedure_coverage(text) SET search_path = pg_catalog, public, pg_temp;
NOTIFY pgrst, 'reload schema';
