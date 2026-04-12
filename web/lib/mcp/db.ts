/**
 * Supabase-backed query layer for the hosted MCP server.
 *
 * Mirrors the shape of the stdio package's src/db/detections.ts, but reads
 * from Supabase Postgres instead of the local SQLite cache. Most functions
 * are thin wrappers around the RPCs defined in migration 002_rls_and_functions.sql.
 *
 * All calls use the service-role client because MCP requests authenticate
 * via bearer tokens (see lib/mcp/auth.ts), not Supabase cookies.
 */

import { createClient, type SupabaseClient } from '@supabase/supabase-js';

let _serviceClient: SupabaseClient | null = null;

export function getServiceClient(): SupabaseClient {
  if (_serviceClient) return _serviceClient;
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) {
    throw new Error('Supabase env missing: NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY required');
  }
  _serviceClient = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return _serviceClient;
}

// ─── Types ─────────────────────────────────────────────────────────────────

export interface DetectionRow {
  id: string;
  name: string;
  description: string | null;
  source_type: string;
  severity: string | null;
  mitre_ids: string[];
  mitre_tactics: string[];
  detection_type: string | null;
  data_sources?: string[];
  query?: string | null;
}

const DETECTION_LIST_COLUMNS =
  'id, name, description, source_type, severity, mitre_ids, mitre_tactics, detection_type, data_sources';

const SOURCE_TYPES = ['sigma', 'splunk_escu', 'elastic', 'kql', 'sublime', 'crowdstrike_cql'] as const;
export type SourceType = (typeof SOURCE_TYPES)[number];
export const ALL_SOURCE_TYPES = SOURCE_TYPES;

// ─── Search & retrieval ───────────────────────────────────────────────────

export async function searchDetections(query: string, limit = 50, sourceType?: string): Promise<DetectionRow[]> {
  const supabase = getServiceClient();

  // Build a tsquery string from user input: split on whitespace, AND together
  const tsquery = query.trim().split(/\s+/).filter(Boolean).join(' & ');
  if (!tsquery) return [];

  let q = supabase
    .from('detections')
    .select(DETECTION_LIST_COLUMNS)
    .textSearch('search_vector', tsquery, { config: 'english' })
    .order('name')
    .limit(Math.min(limit, 100));

  if (sourceType) q = q.eq('source_type', sourceType);

  const { data, error } = await q;
  if (error) throw new Error(`searchDetections: ${error.message}`);
  return (data as DetectionRow[]) ?? [];
}

export async function getDetectionById(id: string): Promise<Record<string, unknown> | null> {
  const supabase = getServiceClient();
  const { data, error } = await supabase
    .from('detections')
    .select('*')
    .eq('id', id)
    .maybeSingle();
  if (error) throw new Error(`getDetectionById: ${error.message}`);
  return data;
}

export async function getRawYaml(id: string): Promise<string | null> {
  const supabase = getServiceClient();
  const { data, error } = await supabase
    .from('detections')
    .select('raw_yaml')
    .eq('id', id)
    .maybeSingle();
  if (error) throw new Error(`getRawYaml: ${error.message}`);
  return (data?.raw_yaml as string | undefined) ?? null;
}

export async function listDetections(limit = 100, offset = 0, sourceType?: string): Promise<DetectionRow[]> {
  const supabase = getServiceClient();
  let q = supabase
    .from('detections')
    .select(DETECTION_LIST_COLUMNS)
    .order('name')
    .range(offset, offset + Math.min(limit, 100) - 1);
  if (sourceType) q = q.eq('source_type', sourceType);
  const { data, error } = await q;
  if (error) throw new Error(`listDetections: ${error.message}`);
  return (data as DetectionRow[]) ?? [];
}

// ─── Stats & coverage ──────────────────────────────────────────────────────

export async function getStats(): Promise<Record<string, unknown>> {
  const supabase = getServiceClient();
  const { data, error } = await supabase.rpc('get_dashboard_stats');
  if (error) throw new Error(`getStats: ${error.message}`);
  return (data as Record<string, unknown>) ?? {};
}

export async function getCoverageSummary(): Promise<Record<string, unknown>> {
  const supabase = getServiceClient();
  const { data, error } = await supabase.rpc('get_coverage_summary');
  if (error) throw new Error(`getCoverageSummary: ${error.message}`);
  return (data as Record<string, unknown>) ?? {};
}

export async function getThreatProfileGaps(profile: string): Promise<Record<string, unknown>> {
  const supabase = getServiceClient();
  const { data, error } = await supabase.rpc('get_threat_profile_gaps', { p_profile: profile });
  if (error) throw new Error(`getThreatProfileGaps: ${error.message}`);
  return (data as Record<string, unknown>) ?? {};
}

export async function getTechniqueIntelligence(techniqueId: string): Promise<Record<string, unknown>> {
  const supabase = getServiceClient();
  const { data, error } = await supabase.rpc('get_technique_intelligence', { p_technique_id: techniqueId });
  if (error) throw new Error(`getTechniqueIntelligence: ${error.message}`);
  return (data as Record<string, unknown>) ?? {};
}

export async function getTechniqueFull(techniqueId: string, detectionLimit = 50): Promise<Record<string, unknown>> {
  const supabase = getServiceClient();
  const { data, error } = await supabase.rpc('get_technique_full', {
    p_technique_id: techniqueId,
    p_detection_limit: detectionLimit,
  });
  if (error) throw new Error(`getTechniqueFull: ${error.message}`);
  return (data as Record<string, unknown>) ?? {};
}

export async function compareSourcesForTechnique(techniqueId: string): Promise<Record<string, unknown>> {
  const supabase = getServiceClient();
  const { data, error } = await supabase.rpc('compare_sources_for_technique', { p_technique_id: techniqueId });
  if (error) throw new Error(`compareSourcesForTechnique: ${error.message}`);
  return (data as Record<string, unknown>) ?? {};
}

// ─── Filters ───────────────────────────────────────────────────────────────

export async function listBySource(sourceType: string, limit = 50): Promise<DetectionRow[]> {
  const supabase = getServiceClient();
  const { data, error } = await supabase
    .from('detections')
    .select(DETECTION_LIST_COLUMNS)
    .eq('source_type', sourceType)
    .order('name')
    .limit(Math.min(limit, 100));
  if (error) throw new Error(`listBySource: ${error.message}`);
  return (data as DetectionRow[]) ?? [];
}

export async function listBySeverity(severity: string, limit = 50): Promise<DetectionRow[]> {
  const supabase = getServiceClient();
  const { data, error } = await supabase
    .from('detections')
    .select(DETECTION_LIST_COLUMNS)
    .eq('severity', severity)
    .order('name')
    .limit(Math.min(limit, 100));
  if (error) throw new Error(`listBySeverity: ${error.message}`);
  return (data as DetectionRow[]) ?? [];
}

export async function listByDetectionType(detectionType: string, limit = 50): Promise<DetectionRow[]> {
  const supabase = getServiceClient();
  const { data, error } = await supabase
    .from('detections')
    .select(DETECTION_LIST_COLUMNS)
    .eq('detection_type', detectionType)
    .order('name')
    .limit(Math.min(limit, 100));
  if (error) throw new Error(`listByDetectionType: ${error.message}`);
  return (data as DetectionRow[]) ?? [];
}

export async function listByMitre(techniqueId: string, limit = 50): Promise<DetectionRow[]> {
  const supabase = getServiceClient();
  // Use the junction table so we catch every detection that references the technique.
  const { data: ids, error: junctionError } = await supabase
    .from('detection_techniques')
    .select('detection_id')
    .eq('technique_id', techniqueId)
    .limit(500);
  if (junctionError) throw new Error(`listByMitre (junction): ${junctionError.message}`);
  if (!ids || ids.length === 0) return [];

  const detectionIds = ids.map((row) => row.detection_id as string);
  const { data, error } = await supabase
    .from('detections')
    .select(DETECTION_LIST_COLUMNS)
    .in('id', detectionIds)
    .order('name')
    .limit(Math.min(limit, 100));
  if (error) throw new Error(`listByMitre: ${error.message}`);
  return (data as DetectionRow[]) ?? [];
}

export async function listByMitreTactic(tactic: string, limit = 50): Promise<DetectionRow[]> {
  const supabase = getServiceClient();
  // detections.mitre_tactics is JSONB array — use the containment operator
  const { data, error } = await supabase
    .from('detections')
    .select(DETECTION_LIST_COLUMNS)
    .contains('mitre_tactics', [tactic])
    .order('name')
    .limit(Math.min(limit, 100));
  if (error) throw new Error(`listByMitreTactic: ${error.message}`);
  return (data as DetectionRow[]) ?? [];
}

export async function searchByFilter(
  filterType: 'process_name' | 'cve' | 'data_source' | 'detection_type' | 'severity',
  value: string,
  limit = 20,
): Promise<Record<string, unknown>> {
  const supabase = getServiceClient();
  const { data, error } = await supabase.rpc('search_detections_by_filter', {
    p_filter_type: filterType,
    p_filter_value: value,
    p_limit: Math.min(limit, 50),
  });
  if (error) throw new Error(`searchByFilter: ${error.message}`);
  return (data as Record<string, unknown>) ?? {};
}

export async function listByAnalyticStory(storyName: string, limit = 50): Promise<DetectionRow[]> {
  const supabase = getServiceClient();
  const { data, error } = await supabase
    .from('detections')
    .select(DETECTION_LIST_COLUMNS)
    .contains('analytic_stories', [storyName])
    .order('name')
    .limit(Math.min(limit, 100));
  if (error) throw new Error(`listByAnalyticStory: ${error.message}`);
  return (data as DetectionRow[]) ?? [];
}

// ─── Threat actors ─────────────────────────────────────────────────────────

export async function getActorProfile(actorName: string): Promise<Record<string, unknown>> {
  const supabase = getServiceClient();
  const { data, error } = await supabase.rpc('get_actor_profile_full', { p_actor_name: actorName });
  if (error) throw new Error(`getActorProfile: ${error.message}`);
  return (data as Record<string, unknown>) ?? {};
}

export async function getActorIntelligence(actorName: string): Promise<Record<string, unknown>> {
  const supabase = getServiceClient();
  const { data, error } = await supabase.rpc('get_actor_intelligence', { p_actor_name: actorName });
  if (error) throw new Error(`getActorIntelligence: ${error.message}`);
  return (data as Record<string, unknown>) ?? {};
}

export async function compareActors(actorNames: string[]): Promise<Record<string, unknown>> {
  const supabase = getServiceClient();
  const { data, error } = await supabase.rpc('compare_actors', { p_actor_names: actorNames });
  if (error) throw new Error(`compareActors: ${error.message}`);
  return (data as Record<string, unknown>) ?? {};
}

export async function listActors(limit = 50, query?: string): Promise<Array<Record<string, unknown>>> {
  const supabase = getServiceClient();
  if (query && query.trim()) {
    const { data, error } = await supabase.rpc('search_actors', { p_query: query });
    if (error) throw new Error(`listActors (search): ${error.message}`);
    return ((data as Array<Record<string, unknown>>) ?? []).slice(0, limit);
  }
  const { data, error } = await supabase
    .from('attack_actors')
    .select('actor_id, name, aliases, description')
    .order('name')
    .limit(Math.min(limit, 200));
  if (error) throw new Error(`listActors: ${error.message}`);
  return (data as Array<Record<string, unknown>>) ?? [];
}

// ─── Navigator layer helper ────────────────────────────────────────────────
// Builds a minimal but valid ATT&CK Navigator layer from covered technique IDs.
// Mirrors the output shape of the stdio server's generateNavigatorLayer().

export async function generateNavigatorLayer(params: {
  name?: string;
  sourceType?: string;
}): Promise<Record<string, unknown>> {
  const supabase = getServiceClient();

  let query = supabase
    .from('detection_techniques')
    .select('technique_id, detections!inner(source_type)')
    .limit(10000);

  if (params.sourceType) {
    query = query.eq('detections.source_type', params.sourceType);
  }

  const { data, error } = await query;
  if (error) throw new Error(`generateNavigatorLayer: ${error.message}`);

  const counts = new Map<string, number>();
  for (const row of (data as Array<{ technique_id: string }>) ?? []) {
    counts.set(row.technique_id, (counts.get(row.technique_id) ?? 0) + 1);
  }

  const maxCount = Math.max(1, ...counts.values());
  const techniques = Array.from(counts.entries()).map(([techniqueID, count]) => ({
    techniqueID,
    score: count,
    color: '',
    comment: `${count} detection(s)`,
    enabled: true,
    metadata: [],
    showSubtechniques: false,
  }));

  return {
    name: params.name || `Security Detections Coverage${params.sourceType ? ` — ${params.sourceType}` : ''}`,
    versions: { attack: '15', navigator: '5.1.0', layer: '4.5' },
    domain: 'enterprise-attack',
    description: `Coverage layer generated from hosted Security Detections MCP (${techniques.length} techniques, max detections per technique: ${maxCount})`,
    techniques,
    gradient: {
      colors: ['#ffffff', '#66bb6a'],
      minValue: 0,
      maxValue: maxCount,
    },
    legendItems: [],
    showTacticRowBackground: false,
    sorting: 0,
    layout: {
      layout: 'side',
      aggregateFunction: 'average',
      showID: true,
      showName: true,
      showAggregateScores: true,
      countUnscored: false,
    },
    hideDisabled: false,
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
  };
}
