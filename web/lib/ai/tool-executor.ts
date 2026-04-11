import { createClient, type SupabaseClient } from '@supabase/supabase-js';

let _supabase: SupabaseClient | null = null;
function getSupabase() {
  if (!_supabase) {
    _supabase = createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.SUPABASE_SERVICE_ROLE_KEY!
    );
  }
  return _supabase;
}

export async function executeToolCall(
  name: string,
  args: Record<string, string>
): Promise<string> {
  switch (name) {
    case 'search_detections':
      return await searchDetections(args);
    case 'get_technique_coverage':
      return await getTechniqueCoverage(args);
    case 'get_actor_coverage':
      return await getActorCoverage(args);
    case 'get_tactic_summary':
      return await getTacticSummary();
    case 'list_actors':
      return await listActors(args);
    case 'compare_sources':
      return await compareSources(args);
    default:
      return JSON.stringify({ error: `Unknown tool: ${name}` });
  }
}

async function searchDetections(args: Record<string, string>): Promise<string> {
  const limit = parseInt(args.limit || '10');
  const sb = getSupabase();
  let query = sb
    .from('detections')
    .select('id, name, description, source_type, severity, mitre_ids, detection_type')
    .limit(limit);

  if (args.query) {
    query = query.textSearch('search_vector', args.query.split(' ').join(' & '));
  }
  if (args.source) {
    query = query.eq('source_type', args.source);
  }
  if (args.severity) {
    query = query.eq('severity', args.severity);
  }

  const { data, error } = await query;
  if (error) return JSON.stringify({ error: error.message });
  return JSON.stringify({
    count: data?.length ?? 0,
    detections: data?.map((d: Record<string, unknown>) => ({
      name: d.name,
      source: d.source_type,
      severity: d.severity,
      techniques: d.mitre_ids,
      type: d.detection_type,
      description: typeof d.description === 'string' ? d.description.substring(0, 200) : null,
    })),
  });
}

async function getTechniqueCoverage(args: Record<string, string>): Promise<string> {
  const techniqueId = args.technique_id;
  const sb = getSupabase();

  // Get detection IDs for this technique
  const { data: detTechRows } = await sb
    .from('detection_techniques')
    .select('detection_id')
    .eq('technique_id', techniqueId);

  const detIds = detTechRows?.map(d => d.detection_id) || [];

  // Fetch detection details separately (no join)
  const sourceCounts: Record<string, number> = {};
  if (detIds.length > 0) {
    const { data: dets } = await sb
      .from('detections')
      .select('source_type')
      .in('id', detIds.slice(0, 500));
    if (dets) {
      for (const d of dets) {
        sourceCounts[d.source_type] = (sourceCounts[d.source_type] || 0) + 1;
      }
    }
  }

  const { data: technique } = await sb
    .from('attack_techniques')
    .select('*')
    .eq('technique_id', techniqueId)
    .single();

  return JSON.stringify({
    technique_id: techniqueId,
    technique_name: technique?.name || 'Unknown',
    description: technique?.description?.substring(0, 300),
    total_detections: detIds.length,
    by_source: sourceCounts,
    platforms: technique?.platforms,
  });
}

async function getActorCoverage(args: Record<string, string>): Promise<string> {
  const actorName = args.actor_name;
  const sb = getSupabase();

  let { data: actors } = await sb
    .from('attack_actors')
    .select('*')
    .ilike('name', `%${actorName}%`)
    .limit(1);

  if (!actors || actors.length === 0) {
    const { data: aliasMatch } = await sb
      .from('attack_actors')
      .select('*')
      .filter('aliases', 'cs', `"${actorName}"`)
      .limit(1);

    if (!aliasMatch || aliasMatch.length === 0) {
      return JSON.stringify({ error: `Actor "${actorName}" not found` });
    }
    actors = aliasMatch;
  }

  const actor = actors[0];

  // Get actor's technique IDs (no join — Supabase needs FK for embedded selects)
  const { data: actorTechRows } = await sb
    .from('actor_techniques')
    .select('technique_id')
    .eq('actor_id', actor.actor_id);

  const techniqueIds = actorTechRows?.map((t: { technique_id: string }) => t.technique_id) || [];

  // Fetch technique names separately
  const techNameMap: Record<string, string> = {};
  if (techniqueIds.length > 0) {
    const { data: techRows } = await sb
      .from('attack_techniques')
      .select('technique_id, name')
      .in('technique_id', techniqueIds);
    if (techRows) {
      for (const t of techRows) techNameMap[t.technique_id] = t.name;
    }
  }

  // Check which have detections
  const coveredSet = new Set<string>();
  if (techniqueIds.length > 0) {
    const { data: coveredTechniques } = await sb
      .from('detection_techniques')
      .select('technique_id')
      .in('technique_id', techniqueIds);
    if (coveredTechniques) {
      for (const t of coveredTechniques) coveredSet.add(t.technique_id);
    }
  }

  const covered = techniqueIds.filter((id: string) => coveredSet.has(id));
  const gaps = techniqueIds.filter((id: string) => !coveredSet.has(id));

  return JSON.stringify({
    actor: actor.name,
    aliases: actor.aliases,
    total_techniques: techniqueIds.length,
    covered: covered.length,
    gaps: gaps.length,
    coverage_pct: techniqueIds.length > 0 ? Math.round((covered.length / techniqueIds.length) * 100) : 0,
    gap_techniques: gaps.slice(0, 20).map((id: string) => ({
      id,
      name: techNameMap[id] || 'Unknown',
    })),
    covered_techniques: covered.slice(0, 10).map((id: string) => ({
      id,
      name: techNameMap[id] || 'Unknown',
    })),
  });
}

async function getTacticSummary(): Promise<string> {
  const sb = getSupabase();
  const { data: tacticRpc } = await sb.rpc('get_tactic_counts');

  const counts: Record<string, number> = {};
  if (tacticRpc) {
    for (const row of tacticRpc) {
      counts[row.tactic_name] = Number(row.count);
    }
  }

  const { count: totalDetections } = await sb
    .from('detections')
    .select('*', { count: 'exact', head: true });

  return JSON.stringify({
    total_detections: totalDetections,
    by_tactic: counts,
  });
}

async function listActors(args: Record<string, string>): Promise<string> {
  const limit = parseInt(args.limit || '20');
  const sb = getSupabase();
  let query = sb
    .from('attack_actors')
    .select('actor_id, name, aliases, description')
    .limit(limit)
    .order('name');

  if (args.search) {
    query = query.ilike('name', `%${args.search}%`);
  }

  const { data } = await query;

  const results = await Promise.all(
    (data || []).map(async (actor) => {
      const { count } = await sb
        .from('actor_techniques')
        .select('*', { count: 'exact', head: true })
        .eq('actor_id', actor.actor_id);
      return {
        name: actor.name,
        aliases: (actor.aliases as string[])?.slice(0, 3),
        technique_count: count ?? 0,
        description: actor.description?.substring(0, 150),
      };
    })
  );

  return JSON.stringify({ actors: results });
}

async function compareSources(args: Record<string, string>): Promise<string> {
  const techniqueId = args.technique_id;
  const sb = getSupabase();

  // Get detection IDs, then fetch details separately (no join)
  const { data: detTechRows } = await sb
    .from('detection_techniques')
    .select('detection_id')
    .eq('technique_id', techniqueId);

  const detIds = detTechRows?.map(d => d.detection_id) || [];

  const bySource: Record<string, { count: number; detections: string[] }> = {};
  const allSources = ['sigma', 'splunk_escu', 'elastic', 'kql', 'sublime', 'crowdstrike_cql'];

  for (const src of allSources) {
    bySource[src] = { count: 0, detections: [] };
  }

  if (detIds.length > 0) {
    const { data: dets } = await sb
      .from('detections')
      .select('name, source_type')
      .in('id', detIds.slice(0, 500));
    if (dets) {
      for (const d of dets) {
        if (bySource[d.source_type]) {
          bySource[d.source_type].count++;
          if (bySource[d.source_type].detections.length < 3) {
            bySource[d.source_type].detections.push(d.name);
          }
        }
      }
    }
  }

  return JSON.stringify({
    technique_id: techniqueId,
    comparison: bySource,
    sources_with_coverage: Object.entries(bySource).filter(([, v]) => v.count > 0).length,
    total_sources: allSources.length,
  });
}
