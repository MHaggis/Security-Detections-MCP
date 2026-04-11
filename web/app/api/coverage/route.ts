import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';

function getSupabase() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!
  );
}

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const actor = searchParams.get('actor');
  const technique = searchParams.get('technique');

  if (actor) {
    return getActorCoverage(actor);
  }
  if (technique) {
    return getTechniqueCoverage(technique);
  }
  return getOverallCoverage();
}

async function getOverallCoverage() {
  const sb = getSupabase();
  const [
    { count: totalDetections },
    { data: tacticRpc },
    { count: totalTechniques },
    { data: coveredCount },
  ] = await Promise.all([
    sb.from('detections').select('*', { count: 'exact', head: true }),
    sb.rpc('get_tactic_counts'),
    sb.from('attack_techniques').select('*', { count: 'exact', head: true }),
    sb.rpc('get_covered_technique_count'),
  ]);

  const coveredTechniqueCount = Number(coveredCount) || 0;

  const tacticCounts: Record<string, number> = {};
  if (tacticRpc) {
    for (const row of tacticRpc) {
      tacticCounts[row.tactic_name] = Number(row.count);
    }
  }

  return NextResponse.json({
    total_detections: totalDetections,
    total_techniques: totalTechniques,
    covered_techniques: coveredTechniqueCount,
    coverage_pct: totalTechniques ? Math.round((coveredTechniqueCount / totalTechniques) * 100) : 0,
    by_tactic: tacticCounts,
  });
}

async function getActorCoverage(actorName: string) {
  const sb = getSupabase();
  const { data: actors } = await sb
    .from('attack_actors')
    .select('*')
    .ilike('name', `%${actorName}%`)
    .limit(1);

  if (!actors || actors.length === 0) {
    return NextResponse.json({ error: 'Actor not found' }, { status: 404 });
  }

  const actor = actors[0];
  const { data: techniques } = await sb
    .from('actor_techniques')
    .select('technique_id, attack_techniques(name)')
    .eq('actor_id', actor.actor_id);

  const techniqueIds = techniques?.map((t: { technique_id: string }) => t.technique_id) || [];
  const { data: covered } = await sb
    .from('detection_techniques')
    .select('technique_id')
    .in('technique_id', techniqueIds.length > 0 ? techniqueIds : ['__none__']);

  const coveredSet = new Set(
    covered?.map((t: { technique_id: string }) => t.technique_id) || []
  );

  return NextResponse.json({
    actor: actor.name,
    aliases: actor.aliases,
    total_techniques: techniqueIds.length,
    covered: techniqueIds.filter((id: string) => coveredSet.has(id)).length,
    gaps: techniqueIds.filter((id: string) => !coveredSet.has(id)),
    coverage_pct: techniqueIds.length > 0
      ? Math.round((techniqueIds.filter((id: string) => coveredSet.has(id)).length / techniqueIds.length) * 100)
      : 0,
  });
}

async function getTechniqueCoverage(techniqueId: string) {
  const sb = getSupabase();

  const { data: detTechRows } = await sb
    .from('detection_techniques')
    .select('detection_id')
    .eq('technique_id', techniqueId);

  const detIds = detTechRows?.map(d => d.detection_id) || [];
  let detections: Array<{ id: string; name: string; source_type: string; severity: string | null }> = [];
  if (detIds.length > 0) {
    const { data } = await sb
      .from('detections')
      .select('id, name, source_type, severity')
      .in('id', detIds.slice(0, 200));
    detections = data || [];
  }

  const { data: technique } = await sb
    .from('attack_techniques')
    .select('*')
    .eq('technique_id', techniqueId)
    .single();

  return NextResponse.json({
    technique_id: techniqueId,
    technique_name: technique?.name,
    total_detections: detections.length,
    detections,
  });
}
