import { createClient } from '@/lib/supabase/server';
import Link from 'next/link';
import { notFound } from 'next/navigation';

interface TechniqueFull {
  technique: { technique_id: string; name: string; description: string; platforms: string[]; url: string } | null;
  total_detections: number;
  by_source: Array<{ source: string; count: number }> | null;
  detections: Array<{ id: string; name: string; source_type: string; severity: string | null; description: string | null }> | null;
  actors: Array<{ actor_id: string; name: string }> | null;
  total_actors: number;
  procedures: Array<{ id: string; name: string; category: string; description: string; detection_count: number; confidence: number; source: string }> | null;
  total_procedures: number;
}

export default async function TechniqueDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const techniqueId = decodeURIComponent(id);
  const supabase = await createClient();

  // Single RPC — replaces 7 separate queries
  const { data: raw } = await supabase.rpc('get_technique_full', { p_technique_id: techniqueId });
  const data = raw as TechniqueFull | null;

  if (!data?.technique && (!data?.detections || data.detections.length === 0)) notFound();

  const technique = data?.technique;
  const detections = data?.detections || [];
  const actors = data?.actors || [];
  const procedures = data?.procedures || [];
  const sourceCounts = data?.by_source || [];

  return (
    <div className="max-w-4xl mx-auto animate-slide-up">
      <Link href="/explore" className="text-text-dim hover:text-text text-sm mb-4 inline-block transition-colors">
        &larr; Back to Explore
      </Link>

      {/* Header */}
      <div className="mb-8">
        <span className="font-[family-name:var(--font-mono)] text-amber text-lg">{techniqueId}</span>
        <h1 className="font-[family-name:var(--font-display)] text-4xl text-text-bright tracking-wider mt-1">
          {technique?.name || techniqueId}
        </h1>
        {technique?.description && (
          <p className="text-text-dim mt-3 leading-relaxed text-sm">
            {technique.description.substring(0, 500)}
            {technique.description.length > 500 ? '...' : ''}
          </p>
        )}
        {technique?.platforms && (
          <div className="flex flex-wrap gap-1.5 mt-3">
            {(technique.platforms as string[]).map((p: string) => (
              <span key={p} className="bg-blue/10 text-blue text-xs px-2 py-0.5 rounded-[var(--radius-tag)] border border-blue/30">
                {p}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Coverage summary */}
      <div className="grid grid-cols-3 gap-4 mb-8">
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
          <div className="font-[family-name:var(--font-display)] text-3xl text-amber">{data?.total_detections || 0}</div>
          <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] uppercase mt-1">Detections</div>
        </div>
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
          <div className="font-[family-name:var(--font-display)] text-3xl text-green">{sourceCounts.length}</div>
          <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] uppercase mt-1">Sources</div>
        </div>
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
          <div className="font-[family-name:var(--font-display)] text-3xl text-blue">{data?.total_actors || 0}</div>
          <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] uppercase mt-1">Threat Actors</div>
        </div>
      </div>

      {/* Source breakdown */}
      {sourceCounts.length > 0 && (
        <div className="mb-8">
          <h2 className="font-[family-name:var(--font-display)] text-xl text-text-bright tracking-wider mb-3">BY SOURCE</h2>
          <div className="flex flex-wrap gap-2">
            {sourceCounts.map(({ source, count }) => (
              <span key={source} className="bg-card border border-border rounded-[var(--radius-card)] px-3 py-1.5 text-sm">
                <span className="text-amber font-[family-name:var(--font-mono)] font-bold">{count}</span>
                <span className="text-text-dim ml-2">{source}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Procedures */}
      {procedures.length > 0 && (
        <div className="mb-8">
          <h2 className="font-[family-name:var(--font-display)] text-xl text-text-bright tracking-wider mb-3">
            PROCEDURES ({data?.total_procedures || procedures.length})
          </h2>
          <div className="space-y-2">
            {procedures.map(proc => (
              <div key={proc.id} className="bg-card border border-border rounded-[var(--radius-card)] p-3">
                <div className="flex items-center justify-between">
                  <span className="text-text-bright text-sm font-medium">{proc.name}</span>
                  <span className="text-text-dim text-xs font-[family-name:var(--font-mono)]">
                    {proc.detection_count} detections
                  </span>
                </div>
                <p className="text-text-dim text-xs mt-1">{proc.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Actors using this technique */}
      {actors.length > 0 && (
        <div className="mb-8">
          <h2 className="font-[family-name:var(--font-display)] text-xl text-text-bright tracking-wider mb-3">
            THREAT ACTORS ({data?.total_actors || actors.length})
          </h2>
          <div className="flex flex-wrap gap-2">
            {actors.map(actor => (
              <Link
                key={actor.actor_id}
                href={`/explore/actor/${encodeURIComponent(actor.name)}`}
                className="bg-card hover:bg-card2 border border-border hover:border-red/30 rounded-[var(--radius-card)] px-3 py-1.5 text-sm text-text-dim hover:text-red transition-all"
              >
                {actor.name}
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Detections list */}
      <div>
        <h2 className="font-[family-name:var(--font-display)] text-xl text-text-bright tracking-wider mb-3">
          DETECTIONS ({data?.total_detections || detections.length})
        </h2>
        <div className="space-y-2">
          {detections.map(d => (
            <Link
              key={d.id}
              href={`/explore/${encodeURIComponent(d.id)}`}
              className="bg-card hover:bg-card2 border border-border hover:border-border-bright rounded-[var(--radius-card)] p-3 block transition-all group"
            >
              <div className="flex items-center justify-between">
                <span className="text-text-bright group-hover:text-amber text-sm font-medium transition-colors truncate">
                  {d.name}
                </span>
                <div className="flex items-center gap-2 shrink-0 ml-3">
                  <span className="text-text-dim text-xs font-[family-name:var(--font-mono)]">{d.source_type}</span>
                  {d.severity && (
                    <span className={`text-xs font-[family-name:var(--font-mono)] px-1.5 py-0.5 rounded-[var(--radius-tag)] border ${
                      d.severity === 'critical' ? 'bg-red/10 text-red border-red/30' :
                      d.severity === 'high' ? 'bg-orange/10 text-orange border-orange/30' :
                      d.severity === 'medium' ? 'bg-amber/10 text-amber border-amber/30' :
                      'bg-blue/10 text-blue border-blue/30'
                    }`}>
                      {d.severity}
                    </span>
                  )}
                </div>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
