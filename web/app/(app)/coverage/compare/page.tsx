import { createClient } from '@/lib/supabase/server';
import Link from 'next/link';

interface CompareResult {
  actors: Array<{ name: string; total_techniques: number; covered: number; gaps: number; coverage_pct: number }> | null;
  shared_gaps: Array<{ technique_id: string; name: string }> | null;
  unique_gaps: Array<{ actor: string; technique_id: string }> | null;
}

export default async function ComparePage({
  searchParams,
}: {
  searchParams: Promise<{ actors?: string }>;
}) {
  const params = await searchParams;
  const selectedActors = params.actors?.split(',').map(a => a.trim()).filter(Boolean) || [];
  const supabase = await createClient();

  // Get top actors for quick picks
  const { data: allActors } = await supabase
    .from('attack_actors')
    .select('actor_id, name')
    .order('name');

  // Get technique counts per actor via RPC
  const { data: techCountsRpc } = await supabase.rpc('get_actor_technique_counts');

  const countMap: Record<string, number> = {};
  if (techCountsRpc) {
    for (const row of techCountsRpc as Array<{ actor_id: string; count: number }>) {
      countMap[row.actor_id] = Number(row.count);
    }
  }

  // Sort actors by technique count for quick picks
  const topActors = (allActors || [])
    .map(a => ({ ...a, count: countMap[a.actor_id] || 0 }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 12);

  // If actors are selected, use the compare_actors RPC (single query instead of N)
  let comparison: CompareResult | null = null;
  if (selectedActors.length > 0) {
    const { data } = await supabase.rpc('compare_actors', { p_actor_names: selectedActors });
    comparison = data as CompareResult | null;
  }

  const actors = comparison?.actors || [];
  const sharedGaps = comparison?.shared_gaps || [];

  return (
    <div className="max-w-6xl mx-auto animate-slide-up">
      <h1 className="font-[family-name:var(--font-display)] text-4xl text-text-bright tracking-wider mb-2">
        COMPARE ACTORS
      </h1>
      <p className="text-text-dim text-sm mb-6">
        Compare detection coverage across threat actors side-by-side.
      </p>

      {/* Actor selector */}
      <form className="mb-8">
        <div className="flex gap-3">
          <input
            type="text"
            name="actors"
            defaultValue={selectedActors.join(', ')}
            placeholder="Enter actor names separated by commas (e.g., APT29, APT28, Lazarus Group)"
            className="flex-1 bg-card border border-border focus:border-amber/50 rounded-[var(--radius-button)] px-4 py-3 text-text placeholder:text-text-dim/50 outline-none transition-colors font-[family-name:var(--font-mono)] text-sm"
          />
          <button
            type="submit"
            className="bg-amber hover:bg-amber-dim text-bg font-bold px-6 py-3 rounded-[var(--radius-button)] transition-colors shrink-0"
          >
            Compare
          </button>
        </div>
      </form>

      {/* Quick picks */}
      {selectedActors.length === 0 && (
        <div className="mb-8">
          <h2 className="font-[family-name:var(--font-display)] text-xl text-text-bright tracking-wider mb-3">
            QUICK COMPARE
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            {topActors.map(actor => (
              <Link
                key={actor.actor_id}
                href={`/coverage/compare?actors=${encodeURIComponent(actor.name)}`}
                className="bg-card hover:bg-card2 border border-border hover:border-amber/30 rounded-[var(--radius-card)] p-3 transition-all text-center"
              >
                <div className="text-text-bright text-sm font-medium">{actor.name}</div>
                <div className="text-amber font-[family-name:var(--font-mono)] text-xs mt-1">{actor.count} TTPs</div>
              </Link>
            ))}
          </div>
          <p className="text-text-dim text-xs mt-3">
            Click an actor to see their coverage, or enter multiple actors above to compare.
          </p>
        </div>
      )}

      {/* Comparison results */}
      {actors.length > 0 && (
        <div>
          {/* Summary cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            {actors.map(actor => (
              <div key={actor.name} className="bg-card border border-border rounded-[var(--radius-card)] p-6">
                <h3 className="font-[family-name:var(--font-display)] text-xl text-text-bright tracking-wider mb-4">
                  {actor.name}
                </h3>
                <div className="space-y-3">
                  <div className="flex justify-between text-sm">
                    <span className="text-text-dim">Techniques</span>
                    <span className="text-text font-[family-name:var(--font-mono)]">{actor.total_techniques}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-text-dim">Covered</span>
                    <span className="text-green font-[family-name:var(--font-mono)]">{actor.covered}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-text-dim">Gaps</span>
                    <span className="text-red font-[family-name:var(--font-mono)]">{actor.gaps}</span>
                  </div>
                  <div className="h-3 bg-bg2 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${actor.coverage_pct > 50 ? 'bg-green' : actor.coverage_pct > 25 ? 'bg-amber' : 'bg-red'}`}
                      style={{ width: `${actor.coverage_pct}%` }}
                    />
                  </div>
                  <div className="text-center">
                    <span className={`font-[family-name:var(--font-display)] text-3xl ${actor.coverage_pct > 50 ? 'text-green' : actor.coverage_pct > 25 ? 'text-amber' : 'text-red'}`}>
                      {actor.coverage_pct}%
                    </span>
                  </div>
                </div>
                <Link
                  href={`/explore/actor/${encodeURIComponent(actor.name)}`}
                  className="block text-center text-amber hover:text-amber-dim text-xs mt-4 transition-colors"
                >
                  View Full Profile &rarr;
                </Link>
              </div>
            ))}
          </div>

          {/* Shared gaps */}
          {actors.length > 1 && (
            <div className="bg-card border border-red/30 rounded-[var(--radius-card)] p-6">
              <h3 className="font-[family-name:var(--font-display)] text-xl text-red tracking-wider mb-3">
                SHARED GAPS
              </h3>
              <p className="text-text-dim text-sm mb-3">
                Techniques that are gaps across all selected actors.
              </p>
              {sharedGaps.length === 0 ? (
                <p className="text-text-dim text-sm">No shared gaps found.</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {sharedGaps.map(t => (
                    <Link
                      key={t.technique_id}
                      href={`/explore/technique/${t.technique_id}`}
                      className="bg-red/10 text-red text-xs font-[family-name:var(--font-mono)] px-2 py-1 rounded-[var(--radius-tag)] border border-red/30 hover:border-red/60 transition-colors"
                    >
                      {t.technique_id} {t.name && `— ${t.name}`}
                    </Link>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
