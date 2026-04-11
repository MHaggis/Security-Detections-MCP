import { createClient } from '@/lib/supabase/server';
import Link from 'next/link';

interface ActorRow {
  actor_id: string;
  name: string;
  aliases: string[] | null;
  description: string | null;
}

export default async function ActorBrowsePage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string }>;
}) {
  const params = await searchParams;
  const query = params.q || '';
  const supabase = await createClient();

  // Fetch actors — use RPC for alias-aware search, direct query otherwise
  let actors: ActorRow[] | null = null;
  if (query) {
    const { data } = await supabase.rpc('search_actors', { p_query: query });
    actors = data as ActorRow[] | null;
  } else {
    const { data } = await supabase
      .from('attack_actors')
      .select('actor_id, name, aliases, description')
      .order('name');
    actors = data as ActorRow[] | null;
  }

  // Get technique counts per actor via RPC (server-side aggregation, bypasses API row limit)
  const { data: techCountsRpc } = await supabase.rpc('get_actor_technique_counts');

  const countMap: Record<string, number> = {};
  if (techCountsRpc) {
    for (const row of techCountsRpc) {
      countMap[row.actor_id] = Number(row.count);
    }
  }

  return (
    <div className="max-w-6xl mx-auto animate-slide-up">
      <h1 className="font-[family-name:var(--font-display)] text-4xl text-text-bright tracking-wider mb-2">
        THREAT ACTORS
      </h1>
      <p className="text-text-dim text-sm mb-6">
        {actors?.length || 0} MITRE ATT&CK threat actors with technique mappings and detection coverage.
      </p>

      {/* Search */}
      <form className="mb-6">
        <input
          type="text"
          name="q"
          defaultValue={query}
          placeholder="Search actors... (e.g., APT29, Lazarus, FIN7)"
          className="w-full bg-card border border-border focus:border-amber/50 rounded-[var(--radius-button)] px-5 py-3 text-text placeholder:text-text-dim/50 outline-none transition-colors font-[family-name:var(--font-mono)] text-sm"
        />
      </form>

      {/* Actor grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {actors?.map((actor: ActorRow) => {
          const aliases = (actor.aliases as string[]) || [];
          const techCount = countMap[actor.actor_id] || 0;
          return (
            <Link
              key={actor.actor_id}
              href={`/explore/actor/${encodeURIComponent(actor.name)}`}
              className="bg-card hover:bg-card2 border border-border hover:border-red/30 rounded-[var(--radius-card)] p-4 transition-all group block"
            >
              <div className="flex items-start justify-between">
                <h3 className="text-text-bright group-hover:text-amber font-medium text-sm transition-colors">
                  {actor.name}
                </h3>
                <span className="text-amber font-[family-name:var(--font-mono)] text-xs font-bold shrink-0 ml-2">
                  {techCount} TTPs
                </span>
              </div>
              {aliases.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1.5">
                  {aliases.slice(0, 3).map((alias: string) => (
                    <span key={alias} className="bg-card2 text-text-dim text-xs font-[family-name:var(--font-mono)] px-1.5 py-0.5 rounded-[var(--radius-tag)] border border-border">
                      {alias}
                    </span>
                  ))}
                  {aliases.length > 3 && (
                    <span className="text-text-dim/50 text-xs">+{aliases.length - 3}</span>
                  )}
                </div>
              )}
              {actor.description && (
                <p className="text-text-dim text-xs mt-2 line-clamp-2">
                  {actor.description.substring(0, 150)}
                </p>
              )}
            </Link>
          );
        })}
      </div>

      {/* Empty state */}
      {(!actors || actors.length === 0) && (
        <div className="text-center py-20">
          <div className="text-4xl mb-4">&#128123;</div>
          <p className="text-text-dim">No actors found{query ? ` for "${query}"` : ''}.</p>
        </div>
      )}
    </div>
  );
}
