import { createClient } from '@/lib/supabase/server';
import Link from 'next/link';
import { notFound } from 'next/navigation';

interface ActorProfile {
  actor: { actor_id: string; name: string; aliases: string[]; description: string } | null;
  total_techniques: number;
  covered: number;
  gaps: number;
  coverage_pct: number;
  covered_techniques: Array<{ technique_id: string; name: string; detection_count: number }> | null;
  gap_techniques: Array<{ technique_id: string; name: string }> | null;
}

export default async function ActorDetailPage({
  params,
}: {
  params: Promise<{ name: string }>;
}) {
  const { name } = await params;
  const actorName = decodeURIComponent(name);
  const supabase = await createClient();

  // Single RPC — replaces 5 separate queries
  const { data: raw } = await supabase.rpc('get_actor_profile_full', { p_actor_name: actorName });
  const profile = raw as ActorProfile | null;

  if (!profile?.actor) notFound();

  const actor = profile.actor;
  const aliases = (actor.aliases as string[]) || [];
  const covered = profile.covered_techniques || [];
  const gaps = profile.gap_techniques || [];

  return (
    <div className="max-w-4xl mx-auto animate-slide-up">
      <Link href="/explore/actor" className="text-text-dim hover:text-text text-sm mb-4 inline-block transition-colors">
        &larr; Back to Actors
      </Link>

      {/* Header */}
      <div className="mb-8">
        <h1 className="font-[family-name:var(--font-display)] text-4xl text-text-bright tracking-wider">
          {actor.name}
        </h1>
        {aliases.length > 0 && (
          <div className="flex flex-wrap gap-2 mt-2">
            {aliases.map((alias: string) => (
              <span key={alias} className="bg-card2 text-text-dim text-xs font-[family-name:var(--font-mono)] px-2 py-0.5 rounded-[var(--radius-tag)] border border-border">
                {alias}
              </span>
            ))}
          </div>
        )}
        {actor.description && (
          <p className="text-text-dim mt-4 leading-relaxed text-sm">
            {actor.description.substring(0, 600)}
            {actor.description.length > 600 ? '...' : ''}
          </p>
        )}
      </div>

      {/* Coverage stats */}
      <div className="grid grid-cols-4 gap-4 mb-8">
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
          <div className="font-[family-name:var(--font-display)] text-3xl text-amber">{profile.total_techniques}</div>
          <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] uppercase mt-1">Techniques</div>
        </div>
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
          <div className="font-[family-name:var(--font-display)] text-3xl text-green">{profile.covered}</div>
          <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] uppercase mt-1">Covered</div>
        </div>
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
          <div className="font-[family-name:var(--font-display)] text-3xl text-red">{profile.gaps}</div>
          <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] uppercase mt-1">Gaps</div>
        </div>
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
          <div className={`font-[family-name:var(--font-display)] text-3xl ${profile.coverage_pct > 50 ? 'text-green' : profile.coverage_pct > 25 ? 'text-amber' : 'text-red'}`}>
            {profile.coverage_pct}%
          </div>
          <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] uppercase mt-1">Coverage</div>
        </div>
      </div>

      {/* Coverage bar */}
      <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 mb-8">
        <div className="flex justify-between text-sm mb-2">
          <span className="text-text-dim font-[family-name:var(--font-mono)]">Coverage</span>
          <span className="text-text font-[family-name:var(--font-mono)]">{profile.covered}/{profile.total_techniques}</span>
        </div>
        <div className="h-3 bg-bg2 rounded-full overflow-hidden">
          <div className="h-full bg-green rounded-full transition-all" style={{ width: `${profile.coverage_pct}%` }} />
        </div>
      </div>

      {/* Gaps */}
      {gaps.length > 0 && (
        <div className="mb-8">
          <h2 className="font-[family-name:var(--font-display)] text-xl text-red tracking-wider mb-3">
            GAPS ({gaps.length})
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {gaps.map(t => (
              <Link
                key={t.technique_id}
                href={`/explore/technique/${t.technique_id}`}
                className="bg-red/5 hover:bg-red/10 border border-red/20 hover:border-red/40 rounded-[var(--radius-card)] px-3 py-2 transition-all group block"
              >
                <span className="text-red font-[family-name:var(--font-mono)] text-sm">{t.technique_id}</span>
                <span className="text-text-dim text-xs ml-2 group-hover:text-text transition-colors">
                  {t.name}
                </span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Covered */}
      {covered.length > 0 && (
        <div className="mb-8">
          <h2 className="font-[family-name:var(--font-display)] text-xl text-green tracking-wider mb-3">
            COVERED ({covered.length})
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {covered.map(t => (
              <Link
                key={t.technique_id}
                href={`/explore/technique/${t.technique_id}`}
                className="bg-green/5 hover:bg-green/10 border border-green/20 hover:border-green/40 rounded-[var(--radius-card)] px-3 py-2 transition-all group block"
              >
                <span className="text-green font-[family-name:var(--font-mono)] text-sm">{t.technique_id}</span>
                <span className="text-text-dim text-xs ml-2 group-hover:text-text transition-colors">
                  {t.name}
                </span>
                <span className="text-amber/60 text-xs font-[family-name:var(--font-mono)] ml-2">
                  {t.detection_count} det.
                </span>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
