import { createClient } from '@/lib/supabase/server';
import Link from 'next/link';

interface DashboardStats {
  detections: number;
  techniques: number;
  actors: number;
  software: number;
  covered_techniques: number;
  procedures: number;
  by_source: Array<{ source: string; count: number }> | null;
  last_sync: { started_at: string; status: string; detections_added: number; detections_updated: number } | null;
}

export default async function DashboardPage() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  // Single RPC for all dashboard stats
  const { data: statsRaw } = await supabase.rpc('get_dashboard_stats');
  const stats: DashboardStats = statsRaw as DashboardStats || {
    detections: 0, techniques: 0, actors: 0, software: 0,
    covered_techniques: 0, procedures: 0, by_source: null, last_sync: null,
  };

  // Get profile
  let profile: { display_name?: string; tier?: string } | null = null;
  if (user) {
    const { data } = await supabase
      .from('profiles')
      .select('display_name, tier')
      .eq('id', user.id)
      .single();
    profile = data;
  }

  return (
    <div className="max-w-6xl mx-auto animate-slide-up">
      {/* Welcome */}
      <div className="mb-8">
        <h1 className="font-[family-name:var(--font-display)] text-4xl text-text-bright tracking-wider">
          WELCOME BACK{profile?.display_name ? `, ${profile.display_name.toUpperCase()}` : ''}
        </h1>
        <p className="text-text-dim mt-1">Your detection coverage intelligence dashboard.</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-6">
          <div className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
            Total Detections
          </div>
          <div className="font-[family-name:var(--font-display)] text-4xl text-amber">
            {stats.detections.toLocaleString()}
          </div>
          <div className="text-text-dim text-xs mt-1">Across 6 sources</div>
        </div>
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-6">
          <div className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
            ATT&CK Techniques
          </div>
          <div className="font-[family-name:var(--font-display)] text-4xl text-green">
            {stats.techniques.toLocaleString()}
          </div>
          <div className="text-text-dim text-xs mt-1">
            {stats.covered_techniques} covered ({stats.techniques > 0 ? Math.round((stats.covered_techniques / stats.techniques) * 100) : 0}%)
          </div>
        </div>
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-6">
          <div className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
            Threat Actors
          </div>
          <div className="font-[family-name:var(--font-display)] text-4xl text-blue">
            {stats.actors.toLocaleString()}
          </div>
          <div className="text-text-dim text-xs mt-1">APT groups mapped</div>
        </div>
      </div>

      {/* Quick Actions */}
      <h2 className="font-[family-name:var(--font-display)] text-2xl text-text-bright tracking-wider mb-4">
        QUICK ACTIONS
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Link href="/explore" className="bg-card hover:bg-card2 border border-border hover:border-amber/30 rounded-[var(--radius-card)] p-6 transition-all group">
          <div className="text-2xl mb-2">&#128269;</div>
          <h3 className="font-[family-name:var(--font-display)] text-xl text-text-bright tracking-wider group-hover:text-amber transition-colors">
            EXPLORE DETECTIONS
          </h3>
          <p className="text-text-dim text-sm mt-1">Search and browse detection rules across all sources.</p>
        </Link>
        <Link href="/chat" className="bg-card hover:bg-card2 border border-border hover:border-blue/30 rounded-[var(--radius-card)] p-6 transition-all group">
          <div className="text-2xl mb-2">&#129302;</div>
          <h3 className="font-[family-name:var(--font-display)] text-xl text-text-bright tracking-wider group-hover:text-blue transition-colors">
            ASK AI
          </h3>
          <p className="text-text-dim text-sm mt-1">Chat with AI about your detection coverage.</p>
        </Link>
        <Link href="/coverage" className="bg-card hover:bg-card2 border border-border hover:border-green/30 rounded-[var(--radius-card)] p-6 transition-all group">
          <div className="text-2xl mb-2">&#128200;</div>
          <h3 className="font-[family-name:var(--font-display)] text-xl text-text-bright tracking-wider group-hover:text-green transition-colors">
            COVERAGE ANALYSIS
          </h3>
          <p className="text-text-dim text-sm mt-1">View tactic heatmaps and identify gaps.</p>
        </Link>
      </div>

      {/* Data Sync Status */}
      <div className="mt-8 bg-card border border-border rounded-[var(--radius-card)] p-6">
        <h2 className="font-[family-name:var(--font-display)] text-xl text-text-bright tracking-wider mb-4">
          DATA SYNC STATUS
        </h2>
        {stats.last_sync ? (
          <div className="flex items-center gap-4">
            <div className={`w-2 h-2 rounded-full ${stats.last_sync.status === 'completed' ? 'bg-green' : stats.last_sync.status === 'running' ? 'bg-amber animate-pulse' : 'bg-red'}`} />
            <span className="text-text-dim text-sm font-[family-name:var(--font-mono)]">
              Last sync: {new Date(stats.last_sync.started_at).toLocaleDateString()} — {stats.last_sync.status}
              {stats.last_sync.detections_added > 0 && ` (+${stats.last_sync.detections_added} new)`}
            </span>
          </div>
        ) : (
          <p className="text-text-dim text-sm font-[family-name:var(--font-mono)]">
            No sync runs recorded yet. Data will be synced nightly.
          </p>
        )}
      </div>
    </div>
  );
}
