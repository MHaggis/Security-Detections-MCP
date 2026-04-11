import { createClient } from '@/lib/supabase/server';
import Link from 'next/link';

const TACTICS = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
];

function tacticColor(count: number, max: number): string {
  if (count === 0) return 'bg-red/20 border-red/30 text-red';
  const ratio = count / max;
  if (ratio > 0.5) return 'bg-green/20 border-green/30 text-green';
  if (ratio > 0.2) return 'bg-amber/20 border-amber/30 text-amber';
  return 'bg-orange/20 border-orange/30 text-orange';
}

export default async function CoveragePage() {
  const supabase = await createClient();

  // Get tactic counts via RPC (server-side aggregation, bypasses API row limit)
  const { data: tacticRpc } = await supabase.rpc('get_tactic_counts');

  const tacticCounts: Record<string, number> = {};
  for (const t of TACTICS) tacticCounts[t] = 0;
  if (tacticRpc) {
    for (const row of tacticRpc) {
      const t = row.tactic_name.toLowerCase().replace(/ /g, '-');
      if (t in tacticCounts) tacticCounts[t] = Number(row.count);
    }
  }

  const maxCount = Math.max(...Object.values(tacticCounts), 1);

  // Source breakdown via RPC (server-side aggregation, bypasses API row limit)
  const { data: sourceRpc } = await supabase.rpc('get_source_counts');

  const sourceCounts: Record<string, number> = {};
  if (sourceRpc) {
    for (const row of sourceRpc) {
      sourceCounts[row.source_type] = Number(row.count);
    }
  }

  // Get total detection count
  const { count: totalDetections } = await supabase
    .from('detections')
    .select('*', { count: 'exact', head: true });

  // Get covered technique count via RPC (server-side aggregation, bypasses API row limit)
  const { data: coveredCountResult } = await supabase.rpc('get_covered_technique_count');
  const coveredTechniqueCount = Number(coveredCountResult) || 0;

  // Total ATT&CK techniques
  const { count: totalTechniques } = await supabase
    .from('attack_techniques')
    .select('*', { count: 'exact', head: true });

  const coveragePct = totalTechniques ? Math.round((coveredTechniqueCount / totalTechniques) * 100) : 0;

  return (
    <div className="max-w-6xl mx-auto animate-slide-up">
      <h1 className="font-[family-name:var(--font-display)] text-4xl text-text-bright tracking-wider mb-6">
        COVERAGE ANALYSIS
      </h1>

      {/* Overview stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
          <div className="font-[family-name:var(--font-display)] text-3xl text-amber">{totalDetections?.toLocaleString()}</div>
          <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] uppercase mt-1">Total Detections</div>
        </div>
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
          <div className="font-[family-name:var(--font-display)] text-3xl text-green">{coveredTechniqueCount}</div>
          <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] uppercase mt-1">Techniques Covered</div>
        </div>
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
          <div className="font-[family-name:var(--font-display)] text-3xl text-blue">{totalTechniques}</div>
          <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] uppercase mt-1">Total Techniques</div>
        </div>
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
          <div className={`font-[family-name:var(--font-display)] text-3xl ${coveragePct > 50 ? 'text-green' : coveragePct > 25 ? 'text-amber' : 'text-red'}`}>
            {coveragePct}%
          </div>
          <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] uppercase mt-1">Coverage</div>
        </div>
      </div>

      {/* Tactic Heatmap */}
      <h2 className="font-[family-name:var(--font-display)] text-2xl text-text-bright tracking-wider mb-4">
        TACTIC HEATMAP
      </h2>
      <div className="grid grid-cols-2 md:grid-cols-7 gap-2 mb-8">
        {TACTICS.map((tactic) => {
          const count = tacticCounts[tactic];
          return (
            <div
              key={tactic}
              className={`border rounded-[var(--radius-card)] p-3 text-center ${tacticColor(count, maxCount)}`}
            >
              <div className="font-[family-name:var(--font-display)] text-2xl">{count}</div>
              <div className="text-xs font-[family-name:var(--font-mono)] uppercase mt-1 truncate" title={tactic}>
                {tactic.replace(/-/g, ' ')}
              </div>
            </div>
          );
        })}
      </div>

      {/* Source Breakdown */}
      <h2 className="font-[family-name:var(--font-display)] text-2xl text-text-bright tracking-wider mb-4">
        SOURCE BREAKDOWN
      </h2>
      <div className="bg-card border border-border rounded-[var(--radius-card)] p-6 mb-8">
        <div className="space-y-3">
          {Object.entries(sourceCounts).sort((a, b) => b[1] - a[1]).map(([source, count]) => {
            const pct = totalDetections ? Math.round((count / totalDetections) * 100) : 0;
            return (
              <div key={source}>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-text font-[family-name:var(--font-mono)]">{source}</span>
                  <span className="text-text-dim font-[family-name:var(--font-mono)]">{count.toLocaleString()} ({pct}%)</span>
                </div>
                <div className="h-2 bg-bg2 rounded-full overflow-hidden">
                  <div className="h-full bg-amber rounded-full" style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Actor Coverage CTA */}
      <div className="bg-card border border-amber/30 rounded-[var(--radius-card)] p-6 text-center">
        <h2 className="font-[family-name:var(--font-display)] text-2xl text-text-bright tracking-wider mb-2">
          THREAT ACTOR COVERAGE
        </h2>
        <p className="text-text-dim mb-4">
          Analyze your detection coverage against specific MITRE ATT&CK threat actors.
        </p>
        <Link
          href="/explore/actor"
          className="inline-block bg-amber hover:bg-amber-dim text-bg font-bold px-6 py-2 rounded-[var(--radius-button)] transition-colors"
        >
          Browse Actors
        </Link>
      </div>
    </div>
  );
}
