import Link from 'next/link';
import { createClient } from '@/lib/supabase/server';

export const dynamic = 'force-dynamic';

export default async function ReportsPage({
  searchParams,
}: {
  searchParams: Promise<{ tab?: string }>;
}) {
  const params = await searchParams;
  const tab = params.tab || 'mine';
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  let reports: Array<{
    id: string;
    title: string;
    source_url: string | null;
    status: string;
    is_public: boolean;
    created_at: string;
    user_id: string | null;
    extracted_techniques: Array<{ id: string }> | null;
    analysis_result: { coverage_pct?: number; total_techniques?: number; covered_count?: number; gap_count?: number } | null;
  }> | null = null;

  if (tab === 'public') {
    const { data } = await supabase
      .from('threat_reports')
      .select('id, title, source_url, status, is_public, created_at, user_id, extracted_techniques, analysis_result')
      .eq('is_public', true)
      .eq('status', 'complete')
      .order('created_at', { ascending: false })
      .limit(50);
    reports = data;
  } else {
    const { data } = await supabase
      .from('threat_reports')
      .select('id, title, source_url, status, is_public, created_at, user_id, extracted_techniques, analysis_result')
      .eq('user_id', user?.id || '')
      .order('created_at', { ascending: false })
      .limit(50);
    reports = data;
  }

  return (
    <div className="max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="font-[family-name:var(--font-display)] text-2xl tracking-wider text-text-bright uppercase">
            Threat Reports
          </h1>
          <p className="text-text-dim text-sm mt-1">
            Upload threat intelligence reports and get instant coverage analysis
          </p>
        </div>
        <Link
          href="/reports/new"
          className="bg-amber text-bg font-semibold px-5 py-2.5 rounded-[var(--radius-button)] hover:bg-amber/90 transition-colors text-sm"
        >
          + New Report
        </Link>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-card border border-border rounded-[var(--radius-card)] p-1 w-fit">
        <Link
          href="/reports?tab=mine"
          className={`px-4 py-2 rounded-[var(--radius-button)] text-sm font-medium transition-colors ${
            tab === 'mine'
              ? 'bg-amber/20 text-amber'
              : 'text-text-dim hover:text-text'
          }`}
        >
          My Reports
        </Link>
        <Link
          href="/reports?tab=public"
          className={`px-4 py-2 rounded-[var(--radius-button)] text-sm font-medium transition-colors ${
            tab === 'public'
              ? 'bg-amber/20 text-amber'
              : 'text-text-dim hover:text-text'
          }`}
        >
          Public Reports
        </Link>
      </div>

      {/* Reports Grid */}
      {!reports?.length ? (
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-12 text-center">
          <div className="text-4xl mb-4 opacity-50">&#128196;</div>
          <h2 className="text-text-bright text-lg mb-2">
            {tab === 'mine' ? 'No reports yet' : 'No public reports'}
          </h2>
          <p className="text-text-dim text-sm mb-6 max-w-md mx-auto">
            {tab === 'mine'
              ? 'Upload a threat intelligence report or paste a URL to get instant detection coverage analysis.'
              : 'No one has shared public reports yet. Be the first!'}
          </p>
          {tab === 'mine' && (
            <Link
              href="/reports/new"
              className="bg-amber text-bg font-semibold px-5 py-2.5 rounded-[var(--radius-button)] hover:bg-amber/90 transition-colors text-sm"
            >
              Analyze Your First Report
            </Link>
          )}
        </div>
      ) : (
        <div className="grid gap-4">
          {reports.map((report) => {
            const techniqueCount = report.extracted_techniques?.length || report.analysis_result?.total_techniques || 0;
            const coveragePct = report.analysis_result?.coverage_pct ?? 0;
            const coveredCount = report.analysis_result?.covered_count ?? 0;
            const gapCount = report.analysis_result?.gap_count ?? 0;

            return (
              <Link
                key={report.id}
                href={`/reports/${report.id}`}
                className="bg-card border border-border rounded-[var(--radius-card)] p-5 hover:border-amber/40 transition-colors group"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="text-text-bright font-semibold truncate group-hover:text-amber transition-colors">
                        {report.title}
                      </h3>
                      <StatusBadge status={report.status} />
                      {report.is_public && (
                        <span className="text-xs px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30">
                          Public
                        </span>
                      )}
                    </div>
                    {report.source_url && (
                      <p className="text-text-dim text-xs font-[family-name:var(--font-mono)] truncate mb-2">
                        {report.source_url}
                      </p>
                    )}
                    <p className="text-text-dim text-xs">
                      {new Date(report.created_at).toLocaleDateString('en-US', {
                        year: 'numeric', month: 'short', day: 'numeric',
                        hour: '2-digit', minute: '2-digit',
                      })}
                    </p>
                  </div>

                  {report.status === 'complete' && (
                    <div className="flex gap-6 shrink-0">
                      <div className="text-center">
                        <div className="text-xl font-[family-name:var(--font-display)] text-amber">{techniqueCount}</div>
                        <div className="text-text-dim text-[10px] uppercase font-[family-name:var(--font-mono)]">Techniques</div>
                      </div>
                      <div className="text-center">
                        <div className="text-xl font-[family-name:var(--font-display)] text-green">{coveredCount}</div>
                        <div className="text-text-dim text-[10px] uppercase font-[family-name:var(--font-mono)]">Covered</div>
                      </div>
                      <div className="text-center">
                        <div className="text-xl font-[family-name:var(--font-display)] text-red">{gapCount}</div>
                        <div className="text-text-dim text-[10px] uppercase font-[family-name:var(--font-mono)]">Gaps</div>
                      </div>
                      <div className="text-center">
                        <div className={`text-xl font-[family-name:var(--font-display)] ${coveragePct >= 70 ? 'text-green' : coveragePct >= 40 ? 'text-amber' : 'text-red'}`}>
                          {coveragePct}%
                        </div>
                        <div className="text-text-dim text-[10px] uppercase font-[family-name:var(--font-mono)]">Coverage</div>
                      </div>
                    </div>
                  )}
                </div>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    pending: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
    analyzing: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    complete: 'bg-green-500/10 text-green-400 border-green-500/30',
    failed: 'bg-red-500/10 text-red-400 border-red-500/30',
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded border ${styles[status] || styles.pending}`}>
      {status}
    </span>
  );
}
