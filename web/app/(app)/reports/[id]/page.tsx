import Link from 'next/link';
import { notFound } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';

export const dynamic = 'force-dynamic';

interface Technique {
  id: string;
  name: string;
  covered: boolean;
  detection_count: number;
  sources: string[];
}

interface AnalysisResult {
  summary: string;
  total_techniques: number;
  covered_count: number;
  gap_count: number;
  coverage_pct: number;
  gap_techniques: Array<{ id: string; name: string }>;
  covered_techniques: Array<{ id: string; name: string; detection_count: number; sources: string[] }>;
  cve_detections: Array<{ cve: string; detection_count: number }>;
}

interface Report {
  id: string;
  title: string;
  content: string;
  source_url: string | null;
  status: string;
  is_public: boolean;
  created_at: string;
  user_id: string | null;
  extracted_techniques: Technique[] | null;
  extracted_actors: string[] | null;
  extracted_iocs: { ips?: string[]; hashes?: string[]; domains?: string[]; cves?: string[] } | null;
  analysis_result: AnalysisResult | null;
}

export default async function ReportDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const supabase = await createClient();

  const { data: report } = await supabase
    .from('threat_reports')
    .select('*')
    .eq('id', id)
    .single() as { data: Report | null };

  if (!report) notFound();

  const analysis = report.analysis_result;
  const techniques = report.extracted_techniques || [];
  const actors = report.extracted_actors || [];
  const iocs = report.extracted_iocs || {};

  return (
    <div className="max-w-6xl mx-auto">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-text-dim text-xs font-[family-name:var(--font-mono)] mb-6">
        <Link href="/reports" className="hover:text-amber transition-colors">Reports</Link>
        <span>/</span>
        <span className="text-text truncate max-w-md">{report.title}</span>
      </div>

      {/* Header */}
      <div className="mb-8">
        <div className="flex items-start justify-between gap-4 mb-3">
          <h1 className="font-[family-name:var(--font-display)] text-2xl tracking-wider text-text-bright">
            {report.title}
          </h1>
          <div className="flex items-center gap-2 shrink-0">
            <StatusBadge status={report.status} />
            {report.is_public && (
              <span className="text-xs px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30">
                Public
              </span>
            )}
          </div>
        </div>
        {report.source_url && (
          <a
            href={report.source_url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-amber hover:text-amber/80 text-sm font-[family-name:var(--font-mono)] underline"
          >
            {report.source_url}
          </a>
        )}
        <p className="text-text-dim text-xs mt-2">
          Analyzed {new Date(report.created_at).toLocaleDateString('en-US', {
            year: 'numeric', month: 'long', day: 'numeric',
            hour: '2-digit', minute: '2-digit',
          })}
        </p>
      </div>

      {/* Analyzing state */}
      {report.status === 'analyzing' && (
        <div className="bg-card border border-blue-500/30 rounded-[var(--radius-card)] p-8 text-center mb-8">
          <div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-400 rounded-full animate-spin mx-auto mb-4" />
          <p className="text-blue-400 font-medium">Analyzing report...</p>
          <p className="text-text-dim text-sm mt-1">Extracting techniques, CVEs, and IOCs. This usually takes 10-30 seconds.</p>
        </div>
      )}

      {/* Failed state */}
      {report.status === 'failed' && (
        <div className="bg-card border border-red-500/30 rounded-[var(--radius-card)] p-8 text-center mb-8">
          <p className="text-red-400 font-medium">Analysis failed</p>
          <p className="text-text-dim text-sm mt-1">Something went wrong during analysis. Try submitting the report again.</p>
          <Link
            href="/reports/new"
            className="inline-block mt-4 bg-amber text-bg font-semibold px-5 py-2 rounded-[var(--radius-button)] hover:bg-amber/90 text-sm"
          >
            Try Again
          </Link>
        </div>
      )}

      {/* Results */}
      {report.status === 'complete' && analysis && (
        <>
          {/* Summary */}
          <div className="bg-card border border-amber/20 rounded-[var(--radius-card)] p-5 mb-8">
            <p className="text-text text-sm leading-relaxed">{analysis.summary}</p>
          </div>

          {/* Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            <StatCard label="Techniques" value={analysis.total_techniques} color="text-amber" />
            <StatCard label="Covered" value={analysis.covered_count} color="text-green" />
            <StatCard label="Gaps" value={analysis.gap_count} color="text-red" />
            <StatCard
              label="Coverage"
              value={`${analysis.coverage_pct}%`}
              color={analysis.coverage_pct >= 70 ? 'text-green' : analysis.coverage_pct >= 40 ? 'text-amber' : 'text-red'}
            />
          </div>

          {/* Coverage Bar */}
          {analysis.total_techniques > 0 && (
            <div className="mb-8">
              <div className="flex justify-between text-xs text-text-dim mb-2">
                <span>Detection Coverage</span>
                <span>{analysis.covered_count} / {analysis.total_techniques}</span>
              </div>
              <div className="w-full bg-bg2 rounded-full h-3 border border-border overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all ${
                    analysis.coverage_pct >= 70 ? 'bg-green' : analysis.coverage_pct >= 40 ? 'bg-amber' : 'bg-red'
                  }`}
                  style={{ width: `${analysis.coverage_pct}%` }}
                />
              </div>
            </div>
          )}

          {/* Covered Techniques */}
          {analysis.covered_techniques?.length > 0 && (
            <div className="mb-8">
              <h2 className="font-[family-name:var(--font-display)] text-lg tracking-wider text-green uppercase mb-4">
                Covered Techniques ({analysis.covered_count})
              </h2>
              <div className="bg-card border border-border rounded-[var(--radius-card)] overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border bg-bg2/50">
                      <th className="text-left text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] px-4 py-3">Technique</th>
                      <th className="text-left text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] px-4 py-3">Name</th>
                      <th className="text-center text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] px-4 py-3">Detections</th>
                      <th className="text-left text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] px-4 py-3">Sources</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analysis.covered_techniques.map((t) => (
                      <tr key={t.id} className="border-b border-border/50 hover:bg-card2/50 transition-colors">
                        <td className="px-4 py-2.5">
                          <Link href={`/explore/technique/${t.id}`} className="text-amber hover:underline font-[family-name:var(--font-mono)]">
                            {t.id}
                          </Link>
                        </td>
                        <td className="px-4 py-2.5 text-text">{t.name}</td>
                        <td className="px-4 py-2.5 text-center text-green font-semibold">{t.detection_count}</td>
                        <td className="px-4 py-2.5">
                          <div className="flex flex-wrap gap-1">
                            {t.sources.map((s) => (
                              <span key={s} className="text-[10px] px-1.5 py-0.5 rounded bg-green/10 text-green border border-green/20">
                                {s}
                              </span>
                            ))}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Gap Techniques */}
          {analysis.gap_techniques?.length > 0 && (
            <div className="mb-8">
              <h2 className="font-[family-name:var(--font-display)] text-lg tracking-wider text-red uppercase mb-4">
                Gap Techniques ({analysis.gap_count})
              </h2>
              <div className="bg-card border border-red-500/20 rounded-[var(--radius-card)] overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border bg-bg2/50">
                      <th className="text-left text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] px-4 py-3">Technique</th>
                      <th className="text-left text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] px-4 py-3">Name</th>
                      <th className="text-left text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] px-4 py-3">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analysis.gap_techniques.map((t) => (
                      <tr key={t.id} className="border-b border-border/50 hover:bg-card2/50 transition-colors">
                        <td className="px-4 py-2.5">
                          <Link href={`/explore/technique/${t.id}`} className="text-amber hover:underline font-[family-name:var(--font-mono)]">
                            {t.id}
                          </Link>
                        </td>
                        <td className="px-4 py-2.5 text-text">{t.name}</td>
                        <td className="px-4 py-2.5">
                          <span className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/30">
                            No Detections
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* CVEs */}
          {analysis.cve_detections?.length > 0 && (
            <div className="mb-8">
              <h2 className="font-[family-name:var(--font-display)] text-lg tracking-wider text-amber uppercase mb-4">
                CVEs ({analysis.cve_detections.length})
              </h2>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                {analysis.cve_detections.map((c) => (
                  <div key={c.cve} className="bg-card border border-border rounded-[var(--radius-card)] p-3">
                    <div className="font-[family-name:var(--font-mono)] text-sm text-text-bright">{c.cve}</div>
                    <div className={`text-xs mt-1 ${c.detection_count > 0 ? 'text-green' : 'text-text-dim'}`}>
                      {c.detection_count > 0 ? `${c.detection_count} detections` : 'No detections'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Actors */}
          {actors.length > 0 && (
            <div className="mb-8">
              <h2 className="font-[family-name:var(--font-display)] text-lg tracking-wider text-amber uppercase mb-4">
                Threat Actors ({actors.length})
              </h2>
              <div className="flex flex-wrap gap-2">
                {actors.map((actor) => (
                  <Link
                    key={actor}
                    href={`/explore/actor/${encodeURIComponent(actor)}`}
                    className="bg-card border border-border rounded-[var(--radius-button)] px-3 py-1.5 text-sm text-text-bright hover:border-amber/40 hover:text-amber transition-colors"
                  >
                    {actor}
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* IOCs */}
          {(iocs.ips?.length || iocs.hashes?.length || iocs.domains?.length) ? (
            <div className="mb-8">
              <h2 className="font-[family-name:var(--font-display)] text-lg tracking-wider text-amber uppercase mb-4">
                IOCs Extracted
              </h2>
              <div className="grid gap-4 md:grid-cols-3">
                {iocs.ips && iocs.ips.length > 0 && (
                  <div className="bg-card border border-border rounded-[var(--radius-card)] p-4">
                    <h3 className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-3">
                      IP Addresses ({iocs.ips.length})
                    </h3>
                    <div className="space-y-1">
                      {iocs.ips.slice(0, 20).map((ip) => (
                        <div key={ip} className="font-[family-name:var(--font-mono)] text-xs text-text">{ip}</div>
                      ))}
                      {iocs.ips.length > 20 && (
                        <div className="text-text-dim text-xs">... and {iocs.ips.length - 20} more</div>
                      )}
                    </div>
                  </div>
                )}
                {iocs.hashes && iocs.hashes.length > 0 && (
                  <div className="bg-card border border-border rounded-[var(--radius-card)] p-4">
                    <h3 className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-3">
                      File Hashes ({iocs.hashes.length})
                    </h3>
                    <div className="space-y-1">
                      {iocs.hashes.slice(0, 20).map((hash) => (
                        <div key={hash} className="font-[family-name:var(--font-mono)] text-[10px] text-text truncate" title={hash}>{hash}</div>
                      ))}
                      {iocs.hashes.length > 20 && (
                        <div className="text-text-dim text-xs">... and {iocs.hashes.length - 20} more</div>
                      )}
                    </div>
                  </div>
                )}
                {iocs.domains && iocs.domains.length > 0 && (
                  <div className="bg-card border border-border rounded-[var(--radius-card)] p-4">
                    <h3 className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-3">
                      Domains ({iocs.domains.length})
                    </h3>
                    <div className="space-y-1">
                      {iocs.domains.slice(0, 20).map((domain) => (
                        <div key={domain} className="font-[family-name:var(--font-mono)] text-xs text-text">{domain}</div>
                      ))}
                      {iocs.domains.length > 20 && (
                        <div className="text-text-dim text-xs">... and {iocs.domains.length - 20} more</div>
                      )}
                    </div>
                  </div>
                )}
              </div>
              <p className="text-text-dim text-xs mt-3 italic">
                IOC-based detection is complementary to behavioral TTP-based detection above.
              </p>
            </div>
          ) : null}

          {/* Technique list from extracted_techniques (if analysis_result techniques differ) */}
          {techniques.length > 0 && !analysis.covered_techniques?.length && !analysis.gap_techniques?.length && (
            <div className="mb-8">
              <h2 className="font-[family-name:var(--font-display)] text-lg tracking-wider text-amber uppercase mb-4">
                All Techniques ({techniques.length})
              </h2>
              <div className="flex flex-wrap gap-2">
                {techniques.map((t) => (
                  <Link
                    key={t.id}
                    href={`/explore/technique/${t.id}`}
                    className={`px-3 py-1.5 rounded text-sm font-[family-name:var(--font-mono)] border ${
                      t.covered
                        ? 'bg-green/10 text-green border-green/30'
                        : 'bg-red-500/10 text-red-400 border-red-500/30'
                    } hover:opacity-80 transition-opacity`}
                  >
                    {t.id}
                  </Link>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {/* Back */}
      <div className="mt-12 pt-6 border-t border-border">
        <Link href="/reports" className="text-text-dim hover:text-amber text-sm transition-colors">
          &larr; Back to Reports
        </Link>
      </div>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number | string; color: string }) {
  return (
    <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
      <div className={`font-[family-name:var(--font-display)] text-3xl ${color}`}>{value}</div>
      <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] uppercase mt-1">{label}</div>
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
