import { createClient } from '@/lib/supabase/server';
import Link from 'next/link';

const SOURCES = [
  { key: 'all', label: 'All Sources' },
  { key: 'sigma', label: 'Sigma' },
  { key: 'splunk_escu', label: 'Splunk ESCU' },
  { key: 'elastic', label: 'Elastic' },
  { key: 'kql', label: 'KQL' },
  { key: 'sublime', label: 'Sublime' },
  { key: 'crowdstrike_cql', label: 'CrowdStrike' },
];

function severityBadge(severity: string | null) {
  const colors: Record<string, string> = {
    critical: 'bg-red/10 text-red border-red/30',
    high: 'bg-orange/10 text-orange border-orange/30',
    medium: 'bg-amber/10 text-amber border-amber/30',
    low: 'bg-blue/10 text-blue border-blue/30',
    informational: 'bg-text-dim/10 text-text-dim border-text-dim/30',
  };
  return colors[severity?.toLowerCase() ?? ''] || 'bg-text-dim/10 text-text-dim border-text-dim/30';
}

function sourceBadge(source: string) {
  const colors: Record<string, string> = {
    sigma: 'bg-blue/10 text-blue border-blue/30',
    splunk_escu: 'bg-green/10 text-green border-green/30',
    elastic: 'bg-orange/10 text-orange border-orange/30',
    kql: 'bg-amber/10 text-amber border-amber/30',
    sublime: 'bg-red/10 text-red border-red/30',
    crowdstrike_cql: 'bg-amber/10 text-amber border-amber/30',
  };
  return colors[source] || 'bg-text-dim/10 text-text-dim border-text-dim/30';
}

function sourceLabel(source: string) {
  const labels: Record<string, string> = {
    sigma: 'Sigma', splunk_escu: 'Splunk', elastic: 'Elastic',
    kql: 'KQL', sublime: 'Sublime', crowdstrike_cql: 'CrowdStrike',
  };
  return labels[source] || source;
}

export default async function ExplorePage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string; source?: string; page?: string }>;
}) {
  const params = await searchParams;
  const query = params.q || '';
  const source = params.source || 'all';
  const page = parseInt(params.page || '1');
  const perPage = 24;
  const offset = (page - 1) * perPage;

  const supabase = await createClient();

  let dbQuery = supabase
    .from('detections')
    .select('id, name, description, source_type, severity, mitre_ids, detection_type', { count: 'exact' });

  if (query) {
    dbQuery = dbQuery.textSearch('search_vector', query.split(' ').join(' & '));
  }

  if (source !== 'all') {
    dbQuery = dbQuery.eq('source_type', source);
  }

  const { data: detections, count } = await dbQuery
    .order('name')
    .range(offset, offset + perPage - 1);

  const totalPages = Math.ceil((count ?? 0) / perPage);

  return (
    <div className="max-w-6xl mx-auto animate-slide-up">
      <h1 className="font-[family-name:var(--font-display)] text-4xl text-text-bright tracking-wider mb-6">
        EXPLORE DETECTIONS
      </h1>

      {/* Search */}
      <form className="mb-6">
        <div className="relative">
          <input
            type="text"
            name="q"
            defaultValue={query}
            placeholder="Search detections... (e.g., powershell, T1059, credential access)"
            className="w-full bg-card border border-border focus:border-amber/50 rounded-[var(--radius-button)] px-5 py-3 pl-12 text-text placeholder:text-text-dim/50 outline-none transition-colors font-[family-name:var(--font-mono)] text-sm"
          />
          <span className="absolute left-4 top-1/2 -translate-y-1/2 text-text-dim">&#128269;</span>
          {source !== 'all' && <input type="hidden" name="source" value={source} />}
        </div>
      </form>

      {/* Source filters */}
      <div className="flex flex-wrap gap-2 mb-6">
        {SOURCES.map((s) => (
          <Link
            key={s.key}
            href={`/explore?${new URLSearchParams({ ...(query ? { q: query } : {}), ...(s.key !== 'all' ? { source: s.key } : {}) }).toString()}`}
            className={`px-4 py-1.5 rounded-[var(--radius-pill)] text-sm font-[family-name:var(--font-mono)] border transition-colors ${
              source === s.key
                ? 'bg-amber/20 text-amber border-amber/40'
                : 'bg-card text-text-dim border-border hover:border-border-bright hover:text-text'
            }`}
          >
            {s.label}
          </Link>
        ))}
      </div>

      {/* Results count */}
      <div className="text-text-dim text-sm font-[family-name:var(--font-mono)] mb-4">
        {count?.toLocaleString() ?? 0} detections found
        {query && <span> for &ldquo;{query}&rdquo;</span>}
      </div>

      {/* Detection grid */}
      <div className="grid gap-3">
        {detections?.map((d) => (
          <Link
            key={d.id}
            href={`/explore/${encodeURIComponent(d.id)}`}
            className="bg-card hover:bg-card2 border border-border hover:border-border-bright rounded-[var(--radius-card)] p-4 transition-all group block"
          >
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0 flex-1">
                <h3 className="text-text-bright group-hover:text-amber font-medium text-sm truncate transition-colors">
                  {d.name}
                </h3>
                {d.description && (
                  <p className="text-text-dim text-xs mt-1 line-clamp-2">{d.description}</p>
                )}
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {(d.mitre_ids as string[] || []).slice(0, 5).map((id: string) => (
                    <span key={id} className="bg-card2 text-text-dim text-xs font-[family-name:var(--font-mono)] px-1.5 py-0.5 rounded-[var(--radius-tag)] border border-border">
                      {id}
                    </span>
                  ))}
                  {(d.mitre_ids as string[] || []).length > 5 && (
                    <span className="text-text-dim text-xs">+{(d.mitre_ids as string[]).length - 5}</span>
                  )}
                </div>
              </div>
              <div className="flex flex-col items-end gap-1.5 shrink-0">
                <span className={`text-xs font-[family-name:var(--font-mono)] px-2 py-0.5 rounded-[var(--radius-tag)] border ${sourceBadge(d.source_type)}`}>
                  {sourceLabel(d.source_type)}
                </span>
                {d.severity && (
                  <span className={`text-xs font-[family-name:var(--font-mono)] px-2 py-0.5 rounded-[var(--radius-tag)] border ${severityBadge(d.severity)}`}>
                    {d.severity}
                  </span>
                )}
              </div>
            </div>
          </Link>
        ))}
      </div>

      {/* Empty state */}
      {(!detections || detections.length === 0) && (
        <div className="text-center py-20">
          <div className="text-4xl mb-4">&#128269;</div>
          <p className="text-text-dim">No detections found. Try a different search.</p>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2 mt-8">
          {page > 1 && (
            <Link
              href={`/explore?${new URLSearchParams({ ...(query ? { q: query } : {}), ...(source !== 'all' ? { source } : {}), page: String(page - 1) }).toString()}`}
              className="bg-card border border-border hover:border-border-bright text-text-dim hover:text-text px-4 py-2 rounded-[var(--radius-button)] text-sm transition-colors"
            >
              Previous
            </Link>
          )}
          <span className="text-text-dim text-sm font-[family-name:var(--font-mono)]">
            Page {page} of {totalPages}
          </span>
          {page < totalPages && (
            <Link
              href={`/explore?${new URLSearchParams({ ...(query ? { q: query } : {}), ...(source !== 'all' ? { source } : {}), page: String(page + 1) }).toString()}`}
              className="bg-card border border-border hover:border-border-bright text-text-dim hover:text-text px-4 py-2 rounded-[var(--radius-button)] text-sm transition-colors"
            >
              Next
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
