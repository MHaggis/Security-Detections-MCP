import { createClient } from '@/lib/supabase/server';
import Link from 'next/link';
import { notFound } from 'next/navigation';

export default async function DetectionDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const supabase = await createClient();

  const { data: detection } = await supabase
    .from('detections')
    .select('*')
    .eq('id', decodeURIComponent(id))
    .single();

  if (!detection) notFound();

  const mitreIds = (detection.mitre_ids as string[]) || [];
  const mitreTactics = (detection.mitre_tactics as string[]) || [];
  const dataSources = (detection.data_sources as string[]) || [];
  const platforms = (detection.platforms as string[]) || [];
  const refs = (detection.refs as string[]) || [];
  const tags = (detection.tags as string[]) || [];

  return (
    <div className="max-w-4xl mx-auto animate-slide-up">
      {/* Back link */}
      <Link href="/explore" className="text-text-dim hover:text-text text-sm mb-4 inline-block transition-colors">
        &larr; Back to Explore
      </Link>

      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-2 mb-2">
          <span className={`text-xs font-[family-name:var(--font-mono)] px-2 py-0.5 rounded-[var(--radius-tag)] border ${
            detection.source_type === 'sigma' ? 'bg-blue/10 text-blue border-blue/30' :
            detection.source_type === 'splunk_escu' ? 'bg-green/10 text-green border-green/30' :
            detection.source_type === 'elastic' ? 'bg-orange/10 text-orange border-orange/30' :
            detection.source_type === 'kql' ? 'bg-amber/10 text-amber border-amber/30' :
            detection.source_type === 'sublime' ? 'bg-red/10 text-red border-red/30' :
            'bg-amber/10 text-amber border-amber/30'
          }`}>
            {detection.source_type}
          </span>
          {detection.severity && (
            <span className={`text-xs font-[family-name:var(--font-mono)] px-2 py-0.5 rounded-[var(--radius-tag)] border ${
              detection.severity === 'critical' ? 'bg-red/10 text-red border-red/30' :
              detection.severity === 'high' ? 'bg-orange/10 text-orange border-orange/30' :
              detection.severity === 'medium' ? 'bg-amber/10 text-amber border-amber/30' :
              'bg-blue/10 text-blue border-blue/30'
            }`}>
              {detection.severity}
            </span>
          )}
          {detection.detection_type && (
            <span className="text-xs font-[family-name:var(--font-mono)] px-2 py-0.5 rounded-[var(--radius-tag)] border bg-card2 text-text-dim border-border">
              {detection.detection_type}
            </span>
          )}
        </div>
        <h1 className="font-[family-name:var(--font-display)] text-3xl text-text-bright tracking-wider">
          {detection.name}
        </h1>
        {detection.description && (
          <p className="text-text-dim mt-2 leading-relaxed">{detection.description}</p>
        )}
      </div>

      {/* MITRE ATT&CK */}
      {mitreIds.length > 0 && (
        <div className="mb-6">
          <h2 className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
            MITRE ATT&CK
          </h2>
          <div className="flex flex-wrap gap-2">
            {mitreIds.map((id) => (
              <Link
                key={id}
                href={`/explore/technique/${id}`}
                className="bg-amber/10 text-amber text-sm font-[family-name:var(--font-mono)] px-3 py-1 rounded-[var(--radius-tag)] border border-amber/30 hover:border-amber/60 transition-colors"
              >
                {id}
              </Link>
            ))}
          </div>
          {mitreTactics.length > 0 && (
            <div className="flex flex-wrap gap-2 mt-2">
              {mitreTactics.map((tactic) => (
                <span key={tactic} className="bg-card2 text-text-dim text-xs font-[family-name:var(--font-mono)] px-2 py-0.5 rounded-[var(--radius-tag)] border border-border">
                  {tactic}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Query */}
      {detection.query && (
        <div className="mb-6">
          <h2 className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
            Detection Query
          </h2>
          <pre className="bg-bg2 border border-border rounded-[var(--radius-card)] p-4 overflow-x-auto text-sm text-green font-[family-name:var(--font-mono)] leading-relaxed">
            <code>{detection.query}</code>
          </pre>
        </div>
      )}

      {/* Metadata */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        {detection.author && (
          <div>
            <h3 className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-1">Author</h3>
            <p className="text-text text-sm">{detection.author}</p>
          </div>
        )}
        {detection.date_created && (
          <div>
            <h3 className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-1">Created</h3>
            <p className="text-text text-sm font-[family-name:var(--font-mono)]">{detection.date_created}</p>
          </div>
        )}
        {dataSources.length > 0 && (
          <div className="col-span-2">
            <h3 className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-1">Data Sources</h3>
            <div className="flex flex-wrap gap-1.5">
              {dataSources.map((ds) => (
                <span key={ds} className="bg-card2 text-text-dim text-xs px-2 py-0.5 rounded-[var(--radius-tag)] border border-border">
                  {ds}
                </span>
              ))}
            </div>
          </div>
        )}
        {platforms.length > 0 && (
          <div className="col-span-2">
            <h3 className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-1">Platforms</h3>
            <div className="flex flex-wrap gap-1.5">
              {platforms.map((p) => (
                <span key={p} className="bg-blue/10 text-blue text-xs px-2 py-0.5 rounded-[var(--radius-tag)] border border-blue/30">
                  {p}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* References */}
      {refs.length > 0 && (
        <div className="mb-6">
          <h2 className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">References</h2>
          <ul className="space-y-1">
            {refs.map((ref, i) => (
              <li key={i}>
                <a href={ref} target="_blank" rel="noopener noreferrer" className="text-blue hover:text-blue-dim text-sm break-all transition-colors">
                  {ref}
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Tags */}
      {tags.length > 0 && (
        <div className="mb-6">
          <h2 className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">Tags</h2>
          <div className="flex flex-wrap gap-1.5">
            {tags.map((tag) => (
              <span key={tag} className="bg-card2 text-text-dim text-xs font-[family-name:var(--font-mono)] px-2 py-0.5 rounded-[var(--radius-tag)] border border-border">
                {tag}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Raw YAML */}
      {detection.raw_yaml && (
        <details className="mb-6">
          <summary className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider cursor-pointer hover:text-text transition-colors">
            Raw Content
          </summary>
          <pre className="bg-bg2 border border-border rounded-[var(--radius-card)] p-4 mt-2 overflow-x-auto text-xs text-text-dim font-[family-name:var(--font-mono)] leading-relaxed max-h-96 overflow-y-auto">
            <code>{detection.raw_yaml}</code>
          </pre>
        </details>
      )}
    </div>
  );
}
