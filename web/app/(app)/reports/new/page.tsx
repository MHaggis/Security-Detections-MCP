'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function NewReportPage() {
  const router = useRouter();
  const [mode, setMode] = useState<'paste' | 'url'>('url');
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [url, setUrl] = useState('');
  const [isPublic, setIsPublic] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);

    if (mode === 'url' && !url.trim()) {
      setError('Enter a URL to analyze');
      return;
    }
    if (mode === 'paste' && !content.trim()) {
      setError('Paste report content to analyze');
      return;
    }
    if (mode === 'url' && !url.match(/^https?:\/\//i)) {
      setError('URL must start with http:// or https://');
      return;
    }

    setAnalyzing(true);

    try {
      const res = await fetch('/api/reports/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: title || undefined,
          content: mode === 'paste' ? content : undefined,
          source_url: mode === 'url' ? url.trim() : undefined,
          is_public: isPublic,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || 'Analysis failed');
        setAnalyzing(false);
        return;
      }

      router.push(`/reports/${data.id}`);
    } catch {
      setError('Network error. Please try again.');
      setAnalyzing(false);
    }
  }

  return (
    <div className="max-w-3xl mx-auto">
      <h1 className="font-[family-name:var(--font-display)] text-2xl tracking-wider text-text-bright uppercase mb-2">
        Analyze Threat Report
      </h1>
      <p className="text-text-dim text-sm mb-8">
        Paste a threat intelligence report or enter a URL. We&apos;ll extract MITRE ATT&amp;CK techniques, CVEs, IOCs, and map them against your detection coverage.
      </p>

      {/* Mode Toggle */}
      <div className="flex gap-1 mb-6 bg-card border border-border rounded-[var(--radius-card)] p-1 w-fit">
        <button
          onClick={() => setMode('url')}
          className={`px-4 py-2 rounded-[var(--radius-button)] text-sm font-medium transition-colors ${
            mode === 'url' ? 'bg-amber/20 text-amber' : 'text-text-dim hover:text-text'
          }`}
        >
          URL
        </button>
        <button
          onClick={() => setMode('paste')}
          className={`px-4 py-2 rounded-[var(--radius-button)] text-sm font-medium transition-colors ${
            mode === 'paste' ? 'bg-amber/20 text-amber' : 'text-text-dim hover:text-text'
          }`}
        >
          Paste Text
        </button>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Title (optional) */}
        <div>
          <label className="block text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
            Title <span className="text-text-dim/50">(optional)</span>
          </label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            maxLength={500}
            placeholder="e.g., CISA Advisory AA24-131A"
            className="w-full bg-bg2 border border-border focus:border-amber/50 rounded-[var(--radius-button)] px-4 py-2.5 text-text placeholder:text-text-dim/40 outline-none transition-colors"
          />
        </div>

        {/* URL Input */}
        {mode === 'url' && (
          <div>
            <label className="block text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
              Report URL
            </label>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://www.cisa.gov/news-events/cybersecurity-advisories/..."
              className="w-full bg-bg2 border border-border focus:border-amber/50 rounded-[var(--radius-button)] px-4 py-2.5 text-text placeholder:text-text-dim/40 outline-none transition-colors font-[family-name:var(--font-mono)] text-sm"
            />
            <p className="text-text-dim/50 text-xs mt-2">
              We&apos;ll fetch the page, extract text, and analyze it for techniques, CVEs, and IOCs.
            </p>
          </div>
        )}

        {/* Paste Content */}
        {mode === 'paste' && (
          <div>
            <label className="block text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
              Report Content
            </label>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              maxLength={100000}
              rows={16}
              placeholder="Paste the full threat intelligence report here..."
              className="w-full bg-bg2 border border-border focus:border-amber/50 rounded-[var(--radius-button)] px-4 py-3 text-text placeholder:text-text-dim/40 outline-none transition-colors resize-y text-sm leading-relaxed"
            />
            <p className="text-text-dim/50 text-xs mt-1 text-right">
              {content.length.toLocaleString()} / 100,000
            </p>
          </div>
        )}

        {/* Public toggle */}
        <label className="flex items-center gap-3 cursor-pointer group">
          <div className="relative">
            <input
              type="checkbox"
              checked={isPublic}
              onChange={(e) => setIsPublic(e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-10 h-5 bg-border rounded-full peer-checked:bg-amber/60 transition-colors" />
            <div className="absolute top-0.5 left-0.5 w-4 h-4 bg-text-dim rounded-full peer-checked:translate-x-5 peer-checked:bg-amber transition-all" />
          </div>
          <span className="text-sm text-text-dim group-hover:text-text transition-colors">
            Make this report public (others can see the analysis)
          </span>
        </label>

        {/* Error */}
        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-[var(--radius-card)] px-4 py-3 text-red-400 text-sm">
            {error}
          </div>
        )}

        {/* Submit */}
        <button
          type="submit"
          disabled={analyzing}
          className="w-full bg-amber text-bg font-semibold py-3 rounded-[var(--radius-button)] hover:bg-amber/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed text-sm"
        >
          {analyzing ? (
            <span className="flex items-center justify-center gap-3">
              <span className="w-4 h-4 border-2 border-bg/30 border-t-bg rounded-full animate-spin" />
              Analyzing Report...
            </span>
          ) : (
            'Analyze Report'
          )}
        </button>
      </form>

      {/* What we extract */}
      <div className="mt-12 grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'ATT&CK Techniques', desc: 'T-codes + coverage mapping', icon: '&#9876;' },
          { label: 'CVEs', desc: 'Vulnerability references', icon: '&#128274;' },
          { label: 'IOCs', desc: 'IPs, hashes, domains', icon: '&#128270;' },
          { label: 'Actors', desc: 'Threat group attribution', icon: '&#128123;' },
        ].map((item) => (
          <div key={item.label} className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
            <div className="text-2xl mb-2 opacity-60" dangerouslySetInnerHTML={{ __html: item.icon }} />
            <div className="text-text-bright text-xs font-semibold mb-1">{item.label}</div>
            <div className="text-text-dim text-[10px]">{item.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
