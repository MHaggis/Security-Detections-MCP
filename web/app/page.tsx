import Link from 'next/link';
import { createClient } from '@supabase/supabase-js';

export const dynamic = 'force-dynamic';

function getSupabase() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  );
}

async function getStats() {
  try {
    const sb = getSupabase();
    const [detRes, actRes, techRes, srcRes] = await Promise.all([
      sb.from('detections').select('*', { count: 'exact', head: true }),
      sb.from('attack_actors').select('*', { count: 'exact', head: true }),
      sb.from('attack_techniques').select('*', { count: 'exact', head: true }),
      sb.rpc('get_source_counts'),
    ]);

    // Count by source (RPC returns pre-aggregated {source_type, count}[])
    const sourceCounts: Record<string, number> = {};
    if (srcRes.data) {
      for (const row of srcRes.data) {
        sourceCounts[row.source_type] = Number(row.count);
      }
    }

    // Count unique sources
    const sourceCount = Object.keys(sourceCounts).length || 6;

    return {
      detections: detRes.count ?? 0,
      actors: actRes.count ?? 0,
      techniques: techRes.count ?? 0,
      sources: sourceCount,
      sourceCounts,
    };
  } catch {
    return { detections: 0, actors: 0, techniques: 0, sources: 6, sourceCounts: {} };
  }
}

const sourceLabels: Record<string, string> = {
  sigma: 'Sigma Rules',
  splunk_escu: 'Splunk ESCU',
  elastic: 'Elastic Rules',
  kql: 'Microsoft KQL',
  sublime: 'Sublime Security',
  crowdstrike_cql: 'CrowdStrike CQL',
};

function StatCard({ value, label, color }: { value: string; label: string; color: string }) {
  const colorClasses: Record<string, string> = {
    amber: 'text-amber border-amber/30 glow-amber',
    green: 'text-green border-green/30 glow-green',
    blue: 'text-blue border-blue/30 glow-blue',
    orange: 'text-orange border-orange/30',
  };
  return (
    <div className={`bg-card border rounded-[var(--radius-card)] p-6 text-center ${colorClasses[color]}`}>
      <div className="font-[family-name:var(--font-display)] text-5xl md:text-6xl tracking-wide">
        {value}
      </div>
      <div className="text-text-dim text-sm mt-2 font-[family-name:var(--font-mono)] uppercase tracking-widest">
        {label}
      </div>
    </div>
  );
}

function FeatureCard({ title, description, icon, accent }: { title: string; description: string; icon: string; accent: string }) {
  const borderColor = accent === 'amber' ? 'border-amber/20 hover:border-amber/40' :
                      accent === 'green' ? 'border-green/20 hover:border-green/40' :
                      accent === 'blue' ? 'border-blue/20 hover:border-blue/40' :
                      'border-orange/20 hover:border-orange/40';
  return (
    <div className={`bg-card border ${borderColor} rounded-[var(--radius-card)] p-6 transition-all duration-300 hover:bg-card2`}>
      <div className="text-3xl mb-4">{icon}</div>
      <h3 className="font-[family-name:var(--font-display)] text-2xl text-text-bright tracking-wide mb-2">{title}</h3>
      <p className="text-text-dim text-sm leading-relaxed">{description}</p>
    </div>
  );
}

function SourceBadge({ name, count }: { name: string; count: string }) {
  return (
    <div className="flex items-center gap-3 bg-card2 border border-border rounded-[var(--radius-card)] px-4 py-3">
      <span className="font-[family-name:var(--font-mono)] text-amber text-sm font-bold">{count}</span>
      <span className="text-text-dim text-sm">{name}</span>
    </div>
  );
}

export default async function LandingPage() {
  const stats = await getStats();

  const detectionsDisplay = stats.detections > 0 ? stats.detections.toLocaleString() : '8,295+';
  const actorsDisplay = stats.actors > 0 ? stats.actors.toLocaleString() : '172';
  const techniquesDisplay = stats.techniques > 0 ? stats.techniques.toLocaleString() : '691';
  const sourcesDisplay = stats.sources.toString();

  const hasSourceCounts = Object.keys(stats.sourceCounts).length > 0;

  return (
    <div className="min-h-screen bg-bg">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-bg/80 backdrop-blur-xl border-b border-border">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-amber/20 border border-amber/40 flex items-center justify-center">
              <span className="text-amber font-bold text-sm">SD</span>
            </div>
            <span className="font-[family-name:var(--font-display)] text-xl tracking-wider text-text-bright">
              SECURITY DETECTIONS
            </span>
          </div>
          <div className="flex items-center gap-4">
            <Link
              href="/explore"
              className="text-text-dim hover:text-text text-sm transition-colors"
            >
              Explore
            </Link>
            <Link
              href="/coverage"
              className="text-text-dim hover:text-text text-sm transition-colors"
            >
              Coverage
            </Link>
            <Link
              href="/mcp"
              className="text-text-dim hover:text-amber text-sm transition-colors font-[family-name:var(--font-mono)]"
            >
              MCP
            </Link>
            <Link
              href="/login"
              className="text-text-dim hover:text-text text-sm transition-colors"
            >
              Sign In
            </Link>
            <Link
              href="/signup"
              className="bg-amber hover:bg-amber-dim text-bg font-semibold text-sm px-4 py-2 rounded-[var(--radius-button)] transition-colors"
            >
              Get Started
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative pt-32 pb-20 overflow-hidden">
        <div className="absolute inset-0 bg-grid orb-amber" />
        <div className="relative max-w-7xl mx-auto px-6">
          <div className="text-center max-w-4xl mx-auto">
            <div className="inline-flex items-center gap-2 bg-card border border-amber/30 rounded-[var(--radius-pill)] px-4 py-1.5 mb-8">
              <span className="w-2 h-2 rounded-full bg-green animate-pulse-slow" />
              <span className="font-[family-name:var(--font-mono)] text-xs text-amber uppercase tracking-widest">
                v3.2 — Procedure-Level Coverage + {actorsDisplay} Threat Actors
              </span>
            </div>

            <h1 className="font-[family-name:var(--font-display)] text-6xl md:text-8xl lg:text-9xl text-text-bright tracking-wide leading-none mb-6">
              DETECTION
              <br />
              <span className="text-amber">INTELLIGENCE</span>
            </h1>

            <p className="text-text-dim text-lg md:text-xl max-w-2xl mx-auto mb-10 leading-relaxed">
              Search {detectionsDisplay} community detection rules across {sourcesDisplay} sources.
              AI-powered coverage analysis against {actorsDisplay} MITRE ATT&CK threat actors.
              Know your gaps before the adversary does.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link
                href="/explore"
                className="bg-amber hover:bg-amber-dim text-bg font-bold px-8 py-3 rounded-[var(--radius-button)] text-lg transition-colors glow-amber"
              >
                Explore Detections
              </Link>
              <Link
                href="/chat"
                className="bg-card hover:bg-card2 border border-border-bright text-text-bright font-semibold px-8 py-3 rounded-[var(--radius-button)] text-lg transition-colors"
              >
                Chat with AI
              </Link>
            </div>
          </div>

          {/* Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-20 max-w-4xl mx-auto">
            <StatCard value={detectionsDisplay} label="Detections" color="amber" />
            <StatCard value={actorsDisplay} label="Threat Actors" color="green" />
            <StatCard value={techniquesDisplay} label="ATT&CK Techniques" color="blue" />
            <StatCard value={sourcesDisplay} label="Detection Sources" color="orange" />
          </div>
        </div>
      </section>

      {/* Sources */}
      <section className="py-16 border-t border-border">
        <div className="max-w-7xl mx-auto px-6">
          <h2 className="font-[family-name:var(--font-display)] text-3xl text-center text-text-bright tracking-wider mb-10">
            DETECTION SOURCES
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            {hasSourceCounts ? (
              Object.entries(stats.sourceCounts)
                .sort((a, b) => b[1] - a[1])
                .map(([sourceType, count]) => (
                  <SourceBadge
                    key={sourceType}
                    name={sourceLabels[sourceType] || sourceType}
                    count={count.toLocaleString()}
                  />
                ))
            ) : (
              <>
                <SourceBadge name="Sigma Rules" count="3,200+" />
                <SourceBadge name="Splunk ESCU" count="1,500+" />
                <SourceBadge name="Elastic Rules" count="1,000+" />
                <SourceBadge name="Microsoft KQL" count="800+" />
                <SourceBadge name="Sublime Security" count="500+" />
                <SourceBadge name="CrowdStrike CQL" count="300+" />
              </>
            )}
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="py-20 border-t border-border">
        <div className="max-w-7xl mx-auto px-6">
          <h2 className="font-[family-name:var(--font-display)] text-4xl text-center text-text-bright tracking-wider mb-4">
            CAPABILITIES
          </h2>
          <p className="text-text-dim text-center mb-12 max-w-2xl mx-auto">
            Everything you need for detection coverage intelligence, powered by AI.
          </p>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
            <FeatureCard
              icon="&#128269;"
              title="DETECTION EXPLORER"
              description={`Search and filter ${detectionsDisplay} detections across all sources. Full rule content, MITRE mappings, and cross-references.`}
              accent="amber"
            />
            <FeatureCard
              icon="&#129302;"
              title="AI CHAT"
              description="Ask questions about your coverage in natural language. 'What's our coverage against APT29?' — get instant, structured answers."
              accent="blue"
            />
            <FeatureCard
              icon="&#128200;"
              title="COVERAGE ANALYSIS"
              description="Tactic-level heatmaps, technique gap analysis, and procedure-level breakdowns. See exactly where you're exposed."
              accent="green"
            />
            <FeatureCard
              icon="&#128123;"
              title="THREAT ACTOR MAPPING"
              description={`Coverage analysis against ${actorsDisplay} MITRE ATT&CK threat actors. Know which APT groups your detections catch — and which they don't.`}
              accent="orange"
            />
            <FeatureCard
              icon="&#128196;"
              title="THREAT REPORT ANALYSIS"
              description="Submit a threat report or advisory. AI extracts TTPs, maps to ATT&CK, and identifies your detection gaps."
              accent="amber"
            />
            <FeatureCard
              icon="&#128506;"
              title="ATT&CK NAVIGATOR"
              description="Generate and export ATT&CK Navigator layers. Visualize coverage, compare sources, and share with your team."
              accent="blue"
            />
          </div>
        </div>
      </section>

      {/* Pricing */}
      <section className="py-20 border-t border-border">
        <div className="max-w-7xl mx-auto px-6">
          <h2 className="font-[family-name:var(--font-display)] text-4xl text-center text-text-bright tracking-wider mb-4">
            PRICING
          </h2>
          <p className="text-text-dim text-center mb-12">
            Free to explore. Upgrade for AI-powered analysis with frontier models.
          </p>

          <div className="grid md:grid-cols-2 gap-6 max-w-3xl mx-auto">
            {/* Free tier */}
            <div className="bg-card border border-border rounded-[var(--radius-card)] p-8">
              <h3 className="font-[family-name:var(--font-display)] text-3xl text-text-bright tracking-wider mb-2">FREE</h3>
              <div className="font-[family-name:var(--font-display)] text-5xl text-text-bright mb-6">$0</div>
              <ul className="space-y-3 text-sm text-text-dim mb-8">
                <li className="flex items-center gap-2"><span className="text-green">&#10003;</span> Browse all {detectionsDisplay} detections</li>
                <li className="flex items-center gap-2"><span className="text-green">&#10003;</span> Coverage dashboards</li>
                <li className="flex items-center gap-2"><span className="text-green">&#10003;</span> Threat actor profiles</li>
                <li className="flex items-center gap-2"><span className="text-green">&#10003;</span> 20 AI chats/day (open-source models)</li>
                <li className="flex items-center gap-2"><span className="text-text-dim">&#8212;</span> Frontier AI models (Claude, GPT)</li>
                <li className="flex items-center gap-2"><span className="text-text-dim">&#8212;</span> BYOK (bring your own API key)</li>
              </ul>
              <Link
                href="/signup"
                className="block text-center bg-card2 hover:bg-border border border-border-bright text-text-bright font-semibold px-6 py-3 rounded-[var(--radius-button)] transition-colors"
              >
                Get Started Free
              </Link>
            </div>

            {/* Pro tier */}
            <div className="bg-card border border-amber/40 rounded-[var(--radius-card)] p-8 glow-amber relative">
              <div className="absolute -top-3 right-6 bg-amber text-bg font-[family-name:var(--font-mono)] text-xs font-bold px-3 py-1 rounded-[var(--radius-pill)] uppercase">
                Recommended
              </div>
              <h3 className="font-[family-name:var(--font-display)] text-3xl text-amber tracking-wider mb-2">PRO</h3>
              <div className="flex items-baseline gap-2 mb-6">
                <span className="font-[family-name:var(--font-display)] text-5xl text-text-bright">$25</span>
                <span className="text-text-dim text-sm">/month or $250/year</span>
              </div>
              <ul className="space-y-3 text-sm text-text-dim mb-8">
                <li className="flex items-center gap-2"><span className="text-green">&#10003;</span> Everything in Free</li>
                <li className="flex items-center gap-2"><span className="text-amber">&#9733;</span> Unlimited AI chats with frontier models</li>
                <li className="flex items-center gap-2"><span className="text-amber">&#9733;</span> Claude Sonnet 4.6, GPT-5.4, Codex, Opus</li>
                <li className="flex items-center gap-2"><span className="text-amber">&#9733;</span> Bring your own API key (Claude, OpenAI)</li>
                <li className="flex items-center gap-2"><span className="text-amber">&#9733;</span> Priority support &amp; feature requests</li>
                <li className="flex items-center gap-2"><span className="text-amber">&#9733;</span> Supports the project&apos;s long-term development</li>
              </ul>
              <a
                href="https://github.com/sponsors/MHaggis"
                target="_blank"
                rel="noopener noreferrer"
                className="block text-center bg-amber hover:bg-amber-dim text-bg font-bold px-6 py-3 rounded-[var(--radius-button)] transition-colors"
              >
                Sponsor on GitHub
              </a>
            </div>
          </div>

          <p className="text-center text-text-dim text-sm mt-8">
            Or bring your own API key (Claude, OpenAI, OpenRouter) — use frontier models at your own cost, no subscription needed.
          </p>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border py-12">
        <div className="max-w-7xl mx-auto px-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-3">
              <div className="w-6 h-6 rounded bg-amber/20 border border-amber/40 flex items-center justify-center">
                <span className="text-amber font-bold text-xs">SD</span>
              </div>
              <span className="font-[family-name:var(--font-mono)] text-text-dim text-sm">
                Security Detections v3.2
              </span>
            </div>
            <div className="flex items-center gap-6 text-sm text-text-dim">
              <a href="https://github.com/MHaggis/Security-Detections-MCP" target="_blank" rel="noopener noreferrer" className="hover:text-text transition-colors">GitHub</a>
              <span>Built by Michael Haag</span>
              <span>Apache 2.0</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
