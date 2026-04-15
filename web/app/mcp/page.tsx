import Link from 'next/link';
import {
  HOSTED_CODEX_TOKEN_ENV_VAR,
  HOSTED_CURSOR_INSTALL_URL,
  HOSTED_MCP_URL,
  HOSTED_TOKEN_PLACEHOLDER,
  HOSTED_VSCODE_INSIDERS_INSTALL_URL,
  HOSTED_VSCODE_INSTALL_URL,
} from '@/lib/mcp/install-links';

function Step({ number, title, children }: { number: number; title: string; children: React.ReactNode }) {
  return (
    <div className="relative pl-12 pb-10 border-l border-amber/20 last:border-0 last:pb-0">
      <div className="absolute left-0 -translate-x-1/2 w-8 h-8 rounded-full bg-amber/20 border border-amber/40 flex items-center justify-center">
        <span className="text-amber font-[family-name:var(--font-mono)] text-sm font-bold">{number}</span>
      </div>
      <h3 className="font-[family-name:var(--font-display)] text-2xl text-text-bright tracking-wider mb-3">{title}</h3>
      <div className="text-text-dim text-sm leading-relaxed space-y-3">{children}</div>
    </div>
  );
}

function CodeBlock({ title, children, lang }: { title?: string; children: string; lang?: string }) {
  return (
    <div className="bg-bg border border-border rounded-[var(--radius-card)] overflow-hidden">
      {title && (
        <div className="bg-card2 border-b border-border px-4 py-2 flex items-center gap-2">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-red/40" />
            <div className="w-3 h-3 rounded-full bg-amber/40" />
            <div className="w-3 h-3 rounded-full bg-green/40" />
          </div>
          <span className="text-text-dim text-xs font-[family-name:var(--font-mono)] ml-2">{title}</span>
          {lang && <span className="text-amber/40 text-xs font-[family-name:var(--font-mono)] ml-auto">{lang}</span>}
        </div>
      )}
      <pre className="p-4 overflow-x-auto text-sm">
        <code className="font-[family-name:var(--font-mono)] text-text">{children}</code>
      </pre>
    </div>
  );
}

function ToolCard({ name, description }: { name: string; description: string }) {
  return (
    <div className="bg-card border border-border rounded-[var(--radius-card)] p-3 flex items-start gap-3">
      <span className="text-green font-[family-name:var(--font-mono)] text-xs mt-0.5 shrink-0">&#9654;</span>
      <div>
        <div className="text-amber font-[family-name:var(--font-mono)] text-sm font-bold">{name}</div>
        <div className="text-text-dim text-xs mt-0.5">{description}</div>
      </div>
    </div>
  );
}

export default function McpSetupPage() {
  return (
    <div className="min-h-screen bg-bg">
      {/* Nav */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-bg/80 backdrop-blur-xl border-b border-border">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-amber/20 border border-amber/40 flex items-center justify-center">
              <span className="text-amber font-bold text-sm">SD</span>
            </div>
            <span className="font-[family-name:var(--font-display)] text-xl tracking-wider text-text-bright">
              SECURITY DETECTIONS
            </span>
          </Link>
          <div className="flex items-center gap-4">
            <Link href="/" className="text-text-dim hover:text-text text-sm transition-colors">Home</Link>
            <Link href="/explore" className="text-text-dim hover:text-text text-sm transition-colors">Explore</Link>
            <a
              href="https://github.com/MHaggis/Security-Detections-MCP"
              target="_blank"
              rel="noopener noreferrer"
              className="bg-amber hover:bg-amber-dim text-bg font-semibold text-sm px-4 py-2 rounded-[var(--radius-button)] transition-colors"
            >
              View on GitHub
            </a>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative pt-28 pb-16 overflow-hidden">
        <div className="absolute inset-0 bg-grid orb-amber" />
        <div className="relative max-w-4xl mx-auto px-6 text-center">
          <div className="inline-flex items-center gap-2 bg-card border border-green/30 rounded-[var(--radius-pill)] px-4 py-1.5 mb-6">
            <span className="w-2 h-2 rounded-full bg-green animate-pulse-slow" />
            <span className="font-[family-name:var(--font-mono)] text-xs text-green uppercase tracking-widest">
              Open Source &middot; Apache 2.0
            </span>
          </div>

          <h1 className="font-[family-name:var(--font-display)] text-5xl md:text-7xl text-text-bright tracking-wide leading-none mb-4">
            RUN IT <span className="text-amber">LOCALLY</span> <span className="text-text-dim">OR</span> <span className="text-green">HOSTED</span>
          </h1>
          <p className="text-text-dim text-lg max-w-2xl mx-auto leading-relaxed">
            The Security Detections MCP server gives your AI assistant direct access to 8,000+ detection rules,
            172 threat actors, and procedure-level coverage analysis. Works with Claude Code, VS Code, Cursor, and any MCP-compatible client.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mt-8">
            <Link
              href="/account/tokens"
              className="bg-green hover:bg-green/80 text-bg font-bold px-8 py-3 rounded-[var(--radius-button)] text-lg transition-colors"
            >
              Get Hosted Token
            </Link>
            <a
              href="https://github.com/MHaggis/Security-Detections-MCP"
              target="_blank"
              rel="noopener noreferrer"
              className="bg-amber hover:bg-amber-dim text-bg font-bold px-8 py-3 rounded-[var(--radius-button)] text-lg transition-colors glow-amber"
            >
              Clone Repository
            </a>
            <a
              href="https://www.npmjs.com/package/security-detections-mcp"
              target="_blank"
              rel="noopener noreferrer"
              className="bg-card hover:bg-card2 border border-border-bright text-text-bright font-semibold px-8 py-3 rounded-[var(--radius-button)] text-lg transition-colors"
            >
              npm Package
            </a>
          </div>
        </div>
      </section>

      {/* Hosted MCP */}
      <section className="py-16 border-t border-border">
        <div className="max-w-3xl mx-auto px-6">
          <div className="flex items-center justify-center gap-2 mb-3">
            <span className="w-2 h-2 rounded-full bg-green animate-pulse-slow" />
            <span className="font-[family-name:var(--font-mono)] text-xs text-green uppercase tracking-widest">
              New &middot; Public Beta
            </span>
          </div>
          <h2 className="font-[family-name:var(--font-display)] text-3xl text-text-bright tracking-wider mb-2 text-center">
            HOSTED MCP — ZERO SETUP
          </h2>
          <p className="text-text-dim text-center mb-10 text-sm max-w-2xl mx-auto">
            Skip the local install. Create an account, generate a token, paste one URL into your MCP client, and start
            querying. Always in sync with the latest detection content.
          </p>

          <div className="space-y-0">
            <Step number={1} title="SIGN IN & GENERATE TOKEN">
              <p>
                Sign in with email or GitHub, then visit{' '}
                <Link href="/account/tokens" className="text-amber hover:underline">
                  /account/tokens
                </Link>
                . Click <span className="text-amber font-bold">Generate</span>, name your token (e.g., &quot;Claude Desktop — laptop&quot;),
                and copy it — it&apos;s shown exactly once.
              </p>
              <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 mt-3">
                <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] mb-2">FREE TIER</div>
                <div className="text-text text-sm">200 calls/day &middot; all read-only tools &middot; all 8,000+ detections</div>
              </div>
            </Step>

            <Step number={2} title="INSTALL IN ONE CLICK">
              <p>Click the button for your client. Replace <code className="text-amber font-[family-name:var(--font-mono)]">sdmcp_YOUR_TOKEN_HERE</code> with the token you just generated (or paste it when the client prompts).</p>

              {/* One-click install buttons */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-4">
                {/* Cursor */}
                <a
                  href={HOSTED_CURSOR_INSTALL_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-between gap-3 bg-card hover:bg-card2 border border-border-bright hover:border-amber/50 rounded-[var(--radius-button)] px-4 py-3 transition-colors"
                >
                  <div>
                    <div className="text-text-bright font-bold text-sm">Cursor</div>
                    <div className="text-text-dim text-xs font-[family-name:var(--font-mono)]">Deeplink install</div>
                  </div>
                  <span className="text-amber font-[family-name:var(--font-mono)] text-xs">INSTALL &rarr;</span>
                </a>

                {/* VS Code */}
                <a
                  href={HOSTED_VSCODE_INSTALL_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-between gap-3 bg-card hover:bg-card2 border border-border-bright hover:border-amber/50 rounded-[var(--radius-button)] px-4 py-3 transition-colors"
                >
                  <div>
                    <div className="text-text-bright font-bold text-sm">VS Code</div>
                    <div className="text-text-dim text-xs font-[family-name:var(--font-mono)]">Deeplink install</div>
                  </div>
                  <span className="text-amber font-[family-name:var(--font-mono)] text-xs">INSTALL &rarr;</span>
                </a>

                {/* VS Code Insiders */}
                <a
                  href={HOSTED_VSCODE_INSIDERS_INSTALL_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-between gap-3 bg-card hover:bg-card2 border border-border hover:border-amber/50 rounded-[var(--radius-button)] px-4 py-3 transition-colors"
                >
                  <div>
                    <div className="text-text-bright font-bold text-sm">VS Code Insiders</div>
                    <div className="text-text-dim text-xs font-[family-name:var(--font-mono)]">Deeplink install</div>
                  </div>
                  <span className="text-amber font-[family-name:var(--font-mono)] text-xs">INSTALL &rarr;</span>
                </a>

                {/* Claude Code */}
                <Link
                  href="/account/tokens"
                  className="flex items-center justify-between gap-3 bg-card hover:bg-card2 border border-border hover:border-amber/50 rounded-[var(--radius-button)] px-4 py-3 transition-colors"
                >
                  <div>
                    <div className="text-text-bright font-bold text-sm">Claude Code</div>
                    <div className="text-text-dim text-xs font-[family-name:var(--font-mono)]">CLI one-liner below</div>
                  </div>
                  <span className="text-amber font-[family-name:var(--font-mono)] text-xs">GET TOKEN &rarr;</span>
                </Link>
              </div>

              {/* Claude Code CLI */}
              <div className="mt-6">
                <div className="text-green font-[family-name:var(--font-mono)] text-sm font-bold mb-2">Claude Code (CLI one-liner)</div>
                <CodeBlock title="Terminal" lang="bash">{`claude mcp add --transport http security-detections ${HOSTED_MCP_URL} --header "Authorization: Bearer ${HOSTED_TOKEN_PLACEHOLDER}"`}</CodeBlock>
              </div>

              {/* Claude Desktop via mcp-remote */}
              <div className="mt-4">
                <div className="text-green font-[family-name:var(--font-mono)] text-sm font-bold mb-2">Claude Desktop (via mcp-remote proxy)</div>
                <p className="text-text-dim text-xs mb-2">
                  Claude Desktop doesn&apos;t speak remote HTTP natively yet — use <code className="text-amber">mcp-remote</code> to bridge stdio to HTTP.
                </p>
                <CodeBlock title="~/Library/Application Support/Claude/claude_desktop_config.json" lang="json">{`{
  "mcpServers": {
    "security-detections": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "${HOSTED_MCP_URL}",
        "--header",
        "Authorization: Bearer ${HOSTED_TOKEN_PLACEHOLDER}"
      ]
    }
  }
}`}</CodeBlock>
              </div>

              {/* OpenAI Codex */}
              <div className="mt-4">
                <div className="text-green font-[family-name:var(--font-mono)] text-sm font-bold mb-2">OpenAI Codex (CLI)</div>
                <CodeBlock title="Terminal" lang="bash">{`export ${HOSTED_CODEX_TOKEN_ENV_VAR}="${HOSTED_TOKEN_PLACEHOLDER}" && codex mcp add security-detections --url ${HOSTED_MCP_URL} --bearer-token-env-var ${HOSTED_CODEX_TOKEN_ENV_VAR}`}</CodeBlock>
                <p className="text-text-dim text-xs mt-2">
                  Persist <code className="text-amber">{HOSTED_CODEX_TOKEN_ENV_VAR}</code> in your shell profile so Codex can read it in future sessions.
                </p>
                <p className="text-text-dim text-xs mt-2">
                  Or edit <code className="text-amber">~/.codex/config.toml</code>:
                </p>
                <CodeBlock title="~/.codex/config.toml" lang="toml">{`[mcp_servers.security-detections]
url = "${HOSTED_MCP_URL}"
bearer_token_env_var = "${HOSTED_CODEX_TOKEN_ENV_VAR}"`}</CodeBlock>
              </div>

              {/* Test with curl */}
              <div className="mt-4">
                <div className="text-green font-[family-name:var(--font-mono)] text-sm font-bold mb-2">Verify with curl</div>
                <CodeBlock title="Terminal" lang="bash">{`curl -X POST ${HOSTED_MCP_URL} -H "Authorization: Bearer ${HOSTED_TOKEN_PLACEHOLDER}" -H "Accept: application/json, text/event-stream" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`}</CodeBlock>
              </div>
            </Step>

            <Step number={3} title="ASK YOUR AI">
              <p>Try these prompts in the client you just configured:</p>
              <div className="space-y-2 mt-2">
                <div className="bg-card border border-green/20 rounded-[var(--radius-card)] px-4 py-3 font-[family-name:var(--font-mono)] text-green text-sm">
                  &quot;What&apos;s our coverage against APT29?&quot;
                </div>
                <div className="bg-card border border-green/20 rounded-[var(--radius-card)] px-4 py-3 font-[family-name:var(--font-mono)] text-green text-sm">
                  &quot;Identify gaps for ransomware and suggest missing detections&quot;
                </div>
                <div className="bg-card border border-green/20 rounded-[var(--radius-card)] px-4 py-3 font-[family-name:var(--font-mono)] text-green text-sm">
                  &quot;Generate a Navigator layer for our Sigma coverage&quot;
                </div>
              </div>
            </Step>
          </div>

          <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 mt-8 text-xs text-text-dim">
            <span className="text-amber font-bold">~25 tools</span> are exposed on the hosted endpoint: search, list by MITRE
            technique/tactic/CVE/process, coverage summary, gap analysis, actor profiles, Navigator layer export. Stateful tools (knowledge
            graph, dynamic tables, custom templates) are local-only for now.
          </div>
        </div>
      </section>

      {/* Quick Start */}
      <section className="py-16 border-t border-border">
        <div className="max-w-3xl mx-auto px-6">
          <h2 className="font-[family-name:var(--font-display)] text-3xl text-text-bright tracking-wider mb-2 text-center">
            QUICK START &mdash; LOCAL
          </h2>
          <p className="text-text-dim text-center mb-10 text-sm">
            Full 81-tool experience with your own detection repos. Up and running in under 10 minutes.
          </p>

          <div className="space-y-0">
            <Step number={1} title="PREREQUISITES">
              <p>Node.js 20+, npm 9+, and git. That&apos;s it.</p>
              <CodeBlock title="Terminal">{`node --version   # v20+
npm --version    # 9+
git --version    # any recent`}</CodeBlock>
            </Step>

            <Step number={2} title="DOWNLOAD DETECTION CONTENT">
              <p>Clone the detection repos you want to index. Start with Sigma if you&apos;re unsure — it&apos;s the most portable.</p>
              <CodeBlock title="Terminal" lang="bash">{`mkdir -p detections && cd detections

# Sigma rules (~3,000+)
git clone --depth 1 --filter=blob:none --sparse \\
  https://github.com/SigmaHQ/sigma.git
cd sigma && git sparse-checkout set rules rules-threat-hunting && cd ..

# Splunk ESCU (~2,000+)
git clone --depth 1 --filter=blob:none --sparse \\
  https://github.com/splunk/security_content.git
cd security_content && git sparse-checkout set detections stories && cd ..

# Elastic (~1,500+)
git clone --depth 1 --filter=blob:none --sparse \\
  https://github.com/elastic/detection-rules.git
cd detection-rules && git sparse-checkout set rules && cd ..

# KQL hunting queries (~400+)
git clone --depth 1 \\
  https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules.git kql-bertjanp

# Sublime Security (~900+)
git clone --depth 1 --filter=blob:none --sparse \\
  https://github.com/sublime-security/sublime-rules.git
cd sublime-rules && git sparse-checkout set detection-rules && cd ..

# CrowdStrike CQL Hub (~139+)
git clone --depth 1 \\
  https://github.com/ByteRay-Labs/Query-Hub.git cql-hub

# MITRE ATT&CK STIX data (172 actors, 691 techniques, 784 software)
git clone --depth 1 \\
  https://github.com/mitre-attack/attack-stix-data.git

cd ..`}</CodeBlock>
            </Step>

            <Step number={3} title="CONFIGURE YOUR CLIENT">
              <p>Pick your IDE and add the MCP config. Replace paths with your actual locations.</p>

              {/* Claude Code */}
              <div className="mt-4">
                <div className="text-amber font-[family-name:var(--font-mono)] text-sm font-bold mb-2">Claude Code</div>
                <CodeBlock title="Terminal" lang="bash">{`claude mcp add security-detections \\
  -e SIGMA_PATHS="/path/to/sigma/rules,/path/to/sigma/rules-threat-hunting" \\
  -e SPLUNK_PATHS="/path/to/security_content/detections" \\
  -e ELASTIC_PATHS="/path/to/detection-rules/rules" \\
  -e KQL_PATHS="/path/to/kql-bertjanp" \\
  -e SUBLIME_PATHS="/path/to/sublime-rules/detection-rules" \\
  -e CQL_HUB_PATHS="/path/to/cql-hub/queries" \\
  -e STORY_PATHS="/path/to/security_content/stories" \\
  -e ATTACK_STIX_PATH="/path/to/attack-stix-data/enterprise-attack/enterprise-attack.json" \\
  -- npx -y security-detections-mcp`}</CodeBlock>
              </div>

              {/* Cursor */}
              <div className="mt-4">
                <div className="text-amber font-[family-name:var(--font-mono)] text-sm font-bold mb-2">Cursor IDE</div>
                <CodeBlock title="~/.cursor/mcp.json" lang="json">{`{
  "mcpServers": {
    "security-detections": {
      "command": "npx",
      "args": ["-y", "security-detections-mcp"],
      "env": {
        "SIGMA_PATHS": "/path/to/sigma/rules,/path/to/sigma/rules-threat-hunting",
        "SPLUNK_PATHS": "/path/to/security_content/detections",
        "ELASTIC_PATHS": "/path/to/detection-rules/rules",
        "KQL_PATHS": "/path/to/kql-bertjanp",
        "SUBLIME_PATHS": "/path/to/sublime-rules/detection-rules",
        "CQL_HUB_PATHS": "/path/to/cql-hub/queries",
        "STORY_PATHS": "/path/to/security_content/stories",
        "ATTACK_STIX_PATH": "/path/to/attack-stix-data/enterprise-attack/enterprise-attack.json"
      }
    }
  }
}`}</CodeBlock>
              </div>

              {/* VS Code */}
              <div className="mt-4">
                <div className="text-amber font-[family-name:var(--font-mono)] text-sm font-bold mb-2">VS Code</div>
                <CodeBlock title="~/.vscode/mcp.json" lang="json">{`{
  "servers": {
    "security-detections": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "security-detections-mcp"],
      "env": {
        "SIGMA_PATHS": "/path/to/sigma/rules,/path/to/sigma/rules-threat-hunting",
        "SPLUNK_PATHS": "/path/to/security_content/detections",
        "ELASTIC_PATHS": "/path/to/detection-rules/rules",
        "KQL_PATHS": "/path/to/kql-bertjanp",
        "SUBLIME_PATHS": "/path/to/sublime-rules/detection-rules",
        "CQL_HUB_PATHS": "/path/to/cql-hub/queries",
        "STORY_PATHS": "/path/to/security_content/stories",
        "ATTACK_STIX_PATH": "/path/to/attack-stix-data/enterprise-attack/enterprise-attack.json"
      }
    }
  }
}`}</CodeBlock>
              </div>
            </Step>

            <Step number={4} title="ASK YOUR FIRST QUESTION">
              <p>Open your AI client and try one of these prompts:</p>
              <div className="space-y-2 mt-2">
                <div className="bg-card border border-blue/20 rounded-[var(--radius-card)] px-4 py-3 font-[family-name:var(--font-mono)] text-blue text-sm">
                  &quot;What&apos;s our coverage against APT29?&quot;
                </div>
                <div className="bg-card border border-blue/20 rounded-[var(--radius-card)] px-4 py-3 font-[family-name:var(--font-mono)] text-blue text-sm">
                  &quot;Show me all detections for T1059.001 PowerShell&quot;
                </div>
                <div className="bg-card border border-blue/20 rounded-[var(--radius-card)] px-4 py-3 font-[family-name:var(--font-mono)] text-blue text-sm">
                  &quot;Compare Sigma vs Splunk coverage for credential access&quot;
                </div>
                <div className="bg-card border border-blue/20 rounded-[var(--radius-card)] px-4 py-3 font-[family-name:var(--font-mono)] text-blue text-sm">
                  &quot;What procedures does T1003.001 LSASS Memory cover?&quot;
                </div>
              </div>
            </Step>
          </div>
        </div>
      </section>

      {/* Available Tools */}
      <section className="py-16 border-t border-border">
        <div className="max-w-4xl mx-auto px-6">
          <h2 className="font-[family-name:var(--font-display)] text-3xl text-text-bright tracking-wider mb-2 text-center">
            81 TOOLS
          </h2>
          <p className="text-text-dim text-center mb-10 text-sm">
            The MCP server exposes these capabilities to your AI assistant.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <h3 className="font-[family-name:var(--font-display)] text-lg text-amber tracking-wider mb-3">SEARCH &amp; BROWSE</h3>
              <div className="space-y-2">
                <ToolCard name="search_detections" description="Full-text search across all 8,000+ detection rules" />
                <ToolCard name="list_by_mitre" description="Get all detections for a MITRE technique ID" />
                <ToolCard name="get_detection" description="Full detection rule with query, metadata, and references" />
                <ToolCard name="list_sources" description="Browse detections by source (Sigma, Splunk, Elastic...)" />
                <ToolCard name="list_by_severity" description="Filter by critical, high, medium, low" />
              </div>
            </div>

            <div>
              <h3 className="font-[family-name:var(--font-display)] text-lg text-amber tracking-wider mb-3">COVERAGE ANALYSIS</h3>
              <div className="space-y-2">
                <ToolCard name="coverage_by_tactic" description="Heatmap of detection coverage across all 14 tactics" />
                <ToolCard name="coverage_gaps" description="Find uncovered MITRE techniques — prioritized by risk" />
                <ToolCard name="compare_sources" description="Cross-source coverage comparison for a topic or technique" />
                <ToolCard name="analyze_procedure_coverage" description="Procedure-level breakdown: which behaviors are actually detected" />
                <ToolCard name="generate_navigator_layer" description="Export ATT&CK Navigator JSON layers" />
              </div>
            </div>

            <div>
              <h3 className="font-[family-name:var(--font-display)] text-lg text-amber tracking-wider mb-3">THREAT ACTORS</h3>
              <div className="space-y-2">
                <ToolCard name="analyze_actor_coverage" description="Coverage % against a specific APT group" />
                <ToolCard name="list_actors" description="Browse all 172 MITRE ATT&CK threat actors" />
                <ToolCard name="compare_actor_coverage" description="Side-by-side comparison of multiple actors" />
                <ToolCard name="get_actor_profile" description="Full dossier: description, aliases, techniques, software" />
              </div>
            </div>

            <div>
              <h3 className="font-[family-name:var(--font-display)] text-lg text-amber tracking-wider mb-3">INTELLIGENCE</h3>
              <div className="space-y-2">
                <ToolCard name="analyze_threat_report" description="Extract TTPs from a threat report, map to ATT&CK" />
                <ToolCard name="search_by_cve" description="Find detections targeting specific CVEs" />
                <ToolCard name="search_by_process" description="Find detections monitoring a specific process name" />
                <ToolCard name="compare_procedure_coverage" description="Cross-source matrix of procedure coverage" />
              </div>
            </div>
          </div>

          <p className="text-text-dim text-center text-xs mt-6 font-[family-name:var(--font-mono)]">
            + 60 more tools for Sigma, Splunk, Elastic, KQL, Sublime, and CrowdStrike CQL specific operations
          </p>
        </div>
      </section>

      {/* Web vs MCP comparison */}
      <section className="py-16 border-t border-border">
        <div className="max-w-4xl mx-auto px-6">
          <h2 className="font-[family-name:var(--font-display)] text-3xl text-text-bright tracking-wider mb-8 text-center">
            MCP vs WEB APP
          </h2>

          <div className="grid md:grid-cols-2 gap-6">
            <div className="bg-card border border-amber/30 rounded-[var(--radius-card)] p-6">
              <h3 className="font-[family-name:var(--font-display)] text-2xl text-amber tracking-wider mb-4">LOCAL MCP</h3>
              <ul className="space-y-2 text-sm text-text-dim">
                <li className="flex items-start gap-2"><span className="text-green mt-0.5">&#10003;</span> <span>81 tools — full power, no restrictions</span></li>
                <li className="flex items-start gap-2"><span className="text-green mt-0.5">&#10003;</span> <span>Works in Claude Code, Cursor, VS Code</span></li>
                <li className="flex items-start gap-2"><span className="text-green mt-0.5">&#10003;</span> <span>Your data stays local — nothing leaves your machine</span></li>
                <li className="flex items-start gap-2"><span className="text-green mt-0.5">&#10003;</span> <span>Unlimited queries, no rate limits</span></li>
                <li className="flex items-start gap-2"><span className="text-green mt-0.5">&#10003;</span> <span>Use any AI model your client supports</span></li>
                <li className="flex items-start gap-2"><span className="text-green mt-0.5">&#10003;</span> <span>Write custom rules and index immediately</span></li>
                <li className="flex items-start gap-2"><span className="text-text-dim mt-0.5">&#8212;</span> <span>Requires local setup (~10 min)</span></li>
                <li className="flex items-start gap-2"><span className="text-text-dim mt-0.5">&#8212;</span> <span>Need to manually update detection repos</span></li>
              </ul>
            </div>

            <div className="bg-card border border-blue/30 rounded-[var(--radius-card)] p-6">
              <h3 className="font-[family-name:var(--font-display)] text-2xl text-blue tracking-wider mb-4">WEB APP</h3>
              <ul className="space-y-2 text-sm text-text-dim">
                <li className="flex items-start gap-2"><span className="text-green mt-0.5">&#10003;</span> <span>Zero setup — just open your browser</span></li>
                <li className="flex items-start gap-2"><span className="text-green mt-0.5">&#10003;</span> <span>Always up-to-date — nightly sync</span></li>
                <li className="flex items-start gap-2"><span className="text-green mt-0.5">&#10003;</span> <span>AI chat with structured data-driven responses</span></li>
                <li className="flex items-start gap-2"><span className="text-green mt-0.5">&#10003;</span> <span>Visual coverage dashboards and heatmaps</span></li>
                <li className="flex items-start gap-2"><span className="text-green mt-0.5">&#10003;</span> <span>Share with team members — no install required</span></li>
                <li className="flex items-start gap-2"><span className="text-green mt-0.5">&#10003;</span> <span>Threat report URL analysis</span></li>
                <li className="flex items-start gap-2"><span className="text-text-dim mt-0.5">&#8212;</span> <span>Free tier: basic AI models, 20 chats/day</span></li>
                <li className="flex items-start gap-2"><span className="text-text-dim mt-0.5">&#8212;</span> <span>Full tool set via AI chat, not direct calls</span></li>
              </ul>
            </div>
          </div>

          <p className="text-text-dim text-center text-sm mt-6">
            Use both. The MCP server is the power tool. The web app is for quick lookups, sharing, and when you don&apos;t have your IDE open.
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
