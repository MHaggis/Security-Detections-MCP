import { createClient, createServiceClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import Link from 'next/link';
import { TokensManager } from './tokens-manager';
import { CopyBlock } from './copy-block';

export const dynamic = 'force-dynamic';

type TokenRow = {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  calls_today: number;
  calls_reset_at: string;
  total_calls: number;
};

export default async function TokensPage() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect('/login?redirect=/account/tokens');

  // Use service role — the cookie client can also read via RLS, but we
  // mirror the account/page.tsx pattern for consistency.
  const service = await createServiceClient();
  const { data: tokens } = await service
    .from('mcp_tokens')
    .select('id, name, prefix, created_at, last_used_at, revoked_at, calls_today, calls_reset_at, total_calls')
    .eq('user_id', user.id)
    .order('created_at', { ascending: false });

  const { data: profile } = await service
    .from('profiles')
    .select('tier')
    .eq('id', user.id)
    .single();

  const tier = (profile?.tier as string | undefined) ?? 'free';
  const dailyLimit = tier === 'admin' ? 100000 : tier === 'pro' ? 5000 : 200;

  return (
    <div className="max-w-3xl mx-auto animate-slide-up">
      <div className="flex items-center gap-3 mb-2">
        <Link href="/account" className="text-text-dim hover:text-text text-sm font-[family-name:var(--font-mono)]">
          &larr; Account
        </Link>
      </div>
      <h1 className="font-[family-name:var(--font-display)] text-4xl text-text-bright tracking-wider mb-2">
        MCP TOKENS
      </h1>
      <p className="text-text-dim text-sm mb-8">
        Generate tokens to connect your AI client to the hosted Security Detections MCP at{' '}
        <code className="bg-bg2 px-2 py-0.5 rounded font-[family-name:var(--font-mono)] text-amber">
          detect.michaelhaag.org/api/mcp/http
        </code>
      </p>

      {/* Tier / quota */}
      <div className="bg-card border border-border rounded-[var(--radius-card)] p-6 mb-6">
        <h2 className="font-[family-name:var(--font-display)] text-lg text-text-bright tracking-wider mb-3">
          YOUR QUOTA
        </h2>
        <div className="grid grid-cols-3 gap-4">
          <div>
            <div className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider">Tier</div>
            <div className={`font-[family-name:var(--font-mono)] font-bold ${tier === 'pro' || tier === 'admin' ? 'text-amber' : 'text-text'}`}>
              {tier.toUpperCase()}
            </div>
          </div>
          <div>
            <div className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider">Daily Limit</div>
            <div className="font-[family-name:var(--font-mono)] text-text font-bold">
              {dailyLimit.toLocaleString()} calls
            </div>
          </div>
          <div>
            <div className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider">Transport</div>
            <div className="font-[family-name:var(--font-mono)] text-text">Streamable HTTP</div>
          </div>
        </div>
      </div>

      <TokensManager initialTokens={(tokens as TokenRow[]) ?? []} dailyLimit={dailyLimit} />

      {/* Quick start */}
      <div className="bg-card border border-border rounded-[var(--radius-card)] p-6 mt-6">
        <h2 className="font-[family-name:var(--font-display)] text-lg text-text-bright tracking-wider mb-3">
          CONFIGURE YOUR CLIENT
        </h2>

        {/* One-click install buttons */}
        <div className="grid grid-cols-2 gap-2 mb-5">
          <a
            href="https://cursor.com/en/install-mcp?name=security-detections-hosted&config=eyJ1cmwiOiJodHRwczovL2RldGVjdC5taWNoYWVsaGFhZy5vcmcvYXBpL21jcC9odHRwIiwiaGVhZGVycyI6eyJBdXRob3JpemF0aW9uIjoiQmVhcmVyIHNkbWNwX1lPVVJfVE9LRU5fSEVSRSJ9fQ=="
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-between bg-bg2 hover:bg-card2 border border-border hover:border-amber/50 rounded px-3 py-2 transition-colors"
          >
            <span className="text-text-bright font-bold text-xs">Install in Cursor</span>
            <span className="text-amber text-xs">&rarr;</span>
          </a>
          <a
            href="vscode:mcp/install?%7B%22name%22%3A%22security-detections%22%2C%22type%22%3A%22http%22%2C%22url%22%3A%22https%3A%2F%2Fdetect.michaelhaag.org%2Fapi%2Fmcp%2Fhttp%22%2C%22headers%22%3A%7B%22Authorization%22%3A%22Bearer%20sdmcp_YOUR_TOKEN_HERE%22%7D%7D"
            className="flex items-center justify-between bg-bg2 hover:bg-card2 border border-border hover:border-amber/50 rounded px-3 py-2 transition-colors"
          >
            <span className="text-text-bright font-bold text-xs">Install in VS Code</span>
            <span className="text-amber text-xs">&rarr;</span>
          </a>
        </div>

        <div className="mb-5">
          <div className="text-amber font-[family-name:var(--font-mono)] text-xs font-bold mb-2">Claude Code (CLI)</div>
          <CopyBlock>{`claude mcp add --transport http security-detections https://detect.michaelhaag.org/api/mcp/http --header "Authorization: Bearer sdmcp_..."`}</CopyBlock>
        </div>

        <div className="mb-5">
          <div className="text-amber font-[family-name:var(--font-mono)] text-xs font-bold mb-2">
            Claude Desktop (via mcp-remote)
          </div>
          <CopyBlock>{`{
  "mcpServers": {
    "security-detections": {
      "command": "npx",
      "args": ["-y", "mcp-remote",
        "https://detect.michaelhaag.org/api/mcp/http",
        "--header", "Authorization: Bearer sdmcp_..."]
    }
  }
}`}</CopyBlock>
        </div>

        <div className="mb-5">
          <div className="text-amber font-[family-name:var(--font-mono)] text-xs font-bold mb-2">OpenAI Codex (CLI)</div>
          <CopyBlock>{`codex mcp add security-detections --transport http https://detect.michaelhaag.org/api/mcp/http --header "Authorization: Bearer sdmcp_..."`}</CopyBlock>
        </div>

        <div>
          <div className="text-amber font-[family-name:var(--font-mono)] text-xs font-bold mb-2">Test with curl</div>
          <CopyBlock>{`curl -X POST https://detect.michaelhaag.org/api/mcp/http -H "Authorization: Bearer sdmcp_..." -H "Accept: application/json, text/event-stream" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`}</CopyBlock>
        </div>
      </div>
    </div>
  );
}
