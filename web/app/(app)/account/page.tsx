import { createClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import Link from 'next/link';
import { AccountForm } from './account-form';

export default async function AccountPage() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) redirect('/login');

  const { data: profile } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', user.id)
    .single();

  return (
    <div className="max-w-2xl mx-auto animate-slide-up">
      <h1 className="font-[family-name:var(--font-display)] text-4xl text-text-bright tracking-wider mb-8">
        ACCOUNT
      </h1>

      {/* Profile Info */}
      <div className="bg-card border border-border rounded-[var(--radius-card)] p-6 mb-6">
        <h2 className="font-[family-name:var(--font-display)] text-xl text-text-bright tracking-wider mb-4">
          PROFILE
        </h2>
        <div className="space-y-3">
          <div>
            <span className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider">Email</span>
            <p className="text-text font-[family-name:var(--font-mono)] text-sm">{user.email}</p>
          </div>
          <div>
            <span className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider">Tier</span>
            <p className={`font-[family-name:var(--font-mono)] text-sm font-bold ${profile?.tier === 'pro' ? 'text-amber' : 'text-text-dim'}`}>
              {profile?.tier?.toUpperCase() || 'FREE'}
            </p>
          </div>
          <div>
            <span className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider">Messages Today</span>
            <p className="text-text font-[family-name:var(--font-mono)] text-sm">
              {profile?.chat_count_today || 0} / {profile?.tier === 'pro' ? '500' : '20'}
            </p>
          </div>
          {(profile?.tier === 'pro' || profile?.tier === 'admin') && (
            <div>
              <span className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider">Monthly AI Usage</span>
              <div className="flex items-center gap-3 mt-1">
                <div className="flex-1 h-2 bg-bg2 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${(profile?.openrouter_usage_usd || 0) / (profile?.openrouter_usage_limit_usd || 25) > 0.8 ? 'bg-red' : 'bg-green'}`}
                    style={{ width: `${Math.min(100, ((profile?.openrouter_usage_usd || 0) / (profile?.openrouter_usage_limit_usd || 25)) * 100)}%` }}
                  />
                </div>
                <span className="text-text font-[family-name:var(--font-mono)] text-sm">
                  ${(profile?.openrouter_usage_usd || 0).toFixed(2)} / ${(profile?.openrouter_usage_limit_usd || 25).toFixed(2)}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Subscription */}
      <div className="bg-card border border-border rounded-[var(--radius-card)] p-6 mb-6">
        <h2 className="font-[family-name:var(--font-display)] text-xl text-text-bright tracking-wider mb-4">
          SUBSCRIPTION
        </h2>
        {profile?.tier === 'pro' ? (
          <div>
            <p className="text-green text-sm mb-4">You have an active Pro subscription.</p>
          </div>
        ) : (
          <div>
            <p className="text-text-dim text-sm mb-4">
              Upgrade to Pro for unlimited AI chats with frontier models.
            </p>
            <a
              href="/account/billing"
              className="inline-block bg-amber hover:bg-amber-dim text-bg font-bold px-6 py-2 rounded-[var(--radius-button)] transition-colors"
            >
              Upgrade to Pro
            </a>
          </div>
        )}
      </div>

      {/* Hosted MCP Tokens */}
      <div className="bg-card border border-border rounded-[var(--radius-card)] p-6 mb-6">
        <h2 className="font-[family-name:var(--font-display)] text-xl text-text-bright tracking-wider mb-2">
          HOSTED MCP TOKENS
        </h2>
        <p className="text-text-dim text-sm mb-4">
          Generate a token to connect your AI assistant (Claude Desktop, Cursor, Claude Code) directly to{' '}
          <code className="text-amber font-[family-name:var(--font-mono)]">detect.michaelhaag.org/api/mcp/http</code>.
          No install required.
        </p>
        <Link
          href="/account/tokens"
          className="inline-block bg-card2 hover:bg-card border border-border-bright text-text-bright font-semibold px-6 py-2 rounded-[var(--radius-button)] transition-colors"
        >
          Manage Tokens &rarr;
        </Link>
      </div>

      {/* API Keys */}
      <div className="bg-card border border-border rounded-[var(--radius-card)] p-6">
        <h2 className="font-[family-name:var(--font-display)] text-xl text-text-bright tracking-wider mb-2">
          API KEYS (BYOK)
        </h2>
        <p className="text-text-dim text-sm mb-4">
          Bring your own API key to use frontier models at your own cost, no subscription needed.
        </p>
        <AccountForm
          userId={user.id}
          displayName={profile?.display_name || ''}
          hasClaudeKey={!!profile?.claude_api_key_encrypted}
          hasOpenaiKey={!!profile?.openai_api_key_encrypted}
          hasOpenrouterKey={!!profile?.openrouter_api_key_encrypted}
          preferredModel={profile?.preferred_model || 'auto'}
        />
      </div>
    </div>
  );
}
