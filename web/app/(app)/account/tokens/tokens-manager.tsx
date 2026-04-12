'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

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

interface Props {
  initialTokens: TokenRow[];
  dailyLimit: number;
}

export function TokensManager({ initialTokens, dailyLimit }: Props) {
  const router = useRouter();
  const [tokens, setTokens] = useState<TokenRow[]>(initialTokens);
  const [name, setName] = useState('');
  const [creating, setCreating] = useState(false);
  const [newToken, setNewToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function createToken() {
    setError(null);
    if (!name.trim()) {
      setError('Token name is required.');
      return;
    }
    setCreating(true);
    try {
      const res = await fetch('/api/account/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Failed to create token');
        return;
      }
      setNewToken(data.token);
      setTokens((prev) => [
        {
          id: data.id,
          name: data.name,
          prefix: data.prefix,
          created_at: data.created_at,
          last_used_at: null,
          revoked_at: null,
          calls_today: 0,
          calls_reset_at: new Date().toISOString().slice(0, 10),
          total_calls: 0,
        },
        ...prev,
      ]);
      setName('');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error');
    } finally {
      setCreating(false);
    }
  }

  async function revokeToken(id: string) {
    if (!confirm('Revoke this token? Clients using it will lose access immediately.')) return;
    const res = await fetch(`/api/account/tokens?id=${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (res.ok) {
      setTokens((prev) => prev.map((t) => (t.id === id ? { ...t, revoked_at: new Date().toISOString() } : t)));
      router.refresh();
    } else {
      const data = await res.json().catch(() => ({}));
      setError(data.error || 'Failed to revoke');
    }
  }

  async function copyToken() {
    if (!newToken) return;
    await navigator.clipboard.writeText(newToken);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function dismissNewToken() {
    setNewToken(null);
    setCopied(false);
  }

  return (
    <div>
      {/* Create form */}
      <div className="bg-card border border-border rounded-[var(--radius-card)] p-6 mb-6">
        <h2 className="font-[family-name:var(--font-display)] text-lg text-text-bright tracking-wider mb-3">
          CREATE TOKEN
        </h2>
        <div className="flex gap-2">
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g., Claude Desktop — laptop"
            maxLength={64}
            className="flex-1 bg-bg2 border border-border focus:border-amber/50 rounded-[var(--radius-button)] px-4 py-2.5 text-text placeholder:text-text-dim/50 outline-none font-[family-name:var(--font-mono)] text-sm"
          />
          <button
            onClick={createToken}
            disabled={creating || !name.trim()}
            className="bg-amber hover:bg-amber-dim disabled:opacity-50 text-bg font-bold px-5 py-2 rounded-[var(--radius-button)] transition-colors text-sm"
          >
            {creating ? 'Creating...' : 'Generate'}
          </button>
        </div>
        {error && <p className="text-red text-sm mt-2">{error}</p>}
      </div>

      {/* Reveal dialog (shown once after creation) */}
      {newToken && (
        <div className="bg-card border border-green/40 rounded-[var(--radius-card)] p-6 mb-6">
          <div className="flex items-start justify-between mb-3">
            <div>
              <h2 className="font-[family-name:var(--font-display)] text-lg text-green tracking-wider">
                TOKEN CREATED
              </h2>
              <p className="text-text-dim text-xs mt-1">
                Copy this token now. It will not be shown again — revoke and regenerate if you lose it.
              </p>
            </div>
            <button
              onClick={dismissNewToken}
              className="text-text-dim hover:text-text text-xs font-[family-name:var(--font-mono)] uppercase"
            >
              Dismiss
            </button>
          </div>
          <div className="bg-bg2 border border-border rounded p-3 font-[family-name:var(--font-mono)] text-xs break-all text-amber">
            {newToken}
          </div>
          <button
            onClick={copyToken}
            className="mt-3 bg-green/20 hover:bg-green/30 border border-green/40 text-green font-[family-name:var(--font-mono)] text-xs px-4 py-1.5 rounded transition-colors"
          >
            {copied ? 'COPIED!' : 'COPY TO CLIPBOARD'}
          </button>
        </div>
      )}

      {/* Token list */}
      <div className="bg-card border border-border rounded-[var(--radius-card)] p-6">
        <h2 className="font-[family-name:var(--font-display)] text-lg text-text-bright tracking-wider mb-4">
          ACTIVE TOKENS
        </h2>
        {tokens.length === 0 ? (
          <p className="text-text-dim text-sm font-[family-name:var(--font-mono)]">
            No tokens yet. Generate one above to get started.
          </p>
        ) : (
          <div className="space-y-3">
            {tokens.map((t) => {
              const revoked = !!t.revoked_at;
              const pct = Math.min(100, Math.round((t.calls_today / dailyLimit) * 100));
              return (
                <div
                  key={t.id}
                  className={`border rounded p-4 ${revoked ? 'border-border/40 opacity-50' : 'border-border'}`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-[family-name:var(--font-mono)] text-text text-sm font-bold truncate">
                          {t.name}
                        </span>
                        {revoked && (
                          <span className="text-red text-xs font-[family-name:var(--font-mono)] uppercase">revoked</span>
                        )}
                      </div>
                      <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] mt-1">
                        {t.prefix}
                        <span className="opacity-50">...</span>
                      </div>
                      <div className="text-text-dim text-xs mt-2 flex gap-4 flex-wrap">
                        <span>Created {new Date(t.created_at).toLocaleDateString()}</span>
                        <span>
                          Last used{' '}
                          {t.last_used_at ? new Date(t.last_used_at).toLocaleDateString() : 'never'}
                        </span>
                        <span>{t.total_calls.toLocaleString()} total calls</span>
                      </div>
                    </div>
                    {!revoked && (
                      <button
                        onClick={() => revokeToken(t.id)}
                        className="text-red hover:text-red-dim text-xs font-[family-name:var(--font-mono)] uppercase px-2 py-1 shrink-0"
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                  {!revoked && (
                    <div className="mt-3">
                      <div className="flex items-center justify-between text-xs text-text-dim mb-1">
                        <span className="font-[family-name:var(--font-mono)]">TODAY</span>
                        <span className="font-[family-name:var(--font-mono)]">
                          {t.calls_today} / {dailyLimit}
                        </span>
                      </div>
                      <div className="h-1.5 bg-bg2 rounded-full overflow-hidden">
                        <div
                          className={`h-full ${pct > 90 ? 'bg-red' : pct > 70 ? 'bg-amber' : 'bg-green'}`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
