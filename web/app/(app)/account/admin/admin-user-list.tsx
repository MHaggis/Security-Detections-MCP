'use client';

import { useState } from 'react';
import { createClient } from '@/lib/supabase/client';

interface UserRow {
  id: string;
  email: string;
  display_name: string | null;
  tier: string;
  role: string;
  chat_count_today: number;
  created_at: string;
}

export function AdminUserList({ users: initialUsers }: { users: UserRow[] }) {
  const [users, setUsers] = useState(initialUsers);
  const [updating, setUpdating] = useState<string | null>(null);
  const supabase = createClient();

  async function updateTier(userId: string, newTier: string) {
    setUpdating(userId);
    const { error } = await supabase
      .from('profiles')
      .update({ tier: newTier })
      .eq('id', userId);

    if (!error) {
      setUsers(prev => prev.map(u =>
        u.id === userId ? { ...u, tier: newTier } : u
      ));
    }
    setUpdating(null);
  }

  function tierBadge(tier: string) {
    switch (tier) {
      case 'admin': return 'bg-amber/20 text-amber border-amber/30';
      case 'pro': return 'bg-green/20 text-green border-green/30';
      case 'blocked': return 'bg-red/20 text-red border-red/30';
      default: return 'bg-card2 text-text-dim border-border';
    }
  }

  return (
    <div className="space-y-2">
      {users.map(user => (
        <div
          key={user.id}
          className="bg-card border border-border rounded-[var(--radius-card)] p-4 flex items-center justify-between gap-4"
        >
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="text-text-bright text-sm font-medium truncate">
                {user.display_name || 'No Name'}
              </span>
              <span className={`text-xs font-[family-name:var(--font-mono)] px-2 py-0.5 rounded-[var(--radius-tag)] border ${tierBadge(user.tier)}`}>
                {user.tier.toUpperCase()}
              </span>
              {user.role === 'admin' && (
                <span className="text-xs font-[family-name:var(--font-mono)] px-2 py-0.5 rounded-[var(--radius-tag)] border bg-amber/10 text-amber border-amber/30">
                  ADMIN
                </span>
              )}
            </div>
            <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] mt-1">
              {user.email}
            </div>
            <div className="text-text-dim/50 text-xs mt-1">
              Joined {new Date(user.created_at).toLocaleDateString()} &middot; {user.chat_count_today} chats today
            </div>
          </div>

          {/* Tier actions */}
          <div className="flex items-center gap-1.5 shrink-0">
            {user.tier !== 'pro' && user.role !== 'admin' && (
              <button
                onClick={() => updateTier(user.id, 'pro')}
                disabled={updating === user.id}
                className="text-xs bg-green/10 hover:bg-green/20 text-green border border-green/30 px-2.5 py-1 rounded-[var(--radius-button)] transition-colors disabled:opacity-50"
              >
                Pro
              </button>
            )}
            {user.tier !== 'free' && user.role !== 'admin' && (
              <button
                onClick={() => updateTier(user.id, 'free')}
                disabled={updating === user.id}
                className="text-xs bg-blue/10 hover:bg-blue/20 text-blue border border-blue/30 px-2.5 py-1 rounded-[var(--radius-button)] transition-colors disabled:opacity-50"
              >
                Free
              </button>
            )}
            {user.tier !== 'blocked' && user.role !== 'admin' && (
              <button
                onClick={() => updateTier(user.id, 'blocked')}
                disabled={updating === user.id}
                className="text-xs bg-red/10 hover:bg-red/20 text-red border border-red/30 px-2.5 py-1 rounded-[var(--radius-button)] transition-colors disabled:opacity-50"
              >
                Block
              </button>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
