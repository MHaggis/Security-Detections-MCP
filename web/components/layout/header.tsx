'use client';

import { usePathname, useRouter } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';
import type { User } from '@supabase/supabase-js';

interface HeaderProps {
  user: User | null;
  profile: { tier?: string; display_name?: string } | null;
}

export function Header({ user, profile }: HeaderProps) {
  const pathname = usePathname();
  const router = useRouter();
  const supabase = createClient();

  // Get section name from path
  const section = pathname.split('/')[1] || 'dashboard';
  const sectionName = section.charAt(0).toUpperCase() + section.slice(1);

  async function handleSignOut() {
    await supabase.auth.signOut();
    router.push('/');
    router.refresh();
  }

  return (
    <header className="h-16 bg-card/50 backdrop-blur-sm border-b border-border flex items-center justify-between px-6 sticky top-0 z-30">
      {/* Left: breadcrumb */}
      <div className="flex items-center gap-2">
        <span className="font-[family-name:var(--font-display)] text-xl tracking-wider text-text-bright">
          {sectionName.toUpperCase()}
        </span>
      </div>

      {/* Right: user actions */}
      <div className="flex items-center gap-4">
        {profile?.tier === 'pro' && (
          <span className="bg-amber/20 text-amber text-xs font-[family-name:var(--font-mono)] font-bold px-2 py-0.5 rounded-[var(--radius-pill)] border border-amber/30">
            PRO
          </span>
        )}
        {user ? (
          <button
            onClick={handleSignOut}
            className="text-text-dim hover:text-text text-sm transition-colors"
          >
            Sign Out
          </button>
        ) : (
          <a
            href="/login"
            className="text-amber hover:text-amber/80 text-sm font-medium transition-colors"
          >
            Sign In
          </a>
        )}
      </div>
    </header>
  );
}
