'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import type { User } from '@supabase/supabase-js';

interface SidebarProps {
  user: User | null;
  profile: { display_name?: string; tier?: string; role?: string } | null;
}

const navItems = [
  { href: '/dashboard', label: 'Dashboard', icon: '&#9638;' },
  { href: '/explore', label: 'Explore', icon: '&#128269;' },
  { href: '/coverage', label: 'Coverage', icon: '&#128200;' },
  { href: '/reports', label: 'Reports', icon: '&#128196;' },
  { href: '/chat', label: 'Chat', icon: '&#128172;' },
  { href: '/explore/actor', label: 'Actors', icon: '&#128123;' },
  { href: '/coverage/compare', label: 'Compare', icon: '&#8644;' },
];

export function Sidebar({ user, profile }: SidebarProps) {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 bottom-0 w-16 lg:w-60 bg-card border-r border-border flex flex-col z-40">
      {/* Logo */}
      <div className="h-16 flex items-center px-4 border-b border-border">
        <Link href="/" className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-amber/20 border border-amber/40 flex items-center justify-center shrink-0">
            <span className="text-amber font-bold text-sm">SD</span>
          </div>
          <span className="font-[family-name:var(--font-display)] text-lg tracking-wider text-text-bright hidden lg:block">
            DETECTIONS
          </span>
        </Link>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 px-2 space-y-1">
        {navItems.map((item) => {
          const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-[var(--radius-card)] text-sm transition-colors group ${
                isActive
                  ? 'bg-amber/10 text-amber border-l-2 border-amber'
                  : 'text-text-dim hover:text-text hover:bg-card2'
              }`}
            >
              <span className="text-lg shrink-0 w-6 text-center" dangerouslySetInnerHTML={{ __html: item.icon }} />
              <span className="hidden lg:block font-medium">{item.label}</span>
            </Link>
          );
        })}
        {profile?.role === 'admin' && (
          <Link
            href="/account/admin"
            className={`flex items-center gap-3 px-3 py-2.5 rounded-[var(--radius-card)] text-sm transition-colors group mt-4 border-t border-border pt-4 ${
              pathname === '/account/admin'
                ? 'bg-amber/10 text-amber border-l-2 border-amber'
                : 'text-amber/60 hover:text-amber hover:bg-card2'
            }`}
          >
            <span className="text-lg shrink-0 w-6 text-center">&#9881;</span>
            <span className="hidden lg:block font-medium">Admin</span>
          </Link>
        )}
      </nav>

      {/* User section */}
      <div className="border-t border-border p-3">
        {user ? (
          <Link
            href="/account"
            className="flex items-center gap-3 px-2 py-2 rounded-[var(--radius-card)] text-sm text-text-dim hover:text-text hover:bg-card2 transition-colors"
          >
            <div className="w-8 h-8 rounded-full bg-amber/20 border border-amber/40 flex items-center justify-center shrink-0">
              <span className="text-amber text-xs font-bold">
                {(profile?.display_name || user?.email || '?')[0].toUpperCase()}
              </span>
            </div>
            <div className="hidden lg:block overflow-hidden">
              <div className="text-text-bright text-sm truncate">{profile?.display_name || 'User'}</div>
              <div className="text-text-dim text-xs truncate font-[family-name:var(--font-mono)]">
                {profile?.tier === 'pro' ? 'PRO' : 'FREE'}
              </div>
            </div>
          </Link>
        ) : (
          <Link
            href="/login"
            className="flex items-center gap-3 px-2 py-2 rounded-[var(--radius-card)] text-sm text-text-dim hover:text-amber hover:bg-card2 transition-colors"
          >
            <div className="w-8 h-8 rounded-full bg-card2 border border-border flex items-center justify-center shrink-0">
              <span className="text-text-dim text-xs">&#8594;</span>
            </div>
            <span className="hidden lg:block font-medium">Sign In</span>
          </Link>
        )}
      </div>
    </aside>
  );
}
