import { createClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import Link from 'next/link';
import { AdminUserList } from './admin-user-list';

export const dynamic = 'force-dynamic';

export default async function AdminPage() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) redirect('/login');

  // Check admin role
  const { data: profile } = await supabase
    .from('profiles')
    .select('role')
    .eq('id', user.id)
    .single();

  if (profile?.role !== 'admin') {
    return (
      <div className="max-w-2xl mx-auto text-center py-20">
        <div className="text-4xl mb-4">&#128274;</div>
        <h1 className="font-[family-name:var(--font-display)] text-3xl text-text-bright tracking-wider mb-2">
          ACCESS DENIED
        </h1>
        <p className="text-text-dim">This page is restricted to administrators.</p>
        <Link href="/dashboard" className="text-amber hover:text-amber-dim text-sm mt-4 inline-block transition-colors">
          &larr; Back to Dashboard
        </Link>
      </div>
    );
  }

  // Fetch all users (using service role via RPC or direct query)
  // Note: We need service role to see all profiles. Use createServiceClient.
  const { createServiceClient } = await import('@/lib/supabase/server');
  const serviceClient = await createServiceClient();

  const { data: users } = await serviceClient
    .from('profiles')
    .select('id, display_name, tier, role, chat_count_today, created_at')
    .order('created_at', { ascending: false });

  // Get emails from auth.users (service role can access this)
  const { data: authUsers } = await serviceClient.auth.admin.listUsers();

  // Merge email data
  const userList = (users || []).map(u => {
    const authUser = authUsers?.users?.find(au => au.id === u.id);
    return {
      ...u,
      email: authUser?.email || 'unknown',
    };
  });

  return (
    <div className="max-w-4xl mx-auto animate-slide-up">
      <Link href="/account" className="text-text-dim hover:text-text text-sm mb-4 inline-block transition-colors">
        &larr; Back to Account
      </Link>

      <h1 className="font-[family-name:var(--font-display)] text-4xl text-text-bright tracking-wider mb-2">
        ADMIN PANEL
      </h1>
      <p className="text-text-dim text-sm mb-8">
        Manage users, tiers, and access.
      </p>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-8">
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
          <div className="font-[family-name:var(--font-display)] text-3xl text-amber">{userList.length}</div>
          <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] uppercase mt-1">Total Users</div>
        </div>
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
          <div className="font-[family-name:var(--font-display)] text-3xl text-green">
            {userList.filter(u => u.tier === 'pro').length}
          </div>
          <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] uppercase mt-1">Pro Users</div>
        </div>
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
          <div className="font-[family-name:var(--font-display)] text-3xl text-blue">
            {userList.filter(u => u.tier === 'free').length}
          </div>
          <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] uppercase mt-1">Free Users</div>
        </div>
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
          <div className="font-[family-name:var(--font-display)] text-3xl text-red">
            {userList.filter(u => u.tier === 'blocked').length}
          </div>
          <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] uppercase mt-1">Blocked</div>
        </div>
      </div>

      {/* User list */}
      <AdminUserList users={userList} />
    </div>
  );
}
