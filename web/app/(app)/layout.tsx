import { createClient } from '@/lib/supabase/server';
import { Sidebar } from '@/components/layout/sidebar';
import { Header } from '@/components/layout/header';

// All app pages require auth/Supabase — prevent static generation
export const dynamic = 'force-dynamic';

export default async function AppLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  // Get profile data
  let profile = null;
  if (user) {
    const { data, error } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', user.id)
      .single();
    if (data) {
      profile = data;
    } else if (error) {
      // Profile might not exist yet (race condition with trigger) — create it
      console.warn('Profile query failed, attempting upsert:', error.message);
      const { data: upserted } = await supabase
        .from('profiles')
        .upsert({
          id: user.id,
          display_name: user.user_metadata?.full_name || user.user_metadata?.user_name || user.email?.split('@')[0] || 'User',
          avatar_url: user.user_metadata?.avatar_url || null,
        }, { onConflict: 'id' })
        .select()
        .single();
      profile = upserted;
    }
  }

  return (
    <div className="min-h-screen bg-bg flex">
      <Sidebar user={user} profile={profile} />
      <div className="flex-1 flex flex-col ml-16 lg:ml-60">
        <Header user={user} profile={profile} />
        <main className="flex-1 p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
