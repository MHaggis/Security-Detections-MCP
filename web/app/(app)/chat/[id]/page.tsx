import { createClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';

export default async function ChatConversationPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) redirect('/login');

  // Verify the conversation belongs to the user
  const { data: conv } = await supabase
    .from('conversations')
    .select('id')
    .eq('id', id)
    .eq('user_id', user.id)
    .single();

  if (!conv) redirect('/chat');

  // The actual chat loading happens client-side in the chat page component
  // Just redirect to /chat with the conversation ID as a query param
  redirect(`/chat?c=${id}`);
}
