import { NextRequest } from 'next/server';
import { createClient, createServiceClient } from '@/lib/supabase/server';
import { encrypt } from '@/lib/crypto';

export async function POST(request: NextRequest) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { display_name, preferred_model, claude_key, openai_key, openrouter_key } = body;

    const updates: Record<string, string | null> = {};

    // Display name — plain text, length-validated
    if (display_name !== undefined) {
      if (display_name && display_name.length > 100) {
        return Response.json({ error: 'Display name too long (max 100 chars)' }, { status: 400 });
      }
      updates.display_name = display_name || null;
    }

    // Preferred model — validated
    if (preferred_model !== undefined) {
      const validModels = ['auto', 'claude', 'claude-opus', 'gpt', 'gpt-codex'];
      if (!validModels.includes(preferred_model)) {
        return Response.json({ error: 'Invalid model selection' }, { status: 400 });
      }
      updates.preferred_model = preferred_model;
    }

    // API keys — validate format, encrypt before storing
    if (claude_key !== undefined) {
      if (claude_key === null) {
        updates.claude_api_key_encrypted = null;
      } else {
        if (!claude_key.startsWith('sk-ant-')) {
          return Response.json({ error: 'Claude API key must start with sk-ant-' }, { status: 400 });
        }
        updates.claude_api_key_encrypted = encrypt(claude_key);
      }
    }

    if (openai_key !== undefined) {
      if (openai_key === null) {
        updates.openai_api_key_encrypted = null;
      } else {
        if (!openai_key.startsWith('sk-')) {
          return Response.json({ error: 'OpenAI API key must start with sk-' }, { status: 400 });
        }
        updates.openai_api_key_encrypted = encrypt(openai_key);
      }
    }

    if (openrouter_key !== undefined) {
      if (openrouter_key === null) {
        updates.openrouter_api_key_encrypted = null;
      } else {
        if (!openrouter_key.startsWith('sk-or-')) {
          return Response.json({ error: 'OpenRouter API key must start with sk-or-' }, { status: 400 });
        }
        updates.openrouter_api_key_encrypted = encrypt(openrouter_key);
      }
    }

    if (Object.keys(updates).length === 0) {
      return Response.json({ error: 'No updates provided' }, { status: 400 });
    }

    // Use service client so the RLS tier/role restriction doesn't block non-sensitive field updates
    const serviceClient = await createServiceClient();
    const { error } = await serviceClient
      .from('profiles')
      .update(updates)
      .eq('id', user.id);

    if (error) {
      return Response.json({ error: error.message }, { status: 500 });
    }

    return Response.json({ success: true });
  } catch (error) {
    return Response.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    );
  }
}
