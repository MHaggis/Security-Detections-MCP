/**
 * MCP token management API.
 *
 *   GET    /api/account/tokens           — list the signed-in user's tokens (metadata only, no secrets)
 *   POST   /api/account/tokens           — generate a new token (plaintext returned ONCE)
 *   DELETE /api/account/tokens?id=<uuid> — revoke a token
 */

import { NextRequest } from 'next/server';
import { createClient, createServiceClient } from '@/lib/supabase/server';
import { generateToken } from '@/lib/mcp/tokens';

const MAX_TOKENS_PER_USER = 10;
const MAX_NAME_LENGTH = 64;

export async function GET() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  const service = await createServiceClient();
  const { data, error } = await service
    .from('mcp_tokens')
    .select('id, name, prefix, created_at, last_used_at, revoked_at, calls_today, calls_reset_at, total_calls')
    .eq('user_id', user.id)
    .order('created_at', { ascending: false });

  if (error) return Response.json({ error: error.message }, { status: 500 });
  return Response.json({ tokens: data ?? [] });
}

export async function POST(request: NextRequest) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  let body: { name?: unknown };
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const rawName = typeof body.name === 'string' ? body.name.trim() : '';
  if (!rawName) return Response.json({ error: 'Token name is required' }, { status: 400 });
  if (rawName.length > MAX_NAME_LENGTH) {
    return Response.json({ error: `Token name too long (max ${MAX_NAME_LENGTH} chars)` }, { status: 400 });
  }

  const service = await createServiceClient();

  // Enforce per-user token cap (active tokens only)
  const { count, error: countError } = await service
    .from('mcp_tokens')
    .select('id', { count: 'exact', head: true })
    .eq('user_id', user.id)
    .is('revoked_at', null);
  if (countError) return Response.json({ error: countError.message }, { status: 500 });
  if ((count ?? 0) >= MAX_TOKENS_PER_USER) {
    return Response.json(
      { error: `Token limit reached (${MAX_TOKENS_PER_USER} active). Revoke an existing token first.` },
      { status: 400 },
    );
  }

  const { token, hash, prefix } = generateToken();
  const { data, error } = await service
    .from('mcp_tokens')
    .insert({
      user_id: user.id,
      token_hash: hash,
      name: rawName,
      prefix,
    })
    .select('id, name, prefix, created_at')
    .single();

  if (error) return Response.json({ error: error.message }, { status: 500 });

  // IMPORTANT: plaintext token returned ONCE here. Not stored anywhere.
  return Response.json({
    id: data.id,
    name: data.name,
    prefix: data.prefix,
    created_at: data.created_at,
    token,
    hint: 'Copy this token now — it will not be shown again.',
  });
}

export async function DELETE(request: NextRequest) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  const { searchParams } = new URL(request.url);
  const id = searchParams.get('id');
  if (!id) return Response.json({ error: 'id query param required' }, { status: 400 });

  const service = await createServiceClient();
  const { error } = await service
    .from('mcp_tokens')
    .update({ revoked_at: new Date().toISOString() })
    .eq('id', id)
    .eq('user_id', user.id);

  if (error) return Response.json({ error: error.message }, { status: 500 });
  return Response.json({ success: true });
}
