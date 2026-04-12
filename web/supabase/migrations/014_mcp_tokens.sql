-- =============================================================================
-- 014_mcp_tokens.sql — Hosted MCP token table + atomic rate-limit RPC
-- Enables the hosted Streamable HTTP MCP endpoint at /api/mcp/[transport].
-- Users generate tokens from /account/tokens; we only store sha256(token).
-- =============================================================================

CREATE TABLE IF NOT EXISTS mcp_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  prefix TEXT NOT NULL,                            -- first 12 chars of token for display (e.g. "sdmcp_ab12cd")
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  calls_today INTEGER NOT NULL DEFAULT 0,
  calls_reset_at DATE NOT NULL DEFAULT CURRENT_DATE,
  total_calls BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_mcp_tokens_user ON mcp_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_mcp_tokens_hash ON mcp_tokens(token_hash) WHERE revoked_at IS NULL;

-- ─── RLS: users can only see and revoke their own tokens ──────────────────────
-- Note: the MCP route handler uses the SERVICE ROLE client to look up token
-- hashes and call increment_mcp_call(), so RLS here protects the UI only.

ALTER TABLE mcp_tokens ENABLE ROW LEVEL SECURITY;

CREATE POLICY mcp_tokens_select_own ON mcp_tokens
  FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY mcp_tokens_insert_own ON mcp_tokens
  FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Updates allowed only to set revoked_at (revocation). Fine-grained column
-- restrictions aren't in Postgres RLS, so we rely on the /api/account/tokens
-- route handler (which uses the service client) to only set revoked_at.
CREATE POLICY mcp_tokens_update_own ON mcp_tokens
  FOR UPDATE USING (auth.uid() = user_id);

-- ─── Atomic rate-limit RPC ────────────────────────────────────────────────────
-- Called by the MCP route handler (service role) on every tool call.
-- Returns JSON: { ok, token_id, user_id, remaining, tier } or { ok: false, reason }.
-- Does everything in one round-trip: lookup by hash, check revocation, check
-- daily quota, increment counter, update last_used_at.

CREATE OR REPLACE FUNCTION increment_mcp_call(p_token_hash TEXT)
RETURNS JSON AS $$
DECLARE
  v_token mcp_tokens%ROWTYPE;
  v_tier TEXT;
  v_limit INT;
BEGIN
  -- Lock the token row for atomic update
  SELECT * INTO v_token
  FROM mcp_tokens
  WHERE token_hash = p_token_hash
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN json_build_object('ok', false, 'reason', 'invalid_token');
  END IF;

  IF v_token.revoked_at IS NOT NULL THEN
    RETURN json_build_object('ok', false, 'reason', 'revoked');
  END IF;

  -- Resolve limit from user tier
  SELECT tier INTO v_tier FROM profiles WHERE id = v_token.user_id;
  v_tier := COALESCE(v_tier, 'free');

  IF v_tier = 'blocked' THEN
    RETURN json_build_object('ok', false, 'reason', 'blocked');
  END IF;

  v_limit := CASE v_tier
    WHEN 'admin' THEN 100000
    WHEN 'pro' THEN 5000
    ELSE 200                                         -- free
  END;

  -- Reset daily counter if new day
  IF v_token.calls_reset_at < CURRENT_DATE THEN
    UPDATE mcp_tokens
      SET calls_today = 1,
          calls_reset_at = CURRENT_DATE,
          last_used_at = now(),
          total_calls = total_calls + 1
      WHERE id = v_token.id;
    RETURN json_build_object(
      'ok', true,
      'token_id', v_token.id,
      'user_id', v_token.user_id,
      'tier', v_tier,
      'limit', v_limit,
      'remaining', v_limit - 1
    );
  END IF;

  -- Quota check
  IF v_token.calls_today >= v_limit THEN
    RETURN json_build_object(
      'ok', false,
      'reason', 'quota_exceeded',
      'tier', v_tier,
      'limit', v_limit,
      'remaining', 0
    );
  END IF;

  -- Increment
  UPDATE mcp_tokens
    SET calls_today = calls_today + 1,
        last_used_at = now(),
        total_calls = total_calls + 1
    WHERE id = v_token.id;

  RETURN json_build_object(
    'ok', true,
    'token_id', v_token.id,
    'user_id', v_token.user_id,
    'tier', v_tier,
    'limit', v_limit,
    'remaining', v_limit - (v_token.calls_today + 1)
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Only the service role should call this; deny public/anon execution.
REVOKE ALL ON FUNCTION increment_mcp_call(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION increment_mcp_call(TEXT) FROM anon;
REVOKE ALL ON FUNCTION increment_mcp_call(TEXT) FROM authenticated;
GRANT EXECUTE ON FUNCTION increment_mcp_call(TEXT) TO service_role;
