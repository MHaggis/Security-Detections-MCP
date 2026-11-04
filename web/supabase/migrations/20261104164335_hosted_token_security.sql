-- The account routes verify the user then write through service_role. Direct
-- Data API access must not let token owners change accounting or revive tokens.
REVOKE INSERT, UPDATE, DELETE ON public.mcp_tokens FROM PUBLIC, anon, authenticated;
DROP POLICY IF EXISTS mcp_tokens_insert_own ON public.mcp_tokens;
DROP POLICY IF EXISTS mcp_tokens_update_own ON public.mcp_tokens;

-- Profile fallback upsert needs only these three columns. Account settings,
-- encrypted provider keys, billing and admin changes already use server routes.
REVOKE INSERT, UPDATE, DELETE ON public.profiles FROM PUBLIC, anon, authenticated;
-- Clear any historical column grants as well as the table-level grants.
DO $$
DECLARE t text; cols text;
BEGIN
  FOREACH t IN ARRAY ARRAY['profiles', 'mcp_tokens'] LOOP
    SELECT string_agg(quote_ident(attname), ', ') INTO cols
    FROM pg_attribute WHERE attrelid = ('public.' || t)::regclass
      AND attnum > 0 AND NOT attisdropped;
    EXECUTE format('REVOKE INSERT (%s), UPDATE (%s) ON public.%I FROM PUBLIC, anon, authenticated', cols, cols, t);
  END LOOP;
END $$;
GRANT INSERT (id, display_name, avatar_url), UPDATE (id, display_name, avatar_url)
  ON public.profiles TO authenticated;
DROP POLICY IF EXISTS profiles_update_restricted ON public.profiles;
DROP POLICY IF EXISTS profiles_update ON public.profiles;
CREATE POLICY profiles_update_restricted ON public.profiles FOR UPDATE TO authenticated
  USING ((SELECT auth.uid()) = id) WITH CHECK ((SELECT auth.uid()) = id);

-- RLS does not apply to TRUNCATE. These roles are Data API clients, never
-- maintenance operators. Preserve service_role and owner privileges.
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM PUBLIC, anon, authenticated;
-- Global defaults must be revoked: schema-specific REVOKE cannot subtract a
-- global default grant. postgres owns application migrations in this project.
ALTER DEFAULT PRIVILEGES FOR ROLE postgres REVOKE TRUNCATE ON TABLES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE TRUNCATE ON TABLES FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public.increment_mcp_call(p_token_hash text)
RETURNS json
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_user_id uuid;
  v_token public.mcp_tokens%ROWTYPE;
  v_tier text;
  v_limit integer;
  v_user_calls bigint;
BEGIN
  SELECT user_id INTO v_user_id FROM public.mcp_tokens WHERE token_hash = p_token_hash;
  IF NOT FOUND THEN
    RETURN json_build_object('ok', false, 'reason', 'invalid_token');
  END IF;

  -- One stable lock per user serializes calls across existing AND new tokens.
  -- Tier changes use this same row lock. Fail closed if the profile is absent.
  SELECT tier INTO v_tier FROM public.profiles WHERE id = v_user_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN json_build_object('ok', false, 'reason', 'blocked');
  END IF;
  SELECT * INTO v_token FROM public.mcp_tokens
    WHERE token_hash = p_token_hash AND user_id = v_user_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN json_build_object('ok', false, 'reason', 'invalid_token');
  END IF;
  IF v_token.revoked_at IS NOT NULL THEN
    RETURN json_build_object('ok', false, 'reason', 'revoked');
  END IF;
  IF v_tier IS NULL OR v_tier = 'blocked' THEN
    RETURN json_build_object('ok', false, 'reason', 'blocked');
  END IF;
  v_limit := CASE v_tier WHEN 'admin' THEN 100000 WHEN 'pro' THEN 5000 ELSE 200 END;
  UPDATE public.mcp_tokens SET calls_today = 0, calls_reset_at = CURRENT_DATE
    WHERE user_id = v_user_id AND calls_reset_at < CURRENT_DATE;
  SELECT COALESCE(sum(calls_today), 0) INTO v_user_calls
    FROM public.mcp_tokens WHERE user_id = v_user_id;
  IF v_user_calls >= v_limit THEN
    RETURN json_build_object('ok', false, 'reason', 'quota_exceeded',
      'tier', v_tier, 'limit', v_limit, 'remaining', 0);
  END IF;
  UPDATE public.mcp_tokens SET calls_today = calls_today + 1,
    last_used_at = now(), total_calls = total_calls + 1 WHERE id = v_token.id;
  RETURN json_build_object('ok', true, 'token_id', v_token.id,
    'user_id', v_user_id, 'tier', v_tier, 'limit', v_limit,
    'remaining', v_limit - (v_user_calls + 1));
END;
$$;
REVOKE ALL ON FUNCTION public.increment_mcp_call(text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.increment_mcp_call(text) TO service_role;

-- The chat route also calls its accounting RPC through service_role. A public
-- caller must not pick another user's ID or supply an arbitrary quota limit.
ALTER FUNCTION public.increment_chat_count(uuid, integer) SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION public.increment_chat_count(uuid, integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.increment_chat_count(uuid, integer) TO service_role;
NOTIFY pgrst, 'reload schema';
