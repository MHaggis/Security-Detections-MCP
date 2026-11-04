-- Production-semantic MCP auth/quota smoke. Run with psql -X -v ON_ERROR_STOP=1 -f.
-- Creates one fresh synthetic auth user in a transaction and ALWAYS rolls back
-- on normal completion. On an assertion/error, disconnect or explicitly ROLLBACK.
-- No real user/token is selected or modified. No usable plaintext token is made.
-- This is sequential behavior evidence; it does not prove concurrent isolation.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL statement_timeout = '20s';
SET LOCAL lock_timeout = '3s';
SET LOCAL timezone = 'UTC';

DO $test$
DECLARE
  fixture_user uuid := gen_random_uuid();
  fixture_token uuid := gen_random_uuid();
  previous_token uuid := gen_random_uuid();
  fixture_hash text := 'rollback-fixture-' || gen_random_uuid()::text;
  previous_hash text := 'rollback-fixture-' || gen_random_uuid()::text;
  result jsonb;
  value_int integer;
  bypass boolean := false;
BEGIN
  -- Refuse unexpected signup hooks: tests must not cause nontransactional side effects.
  IF EXISTS (
    SELECT 1 FROM pg_trigger t
    WHERE t.tgrelid = 'auth.users'::regclass AND NOT t.tgisinternal
      AND t.tgfoid <> 'public.handle_new_user()'::regprocedure
  ) THEN
    RAISE EXCEPTION 'Unexpected auth.users trigger: inspect before running fixture';
  END IF;
  IF has_function_privilege('anon', 'public.increment_mcp_call(text)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'public.increment_mcp_call(text)', 'EXECUTE')
     OR NOT has_function_privilege('service_role', 'public.increment_mcp_call(text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'MCP RPC role grants differ from service-only contract';
  END IF;

  INSERT INTO auth.users(id, email, raw_user_meta_data, raw_app_meta_data)
  VALUES (fixture_user, 'rollback-' || fixture_user::text || '@example.invalid', '{}'::jsonb, '{}'::jsonb);
  IF NOT EXISTS (SELECT 1 FROM public.profiles WHERE id = fixture_user AND tier = 'free') THEN
    RAISE EXCEPTION 'Synthetic signup did not create free profile';
  END IF;
  INSERT INTO public.mcp_tokens(id,user_id,token_hash,name,prefix)
  VALUES (fixture_token,fixture_user,fixture_hash,'rollback smoke','test-only'),
         (previous_token,fixture_user,previous_hash,'rollback previous','test-only');

  EXECUTE 'SET LOCAL ROLE service_role';
  result := public.increment_mcp_call('missing-' || gen_random_uuid()::text)::jsonb;
  IF result->>'reason' IS DISTINCT FROM 'invalid_token' THEN RAISE EXCEPTION 'Invalid token accepted'; END IF;
  result := public.increment_mcp_call(fixture_hash)::jsonb;
  IF result->>'ok' IS DISTINCT FROM 'true' OR result->>'remaining' IS DISTINCT FROM '199'
      OR result->>'user_id' IS DISTINCT FROM fixture_user::text THEN
    RAISE EXCEPTION 'First free call result mismatch';
  END IF;
  EXECUTE 'RESET ROLE';
  SELECT calls_today INTO value_int FROM public.mcp_tokens WHERE id=fixture_token;
  IF value_int <> 1 THEN RAISE EXCEPTION 'First call counter not persisted'; END IF;

  UPDATE public.mcp_tokens SET revoked_at=now(),calls_today=198 WHERE id=previous_token;
  EXECUTE 'SET LOCAL ROLE service_role';
  result := public.increment_mcp_call(previous_hash)::jsonb;
  IF result->>'reason' IS DISTINCT FROM 'revoked' THEN RAISE EXCEPTION 'Revoked token accepted'; END IF;
  result := public.increment_mcp_call(fixture_hash)::jsonb;
  IF result->>'ok' IS DISTINCT FROM 'true' OR result->>'remaining' IS DISTINCT FROM '0' THEN
    RAISE EXCEPTION 'Final allowed user-level call failed';
  END IF;
  result := public.increment_mcp_call(fixture_hash)::jsonb;
  IF result->>'reason' IS DISTINCT FROM 'quota_exceeded' THEN RAISE EXCEPTION 'User quota bypassed'; END IF;
  EXECUTE 'RESET ROLE';
  SELECT calls_today INTO value_int FROM public.mcp_tokens WHERE id=fixture_token;
  IF value_int <> 2 THEN RAISE EXCEPTION 'Rejected call changed counter'; END IF;

  UPDATE public.mcp_tokens SET calls_reset_at=CURRENT_DATE-1 WHERE user_id=fixture_user;
  EXECUTE 'SET LOCAL ROLE service_role';
  result := public.increment_mcp_call(fixture_hash)::jsonb;
  IF result->>'ok' IS DISTINCT FROM 'true' OR result->>'remaining' IS DISTINCT FROM '199' THEN
    RAISE EXCEPTION 'Daily reset failed';
  END IF;
  EXECUTE 'RESET ROLE';
  SELECT calls_today INTO value_int FROM public.mcp_tokens WHERE id=previous_token;
  IF value_int <> 0 THEN RAISE EXCEPTION 'Revoked-token counter not reset'; END IF;

  UPDATE public.profiles SET tier='blocked' WHERE id=fixture_user;
  EXECUTE 'SET LOCAL ROLE service_role';
  result := public.increment_mcp_call(fixture_hash)::jsonb;
  IF result->>'reason' IS DISTINCT FROM 'blocked' THEN RAISE EXCEPTION 'Blocked account accepted'; END IF;
  EXECUTE 'RESET ROLE';
  RAISE NOTICE 'PASS: service-only RPC, invalid/revoked token, final call, user quota including revoked tokens, reset, blocked account';

  -- Probe direct authenticated writes using ONLY this synthetic account.
  -- A failure is caught so the script reaches ROLLBACK and reports the finding.
  PERFORM set_config('request.jwt.claim.sub',fixture_user::text,true);
  PERFORM set_config('request.jwt.claims',jsonb_build_object('sub',fixture_user,'role','authenticated')::text,true);
  BEGIN
    EXECUTE 'SET LOCAL ROLE authenticated';
    UPDATE public.mcp_tokens SET calls_today=0,revoked_at=NULL WHERE id=previous_token;
    GET DIAGNOSTICS value_int = ROW_COUNT;
    bypass := value_int = 1;
    EXECUTE 'RESET ROLE';
  EXCEPTION WHEN insufficient_privilege THEN
    EXECUTE 'RESET ROLE';
    bypass := false;
  END;
  IF bypass THEN
    RAISE WARNING 'FAIL SECURITY: authenticated owner can reset quota and un-revoke token through direct table UPDATE';
  ELSE
    RAISE NOTICE 'PASS: authenticated owner cannot directly reset quota/un-revoke token';
  END IF;
END
$test$;
ROLLBACK;
