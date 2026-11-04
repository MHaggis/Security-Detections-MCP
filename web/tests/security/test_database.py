#!/usr/bin/env python3
"""Disposable native PostgreSQL security integration tests. Never uses a remote DB.
Run: PG_BIN=/path/to/postgresql/bin python3 web/tests/security/test_database.py
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]
PG = Path(os.environ.get('PG_BIN', '/opt/homebrew/opt/postgresql@17/bin'))
USER = '00000000-0000-4000-8000-000000000001'
OTHER = '00000000-0000-4000-8000-000000000002'

class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='sdmcp-security-')
        cls.path = Path(cls.tmp.name)
        cls.env = {**os.environ, 'PGHOST': str(cls.path), 'PGPORT': '54385', 'PGUSER': 'postgres', 'PGDATABASE': 'postgres'}
        subprocess.run([str(PG/'initdb'), '-D', str(cls.path/'db'), '-U', 'postgres', '-A', 'trust'], check=True, stdout=subprocess.DEVNULL)
        subprocess.run([str(PG/'pg_ctl'), '-D', str(cls.path/'db'), '-l', str(cls.path/'server.log'), '-o', f"-k {cls.path} -p 54385 -c listen_addresses=''", '-w', 'start'], check=True, stdout=subprocess.DEVNULL)
        cls.sql("""CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role BYPASSRLS;
          CREATE SCHEMA auth; CREATE TABLE auth.users(id uuid PRIMARY KEY, email text, raw_user_meta_data jsonb DEFAULT '{}');
          CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT nullif(current_setting('request.jwt.claim.sub', true),'')::uuid $$;
          GRANT USAGE ON SCHEMA public,auth TO anon,authenticated,service_role;
          ALTER DEFAULT PRIVILEGES GRANT ALL ON TABLES TO anon,authenticated,service_role;
          ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT TRUNCATE ON TABLES TO PUBLIC;
        """)
        migrations = ROOT/'web/supabase/migrations'
        for name in ['001_schema.sql','002_rls_and_functions.sql','012_security_hardening.sql','013_atomic_rate_limit.sql','014_mcp_tokens.sql']:
            cls.sql((migrations/name).read_text())
        cls.sql('GRANT UPDATE (calls_today) ON public.mcp_tokens TO PUBLIC; GRANT UPDATE (tier) ON public.profiles TO authenticated;')
        migration = migrations/'20261104164335_hosted_token_security.sql'
        cls.sql(migration.read_text())
        cls.sql(migration.read_text()) # repeat safely preserves policies/grants
        cls.sql(f"INSERT INTO auth.users(id,email) VALUES ('{USER}','one@example.invalid'),('{OTHER}','two@example.invalid');")

    @classmethod
    def tearDownClass(cls):
        subprocess.run([str(PG/'pg_ctl'), '-D', str(cls.path/'db'), '-m','immediate','-w','stop'], check=True, stdout=subprocess.DEVNULL)
        cls.tmp.cleanup()

    @classmethod
    def sql(cls, sql, fail=False):
        r = subprocess.run([str(PG/'psql'), '-XqAt', '-v', 'ON_ERROR_STOP=1'], input=sql, text=True, capture_output=True, env=cls.env)
        if fail:
            if r.returncode == 0: raise AssertionError('Unexpected SQL success: '+sql)
            if not ('permission denied' in r.stderr or 'row-level security' in r.stderr): raise AssertionError(r.stderr)
        elif r.returncode: raise AssertionError(r.stderr)
        return r.stdout.strip()

    def setUp(self):
        self.sql(f"DELETE FROM public.mcp_tokens; UPDATE public.profiles SET tier='free',role='user',chat_count_today=0,chat_count_reset_at=now() WHERE id='{USER}'; INSERT INTO public.mcp_tokens(user_id,token_hash,name,prefix) VALUES ('{USER}','hash-one','test','test');")

    def as_user(self, query):
        return f"SET ROLE authenticated; SET request.jwt.claim.sub='{USER}'; {query}"

    def call(self, token='hash-one'):
        return json.loads(self.sql(f"SET ROLE service_role; SELECT public.increment_mcp_call('{token}');"))

    def test_owner_reads_but_cannot_mutate_token_accounting(self):
        self.assertEqual(self.sql(self.as_user('SELECT count(*) FROM public.mcp_tokens;')), '1')
        for assignment in ['calls_today=0', 'calls_reset_at=current_date-1', "token_hash='replacement'", 'revoked_at=NULL', 'user_id=gen_random_uuid()']:
            self.sql(self.as_user('UPDATE public.mcp_tokens SET '+assignment+';'), fail=True)
        self.sql(self.as_user(f"INSERT INTO public.mcp_tokens(user_id,token_hash,name,prefix,calls_today) VALUES('{USER}','x','x','x',-200);"), fail=True)
        self.sql(self.as_user('DELETE FROM public.mcp_tokens;'), fail=True)
        self.assertEqual(self.sql(f"SET ROLE authenticated; SET request.jwt.claim.sub='{OTHER}'; SELECT count(*) FROM public.mcp_tokens;"),'0')

    def test_profile_fallback_and_settings_are_safe(self):
        self.sql(self.as_user(f"INSERT INTO public.profiles(id,display_name,avatar_url) VALUES('{USER}','New name',NULL) ON CONFLICT(id) DO UPDATE SET id=excluded.id,display_name=excluded.display_name,avatar_url=excluded.avatar_url RETURNING id;"))
        for assignment in ["tier='admin'", "role='admin'", 'chat_count_today=0', 'openrouter_usage_limit_usd=9999', 'chat_count_reset_at=now()', "stripe_customer_id='other'"]:
            self.sql(self.as_user('UPDATE public.profiles SET '+assignment+f" WHERE id='{USER}';"), fail=True)
        self.sql(self.as_user(f"INSERT INTO public.profiles(id,tier) VALUES('{USER}','admin') ON CONFLICT(id) DO UPDATE SET tier=excluded.tier;"), fail=True)
        self.sql(self.as_user(f"UPDATE public.profiles SET id='{OTHER}' WHERE id='{USER}';"), fail=True)
        self.sql(f"SET ROLE service_role; UPDATE public.profiles SET preferred_model='claude',claude_api_key_encrypted='test-ciphertext' WHERE id='{USER}';")
        self.assertEqual(self.sql(f"SELECT tier || ':' || role FROM public.profiles WHERE id='{USER}';"),'free:user')

    def test_no_public_truncate_or_rpc(self):
        for role in ['anon','authenticated']:
            for table in ['mcp_tokens','profiles','detections','stories']:
                self.sql(f'SET ROLE {role}; TRUNCATE public.{table} CASCADE;', fail=True)
            self.sql(f"SET ROLE {role}; SELECT public.increment_mcp_call('hash-one');",fail=True)
            self.sql(f"SET ROLE {role}; SELECT public.increment_chat_count('{USER}',999999);",fail=True)
        self.sql('CREATE TABLE public.future_catalog(id integer);')
        self.sql('SET ROLE authenticated; TRUNCATE public.future_catalog;',fail=True)
        self.sql('DROP TABLE public.future_catalog;')
        self.assertEqual(self.sql("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND (has_table_privilege('anon',c.oid,'TRUNCATE') OR has_table_privilege('authenticated',c.oid,'TRUNCATE'));"),'0')

    def test_quota_revocation_block_reset_and_service_management(self):
        self.assertEqual(self.call('absent')['reason'],'invalid_token')
        self.assertEqual(self.call()['remaining'],199)
        self.sql("SET ROLE service_role; UPDATE public.mcp_tokens SET calls_today=199;")
        self.assertEqual(self.call()['remaining'],0)
        self.assertEqual(self.call()['reason'],'quota_exceeded')
        self.sql("SET ROLE service_role; UPDATE public.mcp_tokens SET calls_reset_at=current_date-1;")
        self.assertEqual(self.call()['remaining'],199)
        self.sql(f"UPDATE public.profiles SET tier='blocked' WHERE id='{USER}';")
        self.assertEqual(self.call()['reason'],'blocked')
        self.sql("SET ROLE service_role; UPDATE public.mcp_tokens SET revoked_at=now();")
        self.assertEqual(self.call()['reason'],'revoked')
        self.sql(f"SET ROLE service_role; INSERT INTO public.mcp_tokens(user_id,token_hash,name,prefix) VALUES('{USER}','hash-two','replacement','test');")
        self.sql(f"UPDATE public.profiles SET tier='free' WHERE id='{USER}'; UPDATE public.mcp_tokens SET calls_today=200 WHERE token_hash='hash-one';")
        self.assertEqual(self.call('hash-two')['reason'],'quota_exceeded')

    def test_missing_profile_and_fallback_defaults(self):
        self.sql(f"DELETE FROM public.profiles WHERE id='{USER}';")
        self.assertEqual(self.call()['reason'], 'blocked')
        self.sql(self.as_user(f"INSERT INTO public.profiles(id,display_name,avatar_url) VALUES('{USER}','Fallback',NULL) ON CONFLICT(id) DO UPDATE SET id=excluded.id,display_name=excluded.display_name,avatar_url=excluded.avatar_url;"))
        self.assertEqual(self.sql(f"SELECT tier || ':' || role FROM public.profiles WHERE id='{USER}';"),'free:user')
        self.assertEqual(self.call()['remaining'],199)

    def test_temp_schema_cannot_shadow_accounting(self):
        result = self.sql(f"""SET ROLE service_role;
          CREATE TEMP TABLE profiles (id uuid,chat_count_today integer,chat_count_reset_at timestamptz);
          INSERT INTO pg_temp.profiles VALUES ('{USER}',100,now());
          SELECT public.increment_chat_count('{USER}',20);
          SELECT chat_count_today FROM pg_temp.profiles;
          SELECT chat_count_today FROM public.profiles WHERE id='{USER}';
        """)
        self.assertEqual(result.splitlines(), ['1','100','1'])

    def test_parallel_final_quota_call(self):
        self.sql(f"UPDATE public.mcp_tokens SET calls_today=199; INSERT INTO public.mcp_tokens(user_id,token_hash,name,prefix) SELECT '{USER}', 'parallel-' || i, 'test', 'test' FROM generate_series(0,7) i;")
        processes = [subprocess.Popen([str(PG/'psql'),'-XqAt','-v','ON_ERROR_STOP=1','-c',f"SET ROLE service_role; SELECT public.increment_mcp_call('parallel-{i}');"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=self.env) for i in range(8)]
        results = []
        for p in processes:
            out,err = p.communicate(timeout=10)
            self.assertEqual(p.returncode,0,err)
            results.append(json.loads(out.strip()))
        self.assertEqual(sum(x['ok'] for x in results),1)
        self.assertEqual(self.sql('SELECT sum(calls_today) FROM public.mcp_tokens;'),'200')

    def test_revocation_waiting_call_rechecks_after_lock(self):
        locker = subprocess.Popen([str(PG/'psql'),'-XqAt','-v','ON_ERROR_STOP=1'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1,env=self.env)
        locker.stdin.write("BEGIN; UPDATE public.mcp_tokens SET revoked_at=now() WHERE token_hash='hash-one'; SELECT 'locked';\n"); locker.stdin.flush()
        self.assertEqual(locker.stdout.readline().strip(),'locked')
        waiter = subprocess.Popen([str(PG/'psql'),'-XqAt','-v','ON_ERROR_STOP=1','-c',"SET application_name='security_revoke_waiter'; SET ROLE service_role; SELECT public.increment_mcp_call('hash-one');"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=self.env)
        try:
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                if self.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='security_revoke_waiter' AND wait_event_type='Lock';") == '1': break
                time.sleep(.05)
            else: self.fail('RPC never blocked on revoked token lock')
            locker.stdin.write('COMMIT;\n\\q\n'); locker.stdin.flush()
            locker.wait(timeout=5)
            out,err=waiter.communicate(timeout=5)
            self.assertEqual(waiter.returncode,0,err)
            self.assertEqual(json.loads(out.strip())['reason'],'revoked')
            self.assertEqual(self.sql('SELECT sum(calls_today) FROM public.mcp_tokens;'),'0')
        finally:
            for p in [locker,waiter]:
                if p.poll() is None: p.kill(); p.wait()
                for stream in [p.stdin,p.stdout,p.stderr]:
                    if stream: stream.close()

if __name__ == '__main__': unittest.main(verbosity=2)
