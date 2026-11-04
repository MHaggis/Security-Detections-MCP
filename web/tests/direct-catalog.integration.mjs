/** Dedicated catalog login + verified TLS + actual seed, using only disposable resources. */
import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import { readFileSync, readdirSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { gunzipSync } from 'node:zlib';
import assert from 'node:assert/strict';
import pg from 'pg';
import Database from 'better-sqlite3';
import { catalogConnectionConfig, safeDatabaseError } from '../scripts/catalog-postgres.mjs';
const temporary=mkdtempSync(join(tmpdir(),'direct-catalog-'));
const container=`direct-catalog-${process.pid}`;
const run=(cmd,args,options={})=>execFileSync(cmd,args,{encoding:'utf8',stdio:['pipe','pipe','pipe'],...options});
const docker=(...args)=>run('docker',args);
function admin(input){return run('docker',['exec','-i','-e','PGPASSWORD=disposable-admin-test-password',container,'psql','-h','127.0.0.1','-U','postgres','-v','ON_ERROR_STOP=1','-At'],{input});}
const directory=new URL('../supabase/migrations/',import.meta.url);
const fixture=join(temporary,'seed.sqlite');
const password='disposable-catalog-test-password';
const connection=`postgresql://catalog_sync:${password}@localhost:54379/postgres`;
const ca=join(temporary,'ca.crt');
const script=new URL('../scripts/seed-from-sqlite.ts',import.meta.url).pathname;
let client,sqlite;
async function seed(extra={}) {
  const env={...process.env,CATALOG_SEED_TRANSPORT:'postgres',SUPABASE_CATALOG_DATABASE_URL:connection,DETECTIONS_DB_PATH:fixture,NODE_EXTRA_CA_CERTS:ca,...extra};
  delete env.SUPABASE_SERVICE_ROLE_KEY;
  return promisify(execFile)(process.execPath,['--experimental-strip-types',script],{env,timeout:120000});
}
try {
  run('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(temporary,'ca.key'),'-out',ca,'-days','1','-subj','/CN=Disposable Catalog Test CA']);
  run('openssl',['req','-newkey','rsa:2048','-nodes','-keyout',join(temporary,'server.key'),'-out',join(temporary,'server.csr'),'-subj','/CN=localhost']);
  writeFileSync(join(temporary,'extensions'),'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
  run('openssl',['x509','-req','-in',join(temporary,'server.csr'),'-CA',ca,'-CAkey',join(temporary,'ca.key'),'-CAcreateserial','-out',join(temporary,'server.crt'),'-days','1','-extfile',join(temporary,'extensions')]);
  docker('run','-d','--name',container,'-p','127.0.0.1:54379:5432','-e','POSTGRES_PASSWORD=disposable-admin-test-password','postgres:17-alpine');
  for(let i=0;i<60;i++){try{admin('SELECT 1');break;}catch{await new Promise(r=>setTimeout(r,250));}}
  for(const file of ['server.key','server.crt']) docker('cp',join(temporary,file),`${container}:/tmp/${file}`);
  docker('exec',container,'chown','postgres:postgres','/tmp/server.key','/tmp/server.crt');
  docker('exec',container,'chmod','600','/tmp/server.key');
  admin("ALTER SYSTEM SET ssl='on'; ALTER SYSTEM SET ssl_cert_file='/tmp/server.crt'; ALTER SYSTEM SET ssl_key_file='/tmp/server.key';");
  docker('restart',container);
  for(let i=0;i<60;i++){try{admin('SELECT 1');break;}catch{await new Promise(r=>setTimeout(r,250));}}
  writeFileSync(join(temporary,'pg_hba.conf'),'local all all trust\nhostnossl all catalog_sync all reject\nhostssl all catalog_sync all scram-sha-256\nhost all all all scram-sha-256\n');
  docker('cp',join(temporary,'pg_hba.conf'),`${container}:/var/lib/postgresql/data/pg_hba.conf`);
  docker('exec',container,'chown','postgres:postgres','/var/lib/postgresql/data/pg_hba.conf');
  admin('SELECT pg_reload_conf()');
  admin(`CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role BYPASSRLS;
    CREATE SCHEMA auth; CREATE TABLE auth.users(id uuid primary key, raw_user_meta_data jsonb, email text);
    CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql AS $$ SELECT NULL::uuid $$;`);
  for(const name of ['001_schema.sql','002_rls_and_functions.sql','013_atomic_rate_limit.sql','014_mcp_tokens.sql','016_add_jamf_protect_source.sql']) admin(readFileSync(new URL(name,directory),'utf8'));
  admin('GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role; GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated, service_role;');
  for(const pattern of ['source_qualified_detection_identity','hosted_token_security','catalog_seed_transport','direct_catalog_sync_role']) admin(readFileSync(new URL(readdirSync(directory).find(name=>name.includes(pattern)),directory),'utf8'));
  assert.equal(admin("SELECT rolcanlogin FROM pg_roles WHERE rolname='catalog_sync'").trim(),'f');
  admin(`ALTER ROLE catalog_sync LOGIN PASSWORD '${password}';`);
  const noTls=new pg.Client({...catalogConnectionConfig(connection),ssl:false});
  await assert.rejects(noTls.connect(),/pg_hba.conf rejects connection/);
  await noTls.end();
  for(const role of ['anon','authenticated']) {
    assert.throws(()=>admin(`SET ROLE ${role}; INSERT INTO public.detections(id,name,source_type) VALUES('denied','denied','sigma')`),/row-level security/);
    assert.throws(()=>admin(`SET ROLE ${role}; SELECT public.seed_catalog_batch('detections','W10=')`),/permission denied/);
  }
  client=new pg.Client({...catalogConnectionConfig(connection),ssl:{rejectUnauthorized:true,ca:readFileSync(ca)}});
  await client.connect();
  assert.equal((await client.query('SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()')).rows[0].ssl,true);
  const role=(await client.query("SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls,rolinherit FROM pg_roles WHERE rolname=current_user")).rows[0];
  assert.deepEqual(role,{rolsuper:false,rolcreatedb:false,rolcreaterole:false,rolbypassrls:false,rolinherit:false});
  assert.equal((await client.query('SELECT count(*)::int AS n FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user)')).rows[0].n,0);
  assert.equal((await client.query('SHOW statement_timeout')).rows[0].statement_timeout,'8s');
  const denied=[
    'SELECT * FROM auth.users','INSERT INTO auth.users(id) VALUES(gen_random_uuid())','UPDATE auth.users SET email=NULL','DELETE FROM auth.users',
    'SELECT * FROM public.profiles','INSERT INTO public.profiles(id) VALUES(gen_random_uuid())','UPDATE public.profiles SET tier=\'admin\'','DELETE FROM public.profiles',
    'SELECT * FROM public.mcp_tokens','INSERT INTO public.mcp_tokens(user_id,token_hash,name,prefix) VALUES(gen_random_uuid(),\'x\',\'x\',\'x\')','UPDATE public.mcp_tokens SET calls_today=0','DELETE FROM public.mcp_tokens',
    "SELECT public.increment_mcp_call('x')", "SELECT public.increment_chat_count(gen_random_uuid(),100)",
    'TRUNCATE public.detections CASCADE','DELETE FROM public.detections',
    'CREATE ROLE catalog_escalation','CREATE SCHEMA catalog_escalation','CREATE TABLE public.catalog_escalation(id int)',
    'CREATE FUNCTION public.catalog_escalation() RETURNS int LANGUAGE sql AS $$SELECT 1$$',
    'SET ROLE service_role','SET ROLE postgres',
    "COPY (SELECT 1) TO PROGRAM 'true'","SELECT pg_read_file('/etc/passwd')",
  ];
  for(const statement of denied) await assert.rejects(client.query(statement),/permission denied|must be|not permitted/i,statement);
  await client.query("SELECT set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000123',false)");
  for(const table of ['public.profiles','public.mcp_tokens','auth.users']) {
    const relationOid=Number(admin(`SELECT '${table}'::regclass::oid`).trim());
    for(const privilege of ['SELECT','INSERT','UPDATE']) assert.equal((await client.query('SELECT has_any_column_privilege(current_user,$1::oid,$2) AS allowed',[relationOid,privilege])).rows[0].allowed,false);
    await assert.rejects(client.query(`SELECT * FROM ${table}`),/permission denied/);
  }
  await client.query('CREATE TEMP TABLE forged_signup(id uuid,raw_user_meta_data jsonb,email text)');
  await assert.rejects(client.query('CREATE TRIGGER forged_signup AFTER INSERT ON forged_signup FOR EACH ROW EXECUTE FUNCTION public.handle_new_user()'),/permission denied/);
  admin("INSERT INTO auth.users(id,email) VALUES('00000000-0000-0000-0000-000000000123','signup@example.invalid')");
  assert.equal(admin("SELECT count(*) FROM profiles WHERE id='00000000-0000-0000-0000-000000000123'").trim(),'1','existing signup trigger remains functional');
  const rpc=async(table,rows)=>{const result=await client.query('SELECT public.seed_catalog_batch($1,$2) AS result',[table,Buffer.from(JSON.stringify(rows)).toString('base64')]);return result.rows[0].result;};
  const cases=[
    ['detections',{id:'collision',source_type:'sigma',name:'Sigma',mitre_ids:['T1001']}],
    ['detections',{id:'collision',source_type:'elastic',name:'Elastic',mitre_ids:['T1002']}],
    ['technique_tactics',{technique_id:'T1001',tactic_name:'execution'}],
    ['attack_techniques',{technique_id:'T1001',name:'Technique'}],
    ['attack_actors',{actor_id:'actor-test',name:'Actor'}],['attack_software',{software_id:'software-test',name:'Software'}],
    ['actor_techniques',{actor_id:'actor-test',technique_id:'T1001'}],['software_techniques',{software_id:'software-test',technique_id:'T1001'}],
    ['procedure_reference',{id:'procedure-test',technique_id:'T1001',name:'Procedure',category:'test',description:'Test'}],['stories',{id:'story-test',name:'Story'}],
  ];
  for(const [table,row] of cases){assert.deepEqual(await rpc(table,[row]),{processed:1});assert.deepEqual(await rpc(table,[row]),{processed:1});}
  await rpc('detections',[{id:'collision',source_type:'sigma',name:'Updated Sigma',mitre_ids:['T1003']}]);
  assert.deepEqual((await client.query("SELECT source_type,technique_id FROM public.detection_techniques ORDER BY source_type")).rows,[{source_type:'elastic',technique_id:'T1002'},{source_type:'sigma',technique_id:'T1003'}]);
  await assert.rejects(rpc('profiles',[{id:'no'}]),/Unsupported catalog table/);
  const rows=JSON.parse(gunzipSync(readFileSync(new URL('./fixtures/cql-blocked-batch.json.gz',import.meta.url))));
  sqlite=new Database(fixture);
  const fields=Object.keys(rows[0]);
  sqlite.exec(`CREATE TABLE detections (${fields.map(key=>`"${key}" TEXT`).join(',')}); CREATE TABLE technique_tactics(technique_id TEXT,tactic_name TEXT,source TEXT);`);
  const insert=sqlite.prepare(`INSERT INTO detections VALUES (${fields.map(()=>'?').join(',')})`);
  for(const row of rows) insert.run(...fields.map(key=>Array.isArray(row[key])?JSON.stringify(row[key]):row[key]));
  await seed(); await seed();
  const stored=(await client.query('SELECT * FROM public.detections WHERE source_type=$1',['crowdstrike_cql'])).rows;
  assert.equal(stored.length,100);
  for(const original of rows){const actual=stored.find(row=>row.id===original.id);for(const [key,value] of Object.entries(original)) assert.deepEqual(actual[key],value,`seed field ${key}`);}
  assert.equal((await client.query("SELECT count(*)::int AS n FROM public.sync_runs WHERE status='completed'")).rows[0].n,2);
  sqlite.exec("CREATE TABLE attack_techniques(technique_id TEXT,name TEXT); INSERT INTO attack_techniques VALUES('bad',NULL)");
  await assert.rejects(seed(),error=>{assert.match(error.stderr,/Catalog database operation failed \(23502\)/);assert.ok(!error.stderr.includes(password));return true;});
  assert.equal((await client.query("SELECT count(*)::int AS n FROM public.sync_runs WHERE status='failed'")).rows[0].n,1);
  assert.equal((await client.query("SELECT count(*)::int AS n FROM public.sync_runs WHERE status='completed'")).rows[0].n,2);
  sqlite.exec('DROP TABLE attack_techniques');
  admin(`CREATE FUNCTION public.test_catalog_delay() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN IF NEW.source_type='crowdstrike_cql' THEN PERFORM pg_sleep(0.01); END IF; RETURN NEW; END; $$;
    CREATE TRIGGER test_catalog_delay BEFORE INSERT OR UPDATE ON detections FOR EACH ROW EXECUTE FUNCTION public.test_catalog_delay();
    ALTER ROLE catalog_sync SET statement_timeout='400ms';`);
  const split=await seed();
  assert.match(split.stderr,/canceled \(57014\); splitting/);
  assert.equal((await client.query("SELECT count(*)::int AS n FROM public.detections WHERE source_type='crowdstrike_cql'")).rows[0].n,100);
  assert.equal((await client.query("SELECT count(*)::int AS n FROM public.sync_runs WHERE status='completed'")).rows[0].n,3);
  admin("DROP TRIGGER test_catalog_delay ON detections; DROP FUNCTION test_catalog_delay(); ALTER ROLE catalog_sync SET statement_timeout='8s';");
  await assert.rejects(seed({SUPABASE_CATALOG_DATABASE_URL:''}),/Missing SUPABASE_CATALOG_DATABASE_URL/);
  await assert.rejects(seed({CATALOG_SEED_TRANSPORT:'typo'}),/Invalid CATALOG_SEED_TRANSPORT/);
  await assert.rejects(seed({SUPABASE_CATALOG_DATABASE_URL:connection+'?sslmode=disable'}),error=>{assert.match(error.stderr,/Invalid SUPABASE_CATALOG_DATABASE_URL/);assert.ok(!error.stderr.includes(password));return true;});
  await assert.rejects(seed({SUPABASE_CATALOG_DATABASE_URL:connection.replace(password,'wrong-password')}),/28P01/);
  await assert.rejects(seed({NODE_EXTRA_CA_CERTS:''}),error=>{assert.match(error.stderr,/Catalog database operation failed/);assert.ok(!error.stderr.includes(password));return true;});
  await assert.rejects(seed({SUPABASE_CATALOG_DATABASE_URL:connection.replace('localhost','127.0.0.1')}),error=>{assert.match(error.stderr,/ERR_TLS_CERT_ALTNAME_INVALID/);assert.ok(!error.stderr.includes(password));return true;});
  const sanitized=safeDatabaseError({code:'23502',message:connection,detail:password});
  assert.ok(!String(sanitized).includes(password));assert.ok(!String(sanitized).includes('postgresql://'));
  console.log('PASS: dedicated no-bypass role, all9 catalog writes/edges/defaults, denied accounts/tokens/quotas/DDL/TRUNCATE/escalation/temp-trigger, signup preserved, verified TLS and fail-closed settings, real blocked CQL seed twice, failed sync and credential redaction');
} finally {
  if(sqlite)sqlite.close();
  if(client)await client.end();
  try{docker('rm','-f',container);}catch{}
  rmSync(temporary,{recursive:true,force:true});
}
