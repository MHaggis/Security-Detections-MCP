/** Production-semantic catalog regression. Requires Docker; owns only its named containers. */
import { execFile, execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, mkdtempSync, rmSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { createClient } from '@supabase/supabase-js';
const suffix = process.pid;
const pg = `detection-identity-pg-${suffix}`;
const rest = `detection-identity-rest-${suffix}`;
const network = `detection-identity-${suffix}`;
const docker = (...args) => execFileSync('docker', args, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
const sql = (input) => execFileSync('docker', ['exec', '-i', pg, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-At'], { input, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
const secret = 'disposable-integration-only-jwt-secret-at-least-32-bytes';
const jwt = role => {
  const parts = [{ alg: 'HS256', typ: 'JWT' }, { role, exp: Math.floor(Date.now()/1000)+3600 }].map(v=>Buffer.from(JSON.stringify(v)).toString('base64url'));
  return [...parts, createHmac('sha256', secret).update(parts.join('.')).digest('base64url')].join('.');
};
const url = 'http://127.0.0.1:54380';
const client = role => createClient(url, jwt(role), { auth: { persistSession: false }, global: { fetch: (input, init) => fetch(String(input).replace('/rest/v1/', '/'), init) } });
const temporary = mkdtempSync(join(tmpdir(), 'catalog-identity-'));
let proxy;
const migrationDir = new URL('../supabase/migrations/', import.meta.url);
try {
  docker('network', 'create', network);
  docker('run', '-d', '--name', pg, '--network', network, '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', 'postgres:17-alpine');
  for(let i=0;i<60;i++){try{sql('SELECT 1');break;}catch{await new Promise(r=>setTimeout(r,500));}}
  sql(`CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role BYPASSRLS;
    CREATE SCHEMA auth; CREATE TABLE auth.users(id uuid primary key, raw_user_meta_data jsonb, email text);
    CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql AS $$ SELECT NULL::uuid $$;`);
  for(const file of ['001_schema.sql','002_rls_and_functions.sql','016_add_jamf_protect_source.sql']) sql(readFileSync(new URL(file,migrationDir),'utf8'));
  sql(`GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
    GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated, service_role;
    INSERT INTO detections(id,name,source_type,mitre_ids) VALUES ('collision','Legacy Sigma','sigma','["T1001"]');
    INSERT INTO detection_techniques VALUES ('collision','T1001');`);
  const migration=readFileSync(new URL(readdirSync(migrationDir).find(f=>f.includes('source_qualified_detection_identity')),migrationDir),'utf8');
  assert.throws(()=>sql(migration.replace('COMMIT;', 'SELECT 1/0; COMMIT;')),/division by zero/);
  assert.equal(sql("SELECT count(*) FROM information_schema.columns WHERE table_name='detection_techniques' AND column_name='source_type'").trim(),'0');
  assert.equal(sql("SELECT count(*) FROM detections").trim(),'1');
  sql(migration);
  assert.equal(sql("SELECT source_type || ':' || detection_id FROM detection_techniques").trim(),'sigma:collision');
  for(const role of ['anon','authenticated']) {
    assert.equal(sql(`SET ROLE ${role}; SELECT count(*) FROM detections;`).trim().split('\n').at(-1),'1');
    for(const table of ['detections','detection_techniques']) assert.throws(()=>sql(`SET ROLE ${role}; TRUNCATE ${table} CASCADE;`),/permission denied/);
    assert.throws(()=>sql(`SET ROLE ${role}; INSERT INTO detections(id,name,source_type) VALUES ('bad','bad','sigma');`),/row-level security/);
  }
  docker('run','-d','--name',rest,'--network',network,'-p','127.0.0.1:54380:3000','-e',`PGRST_DB_URI=postgres://postgres@${pg}:5432/postgres`,'-e','PGRST_DB_ANON_ROLE=anon','-e',`PGRST_JWT_SECRET=${secret}`,'public.ecr.aws/supabase/postgrest:v14.18');
  for(let i=0;i<60;i++){try{if((await fetch(url)).ok)break;}catch{} await new Promise(r=>setTimeout(r,500));}
  const service=client('service_role');
  async function good(promise){const result=await promise;assert.equal(result.error,null,JSON.stringify(result.error));return result.data;}
  const rule=(source,name,tech)=>({id:'collision',source_type:source,name,mitre_ids:[tech],raw_yaml:`${source}: ${name}`});
  await good(service.from('detections').upsert([rule('sigma','Sigma updated','T1002'),rule('elastic','Elastic preserved','T1003')],{onConflict:'source_type,id'}));
  assert.equal((await good(service.from('detections').select('*').eq('id','collision'))).length,2);
  assert.deepEqual((await good(service.from('detection_techniques').select('source_type,technique_id').order('source_type'))),[{source_type:'elastic',technique_id:'T1003'},{source_type:'sigma',technique_id:'T1002'}]);
  await good(service.from('detections').upsert(rule('sigma','Sigma twice','T1004'),{onConflict:'source_type,id'}));
  assert.equal((await good(service.from('detections').select('*').contains('mitre_ids', JSON.stringify(['T1003']))))[0].source_type,'elastic');
  const joined=await good(service.from('detection_techniques').select('technique_id,detections!inner(source_type)').eq('detections.source_type','elastic'));
  assert.equal(joined.length,1);assert.equal(joined[0].technique_id,'T1003');
  const counts=await good(service.rpc('get_technique_source_counts',{p_technique_id:'T1003'}));
  assert.equal(counts.length,1);assert.equal(counts[0].source_type,'elastic');
  for(const rpc of ['get_technique_intelligence','get_technique_full','compare_sources_for_technique','get_procedure_coverage']) await good(service.rpc(rpc,{p_technique_id:'T1003'}));
  const invalid=await service.from('detections').upsert([rule('sigma','Must rollback','T1005'),{...rule('elastic','Invalid','T1006'),mitre_ids:[null]}],{onConflict:'source_type,id'});
  assert.ok(invalid.error);
  assert.equal((await good(service.from('detections').select('name').eq('source_type','sigma')))[0].name,'Sigma twice');
  assert.ok((await service.from('detection_techniques').insert({source_type:'kql',detection_id:'collision',technique_id:'T1003'})).error);
  for(const role of ['anon','authenticated']){
    assert.equal((await good(client(role).from('detections').select('*'))).length,2);
    assert.ok((await client(role).from('detections').upsert(rule('sigma','Denied','T1007'),{onConflict:'source_type,id'})).error);
    await good(client(role).from('detections').update({source_type:'kql'}).eq('source_type','sigma'));
    assert.equal((await good(service.from('detections').select('*').eq('source_type','sigma'))).length,1);
  }
  proxy = createServer(async (req,res) => {
    const body=[]; for await (const chunk of req) body.push(chunk);
    try {
      const headers={...req.headers}; delete headers.host; delete headers['content-length'];
      const response=await fetch(url+req.url.replace('/rest/v1',''),{method:req.method,headers,body:body.length?Buffer.concat(body):undefined});
      res.writeHead(response.status,Object.fromEntries(response.headers));res.end(Buffer.from(await response.arrayBuffer()));
    } catch(error){res.writeHead(500);res.end(String(error));}
  });
  await new Promise(resolve=>proxy.listen(54381,'127.0.0.1',resolve));
  process.env.NEXT_PUBLIC_SUPABASE_URL='http://127.0.0.1:54381';
  process.env.SUPABASE_SERVICE_ROLE_KEY=jwt('service_role');
  const queries=await import('../lib/mcp/db.ts');
  await assert.rejects(queries.getDetectionById('collision'),/Ambiguous.*elastic, sigma/);
  await assert.rejects(queries.getRawYaml('collision'),/Ambiguous/);
  assert.equal((await queries.getDetectionById('collision','elastic')).name,'Elastic preserved');
  assert.equal(await queries.getRawYaml('collision','sigma'),'sigma: Sigma twice');
  assert.equal(await queries.getDetectionById('missing'),null);
  assert.deepEqual((await queries.listByMitre('T1003')).map(d=>d.source_type),['elastic']);
  const fixture=join(temporary,'seed.sqlite');
  const sqlite=new Database(fixture);
  sqlite.exec(`CREATE TABLE detections(id TEXT,name TEXT,source_type TEXT,mitre_ids TEXT);
    INSERT INTO detections VALUES('collision','Seed Sigma','sigma','["T2001"]'),('collision','Seed Elastic','elastic','["T2002"]');
    CREATE TABLE technique_tactics(technique_id TEXT,tactic_name TEXT,source TEXT);`);
  const seed=()=>promisify(execFile)(process.execPath,['--experimental-strip-types',new URL('../scripts/seed-from-sqlite.ts',import.meta.url).pathname],{
    env:{...process.env,DETECTIONS_DB_PATH:fixture},timeout:60000});
  await seed(); await seed();
  assert.equal((await good(service.from('detections').select('*'))).length,2);
  assert.deepEqual((await good(service.from('detection_techniques').select('source_type,technique_id').order('source_type'))),[{source_type:'elastic',technique_id:'T2002'},{source_type:'sigma',technique_id:'T2001'}]);
  assert.equal((await good(service.from('sync_runs').select('*').eq('status','completed'))).length,2);
  sqlite.exec("CREATE TABLE attack_techniques(technique_id TEXT,name TEXT); INSERT INTO attack_techniques VALUES('Tbad',NULL);");
  await assert.rejects(seed(),/attack_techniques batch 0 failed/);
  assert.equal((await good(service.from('sync_runs').select('*').eq('status','failed'))).length,1);
  sqlite.exec("DROP TABLE attack_techniques; UPDATE detections SET mitre_ids='invalid-json' WHERE source_type='sigma';");
  await assert.rejects(seed(),/Seed failed/);
  assert.equal((await good(service.from('sync_runs').select('*').eq('status','failed'))).length,2);
  assert.equal((await good(service.from('detection_techniques').select('*').eq('source_type','sigma')))[0].technique_id,'T2001');
  sqlite.close();
  await good(service.from('detections').delete().eq('source_type','sigma').eq('id','collision'));
  assert.equal((await good(service.from('detection_techniques').select('*'))).length,1);
  assert.equal((await queries.getDetectionById('collision')).source_type,'elastic');
  const sources=['sigma','splunk_escu','elastic','kql','sublime','crowdstrike_cql','jamf_protect'];
  await good(service.from('detections').upsert(sources.map(source=>({...rule(source,source,'T3000'),id:'seven'})),{onConflict:'source_type,id'}));
  assert.equal((await good(service.from('detections').select('*').eq('id','seven'))).length,7);
  assert.equal((await good(service.rpc('get_technique_source_counts',{p_technique_id:'T3000'}))).length,7);
  console.log('PASS: legacy migration, collision retention, composite API upserts/joins, exact edge replacement, RPCs, atomic migration/batch rollback, FK, RLS, TRUNCATE denial, all seven sources, hosted lookups and repeat/failing real seed');
} finally {
  if(proxy) await new Promise(resolve=>proxy.close(resolve));
  rmSync(temporary,{recursive:true,force:true});
  for(const name of [rest,pg]){try{docker('rm','-f',name);}catch{}}
  try{docker('network','rm',network);}catch{}
}
