/** Production-semantic catalog regression. Requires Docker; owns only its named containers. */
import { execFile, execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, mkdtempSync, rmSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { createHmac, createHash } from 'node:crypto';
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
let corruptAck = false;
const rpcPayloadSizes = [];
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
  sql(readFileSync(new URL(readdirSync(migrationDir).find(f=>f.includes('catalog_seed_transport')),migrationDir),'utf8'));
  assert.equal(sql("SELECT source_type || ':' || detection_id FROM detection_techniques").trim(),'sigma:collision');
  for(const role of ['anon','authenticated']) {
    assert.equal(sql(`SET ROLE ${role}; SELECT count(*) FROM detections;`).trim().split('\n').at(-1),'1');
    for(const table of ['detections','detection_techniques']) assert.throws(()=>sql(`SET ROLE ${role}; TRUNCATE ${table} CASCADE;`),/permission denied/);
    assert.throws(()=>sql(`SET ROLE ${role}; INSERT INTO detections(id,name,source_type) VALUES ('bad','bad','sigma');`),/row-level security/);
  }
  docker('run','-d','--name',rest,'--network',network,'-p','127.0.0.1:54380:3000','-e',`PGRST_DB_URI=postgres://postgres@${pg}:5432/postgres`,'-e','PGRST_DB_ANON_ROLE=anon','-e',`PGRST_JWT_SECRET=${secret}`,'public.ecr.aws/supabase/postgrest:v14.18');
  for(let i=0;i<60;i++){try{if((await fetch(url)).ok)break;}catch{} await new Promise(r=>setTimeout(r,500));}
  const service=client('service_role');
  const encoded = rows => Buffer.from(JSON.stringify(rows),'utf8').toString('base64');
  const rpc = (table, rows, who=service) => who.rpc('seed_catalog_batch',{p_table:table,p_payload:encoded(rows)});

  async function good(promise){const result=await promise;assert.equal(result.error,null,JSON.stringify(result.error));return result.data;}
  for(const role of ['anon','authenticated']) {
    const denied=await rpc('detections',[{id:'denied',source_type:'sigma',name:'Denied'}],client(role));
    assert.ok(denied.error,'public callers must not execute catalog writer');
  }
  for(const [table,rows] of [
    ['profiles',[{id:'user'}]], ['detection_techniques',[{source_type:'sigma',detection_id:'x',technique_id:'T1'}]],
    ['detections; DROP TABLE detections', [{id:'x'}]],
    ['detections',[{id:'x',source_type:'sigma',name:'x',created_at:'2026-01-01'}]],
    ['detections',[{id:'x',source_type:'sigma',name:'x','name) VALUES(1);--':'x'}]],
    ['detections',[{id:'x',source_type:'sigma',name:'x'},{id:'y',source_type:'sigma'}]],
    ['detections',[{id:null,source_type:'sigma',name:'x'}]],['detections',[{source_type:'sigma',name:'x'}]],
    ['detections',[{id:3,source_type:'sigma',name:'x'}]],['detections',[{id:'',source_type:'sigma',name:'x'}]],['detections',[{}]],['detections',[]],['detections',Array(101).fill({id:'x'})],
    ['detections',{}],['detections',[null]],['detections',[[]]],
  ]) assert.ok((await rpc(table,rows)).error,`must reject ${table} invalid shape/keys`);
  for(const bad of [null,Buffer.alloc(2097153).toString('base64'),'%',Buffer.from([0xff]).toString('base64'),Buffer.from('not JSON').toString('base64'),'A'.repeat(2796205),encoded([{description:'x'.repeat(2097152)}]),'e30=\n']) {
    assert.ok((await service.rpc('seed_catalog_batch',{p_table:'detections',p_payload:bad})).error,'must reject malformed/oversized encoding');
  }
  // Every allowlisted conflict target, including key-only repeats and omitted defaults.
  const catalogCases=[
    ['detections',{id:'rpc-rule',source_type:'sigma',name:'Original',mitre_ids:['T5000']}],
    ['technique_tactics',{technique_id:'T5000',tactic_name:'execution'}],
    ['attack_techniques',{technique_id:'T5000',name:'Technique'}],
    ['attack_actors',{actor_id:'actor-test',name:'Actor'}],
    ['attack_software',{software_id:'software-test',name:'Software'}],
    ['actor_techniques',{actor_id:'actor-test',technique_id:'T5000'}],
    ['software_techniques',{software_id:'software-test',technique_id:'T5000'}],
    ['procedure_reference',{id:'procedure-test',technique_id:'T5000',name:'Procedure',category:'test',description:'Test'}],
    ['stories',{id:'story-test',name:'Story'}],
  ];
  for(const [table,row] of catalogCases){assert.deepEqual(await good(rpc(table,[row])),{processed:1});assert.deepEqual(await good(rpc(table,[row])),{processed:1});}
  assert.ok((await good(service.from('detections').select('created_at').eq('id','rpc-rule')))[0].created_at);
  assert.equal((await good(service.from('technique_tactics').select('source').eq('technique_id','T5000')))[0].source,'detection');
  const failed=await rpc('detections',[{id:'rpc-rule',source_type:'sigma',name:'Rollback',mitre_ids:['T5001']},{id:'bad-rpc',source_type:'sigma',name:null,mitre_ids:[]}]);
  assert.ok(failed.error);
  assert.equal((await good(service.from('detections').select('name').eq('id','rpc-rule')))[0].name,'Original');
  assert.equal((await good(service.from('detection_techniques').select('technique_id').eq('detection_id','rpc-rule')))[0].technique_id,'T5000');
  await good(rpc('detections',[{id:'rpc-default',source_type:'sigma',name:'Defaults'}]));
  assert.deepEqual((await good(service.from('detections').select('mitre_ids').eq('id','rpc-default')))[0].mitre_ids,[]);
  await good(rpc('detections',[{id:'rpc-rule',source_type:'sigma',name:'Changed only name'}]));
  assert.equal((await good(service.from('detection_techniques').select('technique_id').eq('detection_id','rpc-rule')))[0].technique_id,'T5000');
  await good(service.from('detections').delete().eq('id','rpc-default'));
  await good(service.from('detections').delete().eq('id','rpc-rule'));
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
    if(req.url.includes('/rpc/seed_catalog_batch')) {
      const request=JSON.parse(Buffer.concat(body).toString());
      rpcPayloadSizes.push(Buffer.from(request.p_payload,'base64').length);
    }
    try {
      const headers={...req.headers}; delete headers.host; delete headers['content-length'];
      const response=await fetch(url+req.url.replace('/rest/v1',''),{method:req.method,headers,body:body.length?Buffer.concat(body):undefined});
      if(corruptAck && req.url.includes('/rpc/seed_catalog_batch') && response.ok) {
        res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({processed:0}));
      } else {res.writeHead(response.status,Object.fromEntries(response.headers));res.end(Buffer.from(await response.arrayBuffer()));}
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
    env:{...process.env,CATALOG_SEED_TRANSPORT:'http',DETECTIONS_DB_PATH:fixture},timeout:60000});
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

  await good(service.from('detections').delete().eq('source_type','sigma').eq('id','collision'));
  assert.equal((await good(service.from('detection_techniques').select('*'))).length,1);
  assert.equal((await queries.getDetectionById('collision')).source_type,'elastic');
  const sources=['sigma','splunk_escu','elastic','kql','sublime','crowdstrike_cql','jamf_protect'];
  await good(service.from('detections').upsert(sources.map(source=>({...rule(source,source,'T3000'),id:'seven'})),{onConflict:'source_type,id'}));
  assert.equal((await good(service.from('detections').select('*').eq('id','seven'))).length,7);
  assert.equal((await good(service.rpc('get_technique_source_counts',{p_technique_id:'T3000'}))).length,7);
  // Reproduce the hosted limit through actual PostgREST connections. The
  // per-row delay makes large writes exceed 800ms while split batches fit.
  sql(`CREATE FUNCTION public.test_slow_catalog_write() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.id LIKE 'cancel-%' THEN
        RAISE EXCEPTION 'canceling statement due to user request' USING ERRCODE='57014';
      END IF;
      IF NEW.id LIKE 'timeout-%' THEN
        PERFORM pg_sleep(CASE WHEN NEW.id='timeout-single' THEN 1.2 ELSE 0.02 END);
      END IF;
      RETURN NEW;
    END; $$;
    CREATE TRIGGER test_slow_catalog_write BEFORE INSERT OR UPDATE ON detections
      FOR EACH ROW EXECUTE FUNCTION public.test_slow_catalog_write();
    ALTER ROLE postgres SET statement_timeout='800ms';`);
  docker('restart',rest);
  for(let i=0;i<60;i++){try{if((await fetch(url)).ok)break;}catch{} await new Promise(r=>setTimeout(r,100));}
  const timeoutRows=Array.from({length:100},(_,i)=>({
    id:`timeout-${Math.floor(i/2)}`,source_type:i%2?'elastic':'sigma',name:'Timeout first',mitre_ids:['T4000'],
  }));
  const canceled=await service.from('detections').upsert(timeoutRows,{onConflict:'source_type,id'});
  assert.equal(canceled.error?.code,'57014');
  assert.equal((await good(service.from('detections').select('*').like('id','timeout-%'))).length,0,'canceled statement must roll back every detection');
  assert.equal((await good(service.from('detection_techniques').select('*').like('detection_id','timeout-%'))).length,0,'canceled statement must roll back every edge');
  sqlite.exec('DELETE FROM detections');
  const add=sqlite.prepare('INSERT INTO detections VALUES(?,?,?,?)');
  for(const row of timeoutRows) add.run(row.id,row.name,row.source_type,JSON.stringify(row.mitre_ids));
  const completedBefore=(await good(service.from('sync_runs').select('*').eq('status','completed'))).length;
  const recovered=await seed();
  assert.match(recovered.stderr,/canceled \(57014\); splitting 100 rows into 50 and 50/);
  assert.equal((await good(service.from('detections').select('*').like('id','timeout-%'))).length,100);
  assert.equal((await good(service.from('detection_techniques').select('*').eq('technique_id','T4000'))).length,100);
  sqlite.exec(`UPDATE detections SET name='Timeout repeated',mitre_ids='["T4001"]'`);
  const repeated=await seed();
  assert.match(repeated.stderr,/canceled \(57014\); splitting/);
  assert.equal((await good(service.from('detections').select('*').like('id','timeout-%'))).length,100);
  assert.equal((await good(service.from('detection_techniques').select('*').eq('technique_id','T4000'))).length,0);
  assert.equal((await good(service.from('detection_techniques').select('*').eq('technique_id','T4001'))).length,100);
  assert.equal((await good(service.from('sync_runs').select('*').eq('status','completed'))).length,completedBefore+2);
  const beforeSingle=(await good(service.from('sync_runs').select('*').eq('status','failed'))).length;
  sqlite.exec(`DELETE FROM detections; INSERT INTO detections VALUES('timeout-single','Cannot fit','sigma','["T4002"]');`);
  await assert.rejects(seed(),error=>{
    assert.match(error.stderr,/detections batch 0 failed: canceling statement due to statement timeout/);
    assert.doesNotMatch(error.stderr,/splitting/);
    return true;
  });
  assert.equal((await good(service.from('sync_runs').select('*').eq('status','failed'))).length,beforeSingle+1);
  assert.equal((await good(service.from('detections').select('*').eq('id','timeout-single'))).length,0);
  sqlite.exec(`DELETE FROM detections; INSERT INTO detections VALUES
    ('cancel-first','Canceled','sigma','["T4003"]'),('cancel-second','Canceled','elastic','["T4003"]');`);
  await assert.rejects(seed(),error=>{
    assert.match(error.stderr,/detections batch 0 failed: canceling statement due to user request/);
    assert.doesNotMatch(error.stderr,/splitting/);
    return true;
  });
  assert.equal((await good(service.from('sync_runs').select('*').eq('status','failed'))).length,beforeSingle+2);
  assert.equal((await good(service.from('detections').select('*').like('id','cancel-%'))).length,0);
  assert.equal((await good(service.from('sync_runs').select('*').eq('status','completed'))).length,completedBefore+2);
  sql("ALTER ROLE postgres RESET statement_timeout");
  docker('restart',rest);
  for(let i=0;i<60;i++){try{if((await fetch(url)).ok)break;}catch{} await new Promise(r=>setTimeout(r,100));}
  const blockedBytes=gunzipSync(readFileSync(new URL('./fixtures/cql-blocked-batch.json.gz',import.meta.url)));
  assert.equal(createHash('sha256').update(blockedBytes).digest('hex'),'ee14eba97ca988b9abd433e898cb52352ad826b62f221f118c2643284fd75c2c');
  const blockedRows=JSON.parse(blockedBytes);
  assert.deepEqual(await good(rpc('detections',blockedRows)),{processed:100});
  const blockedIds=blockedRows.map(row=>row.id);
  const roundtrip=await good(service.from('detections').select('*').in('id',blockedIds));
  for(const original of blockedRows){
    const actual=roundtrip.find(row=>row.id===original.id&&row.source_type===original.source_type);
    for(const [key,value] of Object.entries(original)) assert.deepEqual(actual[key],value,`lossless ${key}`);
  }
  // Run the same real public rule payload through the actual SQLite seed mapping.
  sqlite.exec('DELETE FROM detections');
  const existingColumns=new Set(sqlite.prepare('PRAGMA table_info(detections)').all().map(row=>row.name));
  const fields=Object.keys(blockedRows[0]);
  for(const key of fields) if(!existingColumns.has(key)) sqlite.exec(`ALTER TABLE detections ADD COLUMN "${key}" TEXT`);
  const insertBlocked=sqlite.prepare(`INSERT INTO detections (${fields.map(key=>`"${key}"`).join(',')}) VALUES (${fields.map(()=>'?').join(',')})`);
  for(const row of blockedRows) insertBlocked.run(...fields.map(key=>Array.isArray(row[key])?JSON.stringify(row[key]):row[key]));
  await seed();
  const seeded=await good(service.from('detections').select('*').in('id',blockedIds));
  for(const original of blockedRows){
    const actual=seeded.find(row=>row.id===original.id);
    for(const [key,value] of Object.entries(original)) assert.deepEqual(actual[key],value,`seed lossless ${key}`);
  }
  const failedBeforeAck=(await good(service.from('sync_runs').select('*').eq('status','failed'))).length;
  corruptAck=true;
  await assert.rejects(seed(),/invalid catalog acknowledgement/);
  corruptAck=false;
  assert.equal((await good(service.from('sync_runs').select('*').eq('status','failed'))).length,failedBeforeAck+1);
  sqlite.exec('DELETE FROM detections');
  const addLarge=sqlite.prepare('INSERT INTO detections(id,name,source_type,mitre_ids,raw_yaml) VALUES(?,?,?,?,?)');
  addLarge.run('large-a','Large A','sigma','[]','x'.repeat(1100000));
  addLarge.run('large-b','Large B','elastic','[]','y'.repeat(1100000));
  const beforeLarge=rpcPayloadSizes.length;
  await seed();
  assert.equal(rpcPayloadSizes.length-beforeLarge,2,'oversized pair must split before transport');
  assert.ok(rpcPayloadSizes.every(bytes=>bytes<=2097152));
  assert.equal((await good(service.from('detections').select('raw_yaml').eq('id','large-a')))[0].raw_yaml.length,1100000);
  sqlite.exec("DELETE FROM detections");
  addLarge.run('too-large','Too large','sigma','[]','x'.repeat(2097153));
  const beforeOversized=rpcPayloadSizes.length;
  await assert.rejects(seed(),/single row exceeds 2 MiB transport limit/);
  assert.equal(rpcPayloadSizes.length,beforeOversized,'oversized single row must not be submitted');
  sqlite.close();
  console.log('PASS: service-only bounded catalog RPC, all nine conflict targets/defaults, malformed inputs denied, exact blocked CQL roundtrip via RPC and seed, byte splitting and acknowledgement validation');
  console.log('PASS: real 57014 rollback, bounded batch splitting, repeat source-specific edge reconciliation, and terminal single-row timeout failure');
  console.log('PASS: legacy migration, collision retention, composite API upserts/joins, exact edge replacement, RPCs, atomic migration/batch rollback, FK, RLS, TRUNCATE denial, all seven sources, hosted lookups and repeat/failing real seed');
} finally {
  if(proxy) await new Promise(resolve=>proxy.close(resolve));
  rmSync(temporary,{recursive:true,force:true});
  for(const name of [rest,pg]){try{docker('rm','-f',name);}catch{}}
  try{docker('network','rm',network);}catch{}
}
