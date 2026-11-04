import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, copyFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const root = process.cwd();
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const npmCli = process.env.npm_execpath;
assert(npmCli, 'Use npm run test:package');
const temporary = mkdtempSync(join(tmpdir(), 'security-detections-package-'));
const outputIndex = process.argv.indexOf('--output');
const output = outputIndex < 0 ? null : resolve(process.argv[outputIndex + 1]);
function npm(args, cwd = root) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.toLowerCase() === 'npm_config_package') delete env[key];
  const result = spawnSync(process.execPath, [npmCli, ...args], { cwd, env, encoding: 'utf8', timeout: 180000, maxBuffer: 8*1024*1024 });
  assert.equal(result.status, 0, `npm ${args[0]}: ${result.error ?? result.stderr}`);
  return result.stdout;
}
try {
  const [packed] = JSON.parse(npm(['pack', '--ignore-scripts', '--json', '--pack-destination', temporary]));
  const allowed = path => path.startsWith('dist/') || ['package.json','README.md','LICENSE'].includes(path);
  assert(packed.files.every(file => allowed(file.path)), 'Unexpected package contents');
  for (const path of ['dist/index.js','dist/server.js','package.json','README.md']) assert(packed.files.some(f=>f.path===path), `Missing ${path}`);
  const archive = join(temporary, packed.filename);
  const consumer = join(temporary, 'consumer');
  // Native better-sqlite3 needs its normal install script in the clean consumer.
  npm(['install','--prefix',consumer,'--omit=dev','--no-audit','--no-fund',archive]);
  const installed = join(consumer,'node_modules',pkg.name);
  const manifest = JSON.parse(readFileSync(join(installed,'package.json'),'utf8'));
  assert.equal(manifest.version,pkg.version);
  assert.equal(manifest.mcpName,pkg.mcpName);
  assert(!existsSync(join(consumer,'node_modules','typescript')), 'Development compiler shipped to consumer');
  assert(existsSync(join(consumer,'node_modules','.bin',pkg.name+(process.platform==='win32'?'.cmd':''))), 'CLI bin missing');
  const client = new Client({ name:'installed-package-smoke',version:'1.0.0' });
  const transport = new StdioClientTransport({ command:process.execPath,args:[resolve(installed,manifest.bin[pkg.name])],cwd:consumer,
    env:{ DETECTIONS_DB_PATH:join(temporary,'fixture.sqlite'),JAMF_PROTECT_PATHS:join(root,'tests/fixtures/jamf_protect') },stderr:'pipe' });
  let stderr=''; transport.stderr?.on('data',chunk=>{stderr+=chunk.toString()});
  try {
    await client.connect(transport,{timeout:30000});
    assert.equal(client.getServerVersion()?.version,pkg.version,'MCP initialization version differs from published package');
    const {tools}=await client.listTools();
    for(const name of ['search','get_by_id','list_by_source','get_stats']) assert(tools.some(t=>t.name===name),`Missing ${name}`);
    const result=await client.callTool({name:'list_by_source',arguments:{source_type:'jamf_protect',limit:10}});
    assert(!result.isError,JSON.stringify(result));
    assert(result.content.filter(c=>c.type==='text').map(c=>c.text).join('\n').includes('dscl'),'Installed SQLite fixture query failed');
    const invalid=await client.callTool({name:'nonexistent_tool',arguments:{}});
    assert(invalid.isError,'Unknown tool accepted');
    console.log(`PASS installed tarball: MCP ${pkg.version}, ${tools.length} tools, native SQLite query, error contract`);
  } catch(error) { console.error(stderr); throw error; }
  finally { await client.close();await transport.close(); }
  const sha256=createHash('sha256').update(readFileSync(archive)).digest('hex');
  if(output){
    mkdirSync(output,{recursive:true});
    copyFileSync(archive,join(output,packed.filename));
    writeFileSync(join(output,'package.sha256'),`${sha256}  ${packed.filename}\n`);
    writeFileSync(join(output,'package-artifact.json'),JSON.stringify({filename:packed.filename,version:pkg.version,sha256},null,2)+'\n');
  }
  console.log(`Verified ${packed.filename} sha256=${sha256}`);
} finally {rmSync(temporary,{recursive:true,force:true});}
