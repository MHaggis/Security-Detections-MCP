/** DEP-003/004: built Next app + real Supabase HTTP client, local RPC fixture.
 * Run `npm run build` first. No production services or credentials are used.
 */
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const hash = value => createHash('sha256').update(value).digest('hex');
const validToken = 'sdmcp_local_fixture_valid';
const exhaustedToken = 'sdmcp_local_fixture_exhausted';
const seenRpc = [];
const fixture = createServer(async (request, response) => {
  let text = '';
  for await (const chunk of request) text += chunk;
  response.setHeader('Content-Type', 'application/json');
  const body = text ? JSON.parse(text) : {};
  seenRpc.push({ path: request.url, body });
  if (request.url === '/rest/v1/rpc/increment_mcp_call') {
    const data = body.p_token_hash === hash(validToken)
      ? { ok: true, token_id: 'fixture-token', user_id: 'fixture-user', tier: 'free', limit: 200, remaining: 199 }
      : { ok: false, reason: body.p_token_hash === hash(exhaustedToken) ? 'quota_exceeded' : 'invalid_token', limit: 200 };
    response.end(JSON.stringify(data));
  } else if (request.url === '/rest/v1/rpc/get_dashboard_stats') {
    response.end(JSON.stringify({ total: 1, sigma: 1 }));
  } else {
    response.statusCode = 404;
    response.end(JSON.stringify({ message: 'Unexpected fixture request' }));
  }
});
fixture.listen(0, '127.0.0.1');
await once(fixture, 'listening');
const fixturePort = fixture.address().port;
const reservation = createServer();
reservation.listen(0, '127.0.0.1');
await once(reservation, 'listening');
const port = reservation.address().port;
await new Promise(resolve => reservation.close(resolve));
let logs = '';
const app = spawn(process.execPath, ['node_modules/next/dist/bin/next', 'start', '-p', String(port), '-H', '127.0.0.1'], {
  cwd: fileURLToPath(new URL('..', import.meta.url)),
  env: {
    ...process.env,
    NEXT_PUBLIC_SUPABASE_URL: `http://127.0.0.1:${fixturePort}`,
    NEXT_PUBLIC_SUPABASE_ANON_KEY: 'local-fixture-anon-key',
    SUPABASE_SERVICE_ROLE_KEY: 'local-fixture-service-key',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
app.stdout.on('data', chunk => { logs += chunk; });
app.stderr.on('data', chunk => { logs += chunk; });
const endpoint = `http://127.0.0.1:${port}/api/mcp/mcp`;
async function call(method, params = {}, token = validToken) {
  return fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json', Accept: 'application/json, text/event-stream',
      'MCP-Protocol-Version': '2025-11-25', ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(10000),
  });
}
async function payload(response) {
  const body = await response.text();
  return JSON.parse(response.headers.get('content-type')?.includes('text/event-stream')
    ? body.split('\n').find(line => line.startsWith('data: ') && line.length > 6).slice(6)
    : body);
}
try {
  let ready = false;
  for (let attempt = 0; attempt < 80; attempt++) {
    try {
      const response = await fetch(endpoint, { signal: AbortSignal.timeout(500) });
      if (response.status === 401) { ready = true; break; }
    } catch { /* wait only for this local server to start */ }
    if (app.exitCode !== null) throw new Error(`Next exited ${app.exitCode}`);
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.ok(ready, 'built Next app must start');
  assert.equal(seenRpc.length, 0, 'missing token must not reach Supabase');
  const initialized = await call('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'http-smoke', version: '1' } });
  assert.equal(initialized.status, 200);
  assert.equal((await payload(initialized)).result.serverInfo.name, 'security-detections-hosted');
  const listed = await call('tools/list');
  assert.equal((await payload(listed)).result.tools.length, 25);
  const called = await call('tools/call', { name: 'get_stats', arguments: {} });
  assert.deepEqual(JSON.parse((await payload(called)).result.content[0].text), { total: 1, sigma: 1 });
  assert.equal((await call('tools/list', {}, 'sdmcp_unknown')).status, 401);
  assert.equal((await call('tools/call', { name: 'get_stats', arguments: {} }, exhaustedToken)).status, 429);
  assert.equal(seenRpc.filter(call => call.path.endsWith('get_dashboard_stats')).length, 1);
  const invalid = await payload(await call('tools/call', { name: 'search', arguments: { query: '', limit: 101 } }));
  assert.ok(invalid.error || invalid.result?.isError);
  assert.ok(seenRpc.every(call => !JSON.stringify(call.body).includes('sdmcp_')), 'RPC receives only token hashes');
  const account = await fetch(`http://127.0.0.1:${port}/account`, { redirect: 'manual', signal: AbortSignal.timeout(10000) });
  assert.equal(account.status, 307);
  assert.ok(account.headers.get('location')?.includes('/login'));
  console.log('PASS built HTTP route: initialize, 25 tools, call, missing/invalid token, quota, invalid arguments, hashed RPC, protected-page redirect');
} catch (error) {
  console.error(logs);
  throw error;
} finally {
  app.kill('SIGTERM');
  if (app.exitCode === null) await once(app, 'exit');
  await new Promise(resolve => fixture.close(resolve));
}
