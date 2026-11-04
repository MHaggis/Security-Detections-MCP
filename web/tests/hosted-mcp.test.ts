import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';

// Only the database boundary is replaced. Production auth, tokens, route,
// tool registration, Zod validation, and MCP SDK HTTP handling remain real.
const database = vi.hoisted(() => ({
  rpc: vi.fn(),
  search: vi.fn(),
  stats: vi.fn(),
  lookup: vi.fn(),
  raw: vi.fn(),
}));
vi.mock('../lib/mcp/db', async (original) => ({
  ...await original<typeof import('../lib/mcp/db')>(),
  getServiceClient: () => ({ rpc: database.rpc }),
  searchDetections: database.search,
  getStats: database.stats,
  getDetectionById: database.lookup,
  getRawYaml: database.raw,
}));
import { GET, POST, DELETE } from '../app/api/mcp/[transport]/route';

const token = 'sdmcp_TEST_FIXTURE_ONLY';
const endpoint = 'https://example.test/api/mcp/mcp';

function request(method: string, params: Record<string, unknown> = {}, authorization: string | null = `Bearer ${token}`, modern = false) {
  const headers = new Headers({
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
    'MCP-Protocol-Version': modern ? '2026-07-28' : '2025-11-25',
  });
  if (authorization !== null) headers.set('Authorization', authorization);
  if (modern) {
    headers.set('MCP-Method', method);
    if (typeof params.name === 'string') headers.set('MCP-Name', params.name);
    params = { ...params, _meta: {
      'io.modelcontextprotocol/protocolVersion': '2026-07-28',
      'io.modelcontextprotocol/clientInfo': { name: 'dependency-regression', version: '1' },
      'io.modelcontextprotocol/clientCapabilities': {},
    } };
  }
  return new Request(endpoint, { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
}

async function payload(response: Response) {
  const body = await response.text();
  if (response.headers.get('content-type')?.includes('text/event-stream')) {
    const event = body.split('\n').find(line => line.startsWith('data: ') && line.length > 6);
    expect(event, body).toBeDefined();
    return JSON.parse(event!.slice(6));
  }
  return JSON.parse(body);
}

beforeEach(() => {
  vi.resetAllMocks();
  database.rpc.mockResolvedValue({ data: { ok: true, token_id: 'token-1', user_id: 'user-1', tier: 'free', limit: 200, remaining: 199 }, error: null });
  database.stats.mockResolvedValue({ total: 1, sigma: 1 });
  database.search.mockResolvedValue([{ id: 'fixture', name: 'PowerShell', source_type: 'sigma' }]);
});

describe('DEP-003: real hosted MCP protocol compatibility', () => {
  it('initializes a legacy Streamable HTTP client without a persistent session', async () => {
    const response = await POST(request('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } }));
    expect(response.status).toBe(200);
    expect(response.headers.get('mcp-session-id')).toBeNull();
    const body = await payload(response);
    expect(body.result.protocolVersion).toBe('2025-11-25');
    expect(body.result.serverInfo.name).toBe('security-detections-hosted');
  });

  it.each([false, true])('lists read-only tools and calls them (modern=%s)', async modern => {
    const response = await POST(request('tools/list', {}, undefined, modern));
    expect(response.status).toBe(200);
    const list = await payload(response);
    expect(list.result.tools).toHaveLength(25);
    for (const tool of list.result.tools) {
      expect(tool.annotations.readOnlyHint).toBe(true);
      expect(tool.annotations.destructiveHint).toBe(false);
      expect(tool.inputSchema.type).toBe('object');
    }
    const result = await POST(request('tools/call', { name: 'get_stats', arguments: {} }, undefined, modern));
    expect(result.status).toBe(200);
    const body = await payload(result);
    expect(JSON.parse(body.result.content[0].text)).toEqual({ total: 1, sigma: 1 });
    expect(database.stats).toHaveBeenCalledOnce();
  });

  it('discovers the modern stateless server', async () => {
    const response = await POST(request('server/discover', {}, undefined, true));
    expect(response.status).toBe(200);
    expect((await payload(response)).error).toBeUndefined();
  });

  it('preserves search defaults and valid explicit filters', async () => {
    const response = await POST(request('tools/call', { name: 'search', arguments: { query: 'powershell' } }));
    expect(response.status).toBe(200);
    expect((await payload(response)).result.isError).not.toBe(true);
    expect(database.search).toHaveBeenCalledWith('powershell', 50, undefined);
    await POST(request('tools/call', { name: 'search', arguments: { query: 'powershell', limit: 10, source_type: 'jamf_protect' } }));
    expect(database.search).toHaveBeenLastCalledWith('powershell', 10, 'jamf_protect');
  });

  it.each([false, true])('ID-003: forwards qualified identity through SDK2 (modern=%s)', async modern => {
    database.lookup.mockResolvedValue({ id: 'collision', source_type: 'elastic', name: 'Elastic rule' });
    database.raw.mockResolvedValue('elastic: rule');
    const args = { id: 'collision', source_type: 'elastic' };
    const lookup = await payload(await POST(request('tools/call', { name: 'get_by_id', arguments: args }, undefined, modern)));
    expect(lookup.result.isError).not.toBe(true);
    expect(JSON.parse(lookup.result.content[0].text).source_type).toBe('elastic');
    expect(database.lookup).toHaveBeenCalledExactlyOnceWith('collision', 'elastic');
    const raw = await payload(await POST(request('tools/call', { name: 'get_raw_yaml', arguments: args }, undefined, modern)));
    expect(raw.result.isError).not.toBe(true);
    expect(JSON.parse(raw.result.content[0].text).yaml).toBe('elastic: rule');
    expect(database.raw).toHaveBeenCalledExactlyOnceWith('collision', 'elastic');
  });

  it.each(['get_by_id', 'get_raw_yaml'])('ID-003: exposes ambiguity without picking a source for %s', async name => {
    const lookup = name === 'get_by_id' ? database.lookup : database.raw;
    lookup.mockRejectedValue(new Error('Ambiguous detection ID collision. Specify source_type: elastic, sigma'));
    const body = await payload(await POST(request('tools/call', { name, arguments: { id: 'collision' } })));
    expect(body.result.isError).toBe(true);
    expect(body.result.content[0].text).toContain('Specify source_type: elastic, sigma');
    expect(lookup).toHaveBeenCalledExactlyOnceWith('collision', undefined);
  });

  it.each(['get_by_id', 'get_raw_yaml'])('ID-003: rejects invalid source before %s lookup', async name => {
    const body = await payload(await POST(request('tools/call', { name, arguments: { id: 'collision', source_type: 'invalid' } })));
    expect(Boolean(body.error || body.result?.isError)).toBe(true);
    expect(database.lookup).not.toHaveBeenCalled();
    expect(database.raw).not.toHaveBeenCalled();
  });

  it.each([
    { query: '' }, { query: 'powershell', limit: 0 }, { query: 'powershell', limit: 101 },
    { query: 'powershell', limit: 1.5 }, { query: 'powershell', source_type: 'invalid' },
  ])('DEP-002: rejects invalid tool arguments before dispatch: %j', async args => {
    const response = await POST(request('tools/call', { name: 'search', arguments: args }));
    const body = await payload(response);
    expect(Boolean(body.error || body.result?.isError)).toBe(true);
    expect(database.search).not.toHaveBeenCalled();
  });

  it('rejects unknown tools without dispatch', async () => {
    const body = await payload(await POST(request('tools/call', { name: 'rebuild_index', arguments: {} })));
    expect(Boolean(body.error || body.result?.isError)).toBe(true);
    expect(database.search).not.toHaveBeenCalled();
    expect(database.stats).not.toHaveBeenCalled();
  });

  it('keeps unsupported transport paths unavailable', async () => {
    const original = request('tools/list');
    expect((await POST(new Request('https://example.test/api/mcp/sse', original))).status).toBe(404);
  });
});

describe('DEP-004: authentication and quota remain ahead of protocol dispatch', () => {
  it.each([null, '', 'Bearer invalid', 'Basic abc'])('rejects missing/malformed credentials %s without RPC', async header => {
    const response = await POST(request('tools/call', { name: 'get_stats', arguments: {} }, header));
    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toContain('https://example.test/.well-known/oauth-protected-resource');
    expect(database.rpc).not.toHaveBeenCalled();
    expect(database.stats).not.toHaveBeenCalled();
  });

  it.each([['invalid_token', 401], ['revoked', 401], ['blocked', 403], ['quota_exceeded', 429]] as const)(
    'rejects %s tokens with HTTP %s before dispatch', async (reason, status) => {
      database.rpc.mockResolvedValue({ data: { ok: false, reason, limit: 200 }, error: null });
      const response = await POST(request('tools/call', { name: 'get_stats', arguments: {} }));
      expect(response.status).toBe(status);
      expect(database.rpc).toHaveBeenCalledExactlyOnceWith('increment_mcp_call', { p_token_hash: createHash('sha256').update(token).digest('hex') });
      expect(database.stats).not.toHaveBeenCalled();
    },
  );

  it.each([{ data: null, error: null }, { data: null, error: { message: 'backend fixture failure' } }])('fails closed on backend failure', async result => {
    database.rpc.mockResolvedValue(result);
    expect((await POST(request('tools/call', { name: 'get_stats', arguments: {} }))).status).toBe(500);
    expect(database.stats).not.toHaveBeenCalled();
  });

  it.each(['GET', 'DELETE'])('authenticates %s before handler execution', async method => {
    const response = await (method === 'GET' ? GET : DELETE)(new Request(endpoint, { method }));
    expect(response.status).toBe(401);
    expect(database.rpc).not.toHaveBeenCalled();
  });

  it('allows the final permitted call and rejects the next request', async () => {
    database.rpc.mockResolvedValueOnce({ data: { ok: true, token_id: 'token-1', user_id: 'user-1', tier: 'free', limit: 200, remaining: 0 }, error: null });
    database.rpc.mockResolvedValueOnce({ data: { ok: false, reason: 'quota_exceeded', limit: 200 }, error: null });
    expect((await POST(request('tools/call', { name: 'get_stats', arguments: {} }))).status).toBe(200);
    expect((await POST(request('tools/call', { name: 'get_stats', arguments: {} }))).status).toBe(429);
    expect(database.stats).toHaveBeenCalledOnce();
  });
});
