import { describe, it, expect, beforeEach } from 'vitest';
import { MCPClient, getMCPClient } from '../../tools/mcp-client.js';
import { setConfig, loadConfig, resetConfig } from '../../config.js';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';

describe('MCPClient', () => {
  let client: MCPClient;

  beforeEach(() => {
    resetConfig();
    const cfg = loadConfig();
    cfg.dryRun = true;
    setConfig(cfg);
    client = new MCPClient();
  });

  it('routes splunk-mcp calls (returns pending when MCP not enabled)', async () => {
    const result = await client.callTool({
      server: 'splunk-mcp',
      tool: 'search',
      arguments: { search: 'index=win' },
    });
    expect(result.success).toBe(true);
    const inner = result.result as any;
    // SPLUNK_MCP_ENABLED is not set, so client returns pending structure
    expect(inner._mcp_pending).toBe(true);
  });

  it('routes mitre-attack calls', async () => {
    const result = await client.callTool({
      server: 'mitre-attack',
      tool: 'get_technique',
      arguments: { id: 'T1059.001' },
    });
    expect(result.success).toBe(true);
    const inner = result.result as any;
    expect(inner._mcp_pending).toBe(true);
  });

  it('returns error for unknown server', async () => {
    const result = await client.callTool({
      server: 'unknown-server',
      tool: 'foo',
      arguments: {},
    });
    expect(result.success).toBe(false);
    expect(result.error).toContain('Unknown MCP server');
  });

  it('getMCPClient returns singleton', () => {
    const a = getMCPClient();
    const b = getMCPClient();
    expect(a).toBe(b);
  });
});

// Exercise the real SQLite seam in child processes so importing the database
// cannot bind the test runner to a developer's default cache or singleton.
// Run root and agents builds before this suite.
describe('MCPClient direct database integration', () => {
  const root = new URL('../../../', import.meta.url);
  const require = createRequire(import.meta.url);

  for (const [label, relativePath, nodeArgs] of [
    ['source via tsx', 'agents/tools/mcp-client.ts', ['--import', require.resolve('tsx')]],
    ['compiled JavaScript', 'agents/dist/tools/mcp-client.js', []],
  ] as const) {
    for (const hasDatabase of [true, false]) {
      it(`${label}: ${hasDatabase ? 'queries indexed detections' : 'keeps missing database pending'}`, () => {
        const directory = mkdtempSync(join(tmpdir(), 'agents-db-client-'));
        const script = `
          import assert from 'node:assert/strict';
          import { existsSync } from 'node:fs';
          const db = await import(${JSON.stringify(new URL('dist/db/index.js', root).href)});
          assert.equal(db.getDbPath(), process.env.DETECTIONS_DB_PATH);
          if (${hasDatabase}) {
            db.initDb().prepare(\`INSERT INTO detections
              (id, name, description, query, source_type, mitre_ids)
              VALUES (?, ?, ?, ?, ?, ?)\`).run(
                'client-regression', 'PowerShell fixture', 'Client integration fixture',
                'powershell.exe', 'sigma', '["T1059.001"]'
              );
            db.closeDb();
          }
          const { MCPClient } = await import(${JSON.stringify(new URL(relativePath, root).href)});
          const client = new MCPClient();
          const search = await client.callTool({
            server: 'security-detections', tool: 'search',
            arguments: { query: 'powershell', limit: 5 },
          });
          assert.equal(search.success, true);
          if (${hasDatabase}) {
            assert.ok(Array.isArray(search.result), 'must query SQLite, not return pending');
            assert.deepEqual(search.result.map(row => row.id), ['client-regression']);
            const techniques = await client.callTool({
              server: 'security-detections', tool: 'list_by_mitre',
              arguments: { technique_id: 'T1059.001' },
            });
            assert.equal(techniques.success, true);
            assert.deepEqual(techniques.result.map(row => row.id), ['client-regression']);
            const stats = await client.callTool({
              server: 'security-detections', tool: 'get_stats', arguments: {},
            });
            assert.equal(stats.success, true);
            assert.equal(stats.result.total, 1);
            assert.equal(stats.result.sigma, 1);
          } else {
            assert.equal(search.result._mcp_pending, true);
            assert.equal(existsSync(process.env.DETECTIONS_DB_PATH), false);
          }
          db.closeDb();
        `;
        try {
          const result = spawnSync(process.execPath, [...nodeArgs, '--input-type=module', '-e', script], {
            cwd: directory,
            env: { ...process.env, DETECTIONS_DB_PATH: join(directory, 'detections.sqlite') },
            encoding: 'utf8',
            timeout: 15000,
          });
          expect(result.error).toBeUndefined();
          expect(result.status, result.stdout + result.stderr).toBe(0);
        } finally {
          rmSync(directory, { recursive: true, force: true });
        }
      });
    }
  }
});
