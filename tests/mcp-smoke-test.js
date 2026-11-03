import './isolated-db.js';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [fileURLToPath(new URL('../dist/index.js', import.meta.url))],
  env: {
    DETECTIONS_DB_PATH: process.env.DETECTIONS_DB_PATH,
    JAMF_PROTECT_PATHS: fileURLToPath(new URL('./fixtures/jamf_protect', import.meta.url)),
  },
  stderr: 'pipe',
});
const client = new Client({ name: 'smoke-test', version: '1.0.0' });
let stderr = '';
transport.stderr?.on('data', chunk => { stderr += chunk.toString(); });
try {
  await client.connect(transport, { timeout: 30000 });
  const { tools } = await client.listTools();
  for (const name of ['search', 'get_by_id', 'list_by_source', 'get_stats']) {
    assert(tools.some(tool => tool.name === name), `Missing tool ${name}`);
  }
  const result = await client.callTool({ name: 'list_by_source', arguments: { source_type: 'jamf_protect', limit: 10 } });
  assert(!result.isError, JSON.stringify(result));
  const text = result.content.filter(item => item.type === 'text').map(item => item.text).join('\n');
  assert(text.includes('dscl'), 'Fixture data must survive indexing and a real stdio tool call');
  const invalid = await client.callTool({ name: 'nonexistent_tool', arguments: {} });
  assert(invalid.isError, 'Unknown tool must return an error');
  console.log(`PASS: MCP initialize, ${tools.length} tools, fixture query and unknown-tool rejection`);
} catch (error) {
  console.error(stderr);
  throw error;
} finally {
  await client.close();
  await transport.close();
}
