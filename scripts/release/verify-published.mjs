import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readMetadata, verifyRelease } from './verify-release.mjs';

export function verifyPublishedMetadata(published, server) {
  assert(published && typeof published === 'object' && !Array.isArray(published), 'Invalid published npm metadata');
  assert.equal(server.name, 'io.github.MHaggis/security-detections-mcp', 'Unexpected Registry namespace');
  assert.equal(server.packages?.length, 1, 'Expected one npm package');
  assert.equal(server.packages[0].identifier, 'security-detections-mcp', 'Unexpected npm package');
  assert.equal(server.packages[0].version, server.version, 'Registry version mismatch');
  assert.equal(published.name, server.packages[0].identifier, 'Published npm name mismatch');
  assert.equal(published.version, server.version, 'Published npm version mismatch');
  assert.equal(published.mcpName, server.name, 'Published npm mcpName must match the case-sensitive Registry namespace');
}

export async function checkPublishedMetadata(server, request = fetch) {
  assert.equal(server.packages?.[0]?.identifier, 'security-detections-mcp', 'Unexpected npm package');
  assert.match(server.version, /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
  const response = await request(`https://registry.npmjs.org/security-detections-mcp/${server.version}`,
    { redirect: 'error', signal: AbortSignal.timeout(30000) });
  assert.equal(response.status, 200, 'Could not verify exact published npm metadata');
  verifyPublishedMetadata(await response.json(), server);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const metadata = readMetadata();
  verifyRelease({ ...metadata, tag: process.env.GITHUB_REF_NAME });
  await checkPublishedMetadata(metadata.server);
  console.log(`Verified published npm ${metadata.pkg.version} mcpName matches ${metadata.server.name}`);
}
