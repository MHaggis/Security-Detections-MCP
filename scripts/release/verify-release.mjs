import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export function verifyRelease({ pkg, lock, server, tag = `v${pkg.version}` }) {
  assert.equal(pkg.name, 'security-detections-mcp');
  assert.equal(pkg.mcpName, 'io.github.MHaggis/security-detections-mcp');
  assert.equal(server.name, pkg.mcpName);
  assert(server.description.length > 0 && server.description.length <= 100, 'Registry description must be 1–100 characters');
  assert.equal(tag, `v${pkg.version}`, 'Release tag must match package version');
  assert.equal(lock.name, pkg.name);
  assert.equal(lock.version, pkg.version, 'Lockfile version must match');
  assert.equal(lock.packages?.['']?.version, pkg.version, 'Lockfile root version must match');
  assert.equal(server.version, pkg.version, 'Registry version must match');
  assert.equal(server.packages?.length, 1);
  assert.equal(server.packages[0].registryType, 'npm');
  assert.equal(server.packages[0].identifier, pkg.name);
  assert.equal(server.packages[0].version, pkg.version, 'Registry package version must match');
}
export function readMetadata() {
  const read = name => JSON.parse(readFileSync(name, 'utf8'));
  return { pkg: read('package.json'), lock: read('package-lock.json'), server: read('server.json') };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  verifyRelease({ ...readMetadata(), tag: process.argv[2] });
  console.log('Release metadata matches');
}
