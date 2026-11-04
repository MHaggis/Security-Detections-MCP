import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compareVersions, stableVersion } from './auto-release.mjs';

export async function checkUnpublished(version, request = fetch) {
  stableVersion(version);
  const root = 'https://registry.npmjs.org/security-detections-mcp';
  const get = url => request(url, { redirect: 'error', signal: AbortSignal.timeout(30000) });
  const target = await get(`${root}/${version}`);
  assert.equal(target.status, 404, target.status === 200
    ? 'npm version already exists. Inspect the original run; rerun only failed Registry/desktop jobs, never republish npm.'
    : 'Could not confirm npm version availability; refusing to publish');
  const latest = await get(`${root}/latest`);
  assert.equal(latest.status, 200, 'Could not verify current npm latest; refusing to publish');
  const current = await latest.json();
  assert(compareVersions(version, current.version) > 0, 'Publication must advance npm latest; old releases cannot roll it backward');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    await checkUnpublished(JSON.parse(readFileSync('package.json', 'utf8')).version);
    console.log('New stable npm version confirmed; latest will advance.');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
