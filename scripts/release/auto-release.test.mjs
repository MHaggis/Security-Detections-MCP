import assert from 'node:assert/strict';
import { test } from 'node:test';
import { automateRelease, eligibleRun, planRelease, repository, stableVersion, requiredWorkflows, releaseCIReady, npmStableVersion } from './auto-release.mjs';
import { validateRelease } from './prepare-release.mjs';
import { checkUnpublished } from './check-unpublished.mjs';

const sha = 'a'.repeat(40);
const trusted = () => ({ repository: { full_name: repository }, head_repository: { full_name: repository },
  path: '.github/workflows/ci.yml', event: 'push', head_branch: 'main', status: 'completed', conclusion: 'success', head_sha: sha });

test('patch versions advance stable tags, ignoring prereleases and numeric lexical ordering', () => {
  assert.deepEqual(planRelease('0.1.4', ['v0.1.4', 'v0.1.9', 'v0.1.10', 'v9.0.0-beta.0', 'other'], []), { tag: 'v0.1.11', existing: false });
  assert.deepEqual(planRelease('0.2.0', ['v0.1.5'], []), { tag: 'v0.2.0', existing: false });
  assert.deepEqual(planRelease('0.1.4', [], []), { tag: 'v0.1.4', existing: false });
});
test('retries reuse the commit tag and reject ambiguous tags', () => {
  assert.deepEqual(planRelease('0.1.4', ['v0.1.5'], ['v0.1.5']), { tag: 'v0.1.5', existing: true });
  assert.throws(() => planRelease('0.1.4', ['v0.1.5', 'v0.1.6'], ['v0.1.5', 'v0.1.6']), /Multiple/);
});
test('version input rejects shell text, prereleases, leading zeros and overflow', () => {
  for (const value of ['v0.1.4', '0.1.4-beta.0', '01.1.4', '1.2.3\n', '1.2.3;id', '1.2.9007199254740992']) assert.throws(() => stableVersion(value));
});
test('only successful trusted main push CI can enter release orchestration', () => {
  assert(eligibleRun(trusted()));
  for (const change of [
    { repository: { full_name: 'fork/repo' } }, { head_repository: { full_name: 'fork/repo' } },
    { event: 'pull_request' }, { head_branch: 'feature' }, { conclusion: 'failure' },
    { conclusion: 'cancelled' }, { status: 'in_progress' }, { path: '.github/workflows/other.yml' }, { head_sha: 'bad' },
  ]) assert.equal(eligibleRun({ ...trusted(), ...change }), false);
});

function harness({ main = [sha, sha], runs = [], release, existingTag = false, remoteTag = sha } = {}) {
  const writes = [];
  const gh = (args, json = true) => {
    if (!json) { writes.push(args); return ''; }
    if (args[0] === 'release') return release ? [release] : [];
    const path = args.at(-1);
    if (path.endsWith('/git/ref/heads/main')) return { object: { sha: main.shift() ?? sha } };
    if (path.includes('/actions/runs?')) return [{workflow_runs: requiredWorkflows.map((path,i)=>({...trusted(),path,id:i+1}))}];
    if (path.includes('/actions/workflows/')) return [{ workflow_runs: runs }];
    if (path.includes('/commits/')) return { sha: remoteTag };
    if (path === `repos/${repository}`) return { private: false };
    throw new Error(`Unexpected API ${path}`);
  };
  const git = args => args.includes('--points-at') ? (existingTag ? 'v0.1.5\n' : '') : 'v0.1.4\n' + (existingTag ? 'v0.1.5\n' : '');
  return { writes, execute: () => automateRelease({ run: trusted(), head: sha, sourceVersion: '0.1.4', gh, git, log() {} }) };
}
test('latest green main creates a release on that exact SHA then explicitly dispatches tag', () => {
  const h = harness(); assert.equal(h.execute(), 'v0.1.5');
  assert.equal(h.writes.length, 2);
  assert(h.writes[0].includes(sha));
  assert.deepEqual(h.writes[1], ['workflow', 'run', 'publish.yml', '--repo', repository, '--ref', 'v0.1.5']);
});
test('stale CI and main advancing before first write produce no remote writes', () => {
  for (const main of [['b'.repeat(40)], [sha, 'b'.repeat(40)]]) {
    const h = harness({ main }); assert.equal(h.execute(), undefined); assert.equal(h.writes.length, 0);
  }
});
test('tag creation interruption recovers without allocating another version', () => {
  const h = harness({ existingTag: true }); assert.equal(h.execute(), 'v0.1.5');
  assert(h.writes[0].includes('--verify-tag')); assert.equal(h.writes.length, 2);
});
test('release creation interruption dispatches the existing release once', () => {
  const h = harness({ existingTag: true, release: { tagName: 'v0.1.5', isDraft: false, isPrerelease: false } });
  h.execute(); assert.equal(h.writes.length, 1); assert.equal(h.writes[0][0], 'workflow');
});
test('concurrent remote tag allocation fails closed before dispatch', () => {
  const h = harness({ remoteTag: 'b'.repeat(40) });
  assert.throws(h.execute, /Remote release tag/);
  assert.equal(h.writes.length, 1);
  assert.equal(h.writes[0][0], 'release');
});
for (const [status, conclusion] of [['queued', null], ['in_progress', null], ['completed', 'success'], ['completed', 'failure']]) {
  test(`existing ${status}/${conclusion} publication never dispatches a duplicate or allocates another version`, () => {
    const h = harness({ existingTag: true, release: { tagName: 'v0.1.5', isDraft: false, isPrerelease: false }, runs: [{ head_sha: sha, status, conclusion }] });
    if (conclusion === 'failure') assert.throws(h.execute, /rerun only failed jobs/); else assert.equal(h.execute(), 'v0.1.5');
    assert.equal(h.writes.length, 0);
  });
}
test('dispatch guard binds stable public release to exact tag checkout', () => {
  const valid = { ref: 'refs/tags/v0.1.5', tag: 'v0.1.5', release: { tag_name: 'v0.1.5', draft: false, prerelease: false, immutable: false }, head: sha, tagCommit: sha, sourceVersion: '0.1.4' };
  validateRelease(valid);
  for (const change of [{ ref: 'refs/heads/main' }, { tagCommit: 'b'.repeat(40) }, { tag: 'v0.1.5-beta.0' }, { sourceVersion: '0.1.6' }]) assert.throws(() => validateRelease({ ...valid, ...change }));
  for (const change of [{ draft: true }, { prerelease: true }, { tag_name: 'v0.1.6' }]) assert.throws(() => validateRelease({ ...valid, release: { ...valid.release, ...change } }));
});
test('npm guard permits only an absent version newer than latest and fails closed', async () => {
  const request = (target, latest = '0.1.4', status = 200) => async url => url.endsWith('/latest') ? { status, json: async () => ({ version: latest }) } : { status: target };
  await checkUnpublished('0.1.5', request(404));
  await assert.rejects(checkUnpublished('0.1.5', request(200)), /already exists/);
  await assert.rejects(checkUnpublished('0.1.5', request(503)), /Could not confirm/);
  await assert.rejects(checkUnpublished('0.1.3', request(404)), /advance npm latest/);
  await assert.rejects(checkUnpublished('0.1.5', request(404, '0.1.4', 503)), /verify current/);
  await assert.rejects(checkUnpublished('0.1.5', async () => { throw new Error('offline'); }), /offline/);
});

test('npm baseline prevents reused versions even when git tags lag npm', () => {
  assert.deepEqual(planRelease('3.3.0', [], [], '3.3.0'), {tag:'v3.3.1',existing:false});
  assert.deepEqual(planRelease('3.3.0', ['v3.3.1'], [], '3.3.9'), {tag:'v3.3.10',existing:false});
  assert.deepEqual(planRelease('4.0.0', ['v3.3.1'], [], '3.3.9'), {tag:'v4.0.0',existing:false});
});
test('all exact main workflows must pass; missing, fork, stale and latest failed rerun block', () => {
  const good = requiredWorkflows.map((path,i)=>({...trusted(),path,id:i+1}));
  const ready = rows => releaseCIReady(()=>[{workflow_runs:rows}],sha);
  assert(ready(good));
  assert(!ready(good.slice(1)));
  assert(!ready(good.map((r,i)=>i ? r : {...r,head_sha:'b'.repeat(40)})));
  assert(!ready(good.map((r,i)=>i ? r : {...r,head_repository:{full_name:'attacker/fork'}})));
  assert(!ready([...good,{...good[0],id:999,conclusion:'failure'}]));
  assert(!ready([...good,{...good[0],id:999,status:'in_progress',conclusion:null}]));
});
test('npm baseline includes stable versions beyond latest and fails closed offline', async () => {
  assert.equal(await npmStableVersion(async()=>({status:200,json:async()=>({versions:{'3.3.0':{},'3.3.10':{},'9.0.0-beta.1':{}}})})),'3.3.10');
  await assert.rejects(npmStableVersion(async()=>({status:503})),/verify npm/);
  await assert.rejects(npmStableVersion(async()=>({status:200,json:async()=>({versions:{}})})),/baseline/);
});

test('artifact validation rejects corruption, version mismatch and path substitution', async () => {
  const {validateArtifact}=await import('./publish-artifact.mjs');
  const {createHash}=await import('node:crypto');
  const bytes=Buffer.from('tested package bytes');
  const valid={version:'3.3.1',filename:'security-detections-mcp-3.3.1.tgz',sha256:createHash('sha256').update(bytes).digest('hex')};
  validateArtifact(valid,bytes,'3.3.1');
  assert.throws(()=>validateArtifact(valid,Buffer.from('changed bytes'),'3.3.1'),/digest/);
  assert.throws(()=>validateArtifact({...valid,filename:'../untrusted.tgz'},bytes,'3.3.1'),/filename/);
  assert.throws(()=>validateArtifact(valid,bytes,'3.3.2'));
});
test('all release metadata must agree, including Registry ownership', async () => {
  const {verifyRelease}=await import('./verify-release.mjs');
  const pkg={name:'security-detections-mcp',version:'3.3.1',mcpName:'io.github.MHaggis/security-detections-mcp'};
  const lock={name:pkg.name,version:pkg.version,packages:{'':{version:pkg.version}}};
  const server={name:pkg.mcpName,version:pkg.version,description:'Detection search',packages:[{registryType:'npm',identifier:pkg.name,version:pkg.version}]};
  verifyRelease({pkg,lock,server});
  assert.throws(()=>verifyRelease({pkg,lock,server:{...server,version:'2.1.0'}}));
  assert.throws(()=>verifyRelease({pkg,lock,server:{...server,name:'io.github.attacker/server'}}));
  // The Registry's OIDC grant uses the canonical GitHub owner case, even
  // though GitHub URLs/usernames otherwise compare case-insensitively.
  const wrongCase = 'io.github.mhaggis/security-detections-mcp';
  assert.throws(()=>verifyRelease({pkg:{...pkg,mcpName:wrongCase},lock,server:{...server,name:wrongCase}}));
  assert.throws(()=>verifyRelease({pkg,lock,server:{...server,name:wrongCase}}));
});
