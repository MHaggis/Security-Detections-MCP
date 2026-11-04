import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const repository = 'MHaggis/Security-Detections-MCP';
export const requiredWorkflows = [
  '.github/workflows/ci.yml', '.github/workflows/agents-cli.yml',
  '.github/workflows/automation.yml', '.github/workflows/hosted-security.yml',
  '.github/workflows/release-validation.yml',
];
export function releaseCIReady(gh, sha) {
  const runs = gh(['api', '--paginate', '--slurp', `repos/${repository}/actions/runs?head_sha=${sha}&event=push&per_page=100`])
    .flatMap(page => page.workflow_runs);
  return requiredWorkflows.every(path => {
    const latest = runs.filter(run => run.path === path && run.head_sha === sha && run.event === 'push' &&
      run.head_branch === 'main' && run.head_repository?.full_name === repository)
      .sort((a, b) => b.id - a.id)[0];
    return latest?.status === 'completed' && latest.conclusion === 'success';
  });
}
export async function npmStableVersion(request = fetch) {
  const response = await request('https://registry.npmjs.org/security-detections-mcp',
    { redirect: 'error', signal: AbortSignal.timeout(30000) });
  assert.equal(response.status, 200, 'Could not verify npm versions; refusing version allocation');
  const metadata = await response.json();
  const versions = Object.keys(metadata.versions ?? {}).filter(v => /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(v));
  assert(versions.length, 'No stable npm baseline found');
  return versions.sort(compareVersions).at(-1);
}

export function stableVersion(value) {
  assert.match(value, /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/, 'Expected a stable numeric version');
  const parts = value.split('.').map(Number);
  assert(parts.every(Number.isSafeInteger), 'Version exceeds safe integer range');
  return parts;
}
export function compareVersions(left, right) {
  const a = stableVersion(left), b = stableVersion(right);
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}
export function planRelease(sourceVersion, tags, headTags, npmVersion) {
  stableVersion(sourceVersion);
  if (npmVersion !== undefined) stableVersion(npmVersion);
  const stableTags = tags.filter(tag => /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(tag));
  const existing = headTags.filter(tag => stableTags.includes(tag));
  assert(existing.length <= 1, 'Multiple stable release tags identify this commit');
  if (existing.length) return { tag: existing[0], existing: true };
  const versions = [...stableTags.map(tag => tag.slice(1)), ...(npmVersion ? [npmVersion] : [])].sort(compareVersions);
  const last = versions.at(-1);
  if (!last || compareVersions(sourceVersion, last) > 0) return { tag: `v${sourceVersion}`, existing: false };
  const [major, minor, patch] = stableVersion(last);
  const next = `${major}.${minor}.${patch + 1}`;
  stableVersion(next);
  return { tag: `v${next}`, existing: false };
}
export function eligibleRun(run) {
  return run.repository?.full_name === repository && run.head_repository?.full_name === repository &&
    requiredWorkflows.includes(run.path) && run.event === 'push' && run.head_branch === 'main' &&
    run.status === 'completed' && run.conclusion === 'success' && /^[a-f0-9]{40}$/.test(run.head_sha);
}

// Dependency injection lets tests prove mutation order without contacting GitHub.
export function automateRelease({ run, head, sourceVersion, npmVersion, git, gh, log = console.log }) {
  assert(eligibleRun(run), 'Only successful same-repository main push CI may release');
  assert.equal(head, run.head_sha, 'Checkout must be the tested commit');
  assert.equal(gh(['api', `repos/${repository}`]).private, false, 'Repository must be public');
  const currentMain = () => gh(['api', `repos/${repository}/git/ref/heads/main`]).object.sha;
  if (currentMain() !== head) { log('Skipping stale CI: a newer main commit must pass first.'); return; }
  if (!releaseCIReady(gh, head)) { log('Waiting for every required workflow to pass on this exact main commit.'); return; }
  const lines = value => value.trim().split('\n').filter(Boolean);
  const plan = planRelease(sourceVersion, lines(git(['tag', '--list'])), lines(git(['tag', '--points-at', head])), npmVersion);
  const releases = gh(['release', 'list', '--repo', repository, '--limit', '1000', '--json', 'tagName,isDraft,isPrerelease']);
  const release = releases.find(item => item.tagName === plan.tag);
  assert(!release || (!release.isDraft && !release.isPrerelease), 'Existing release must be public and stable');
  const runs = gh(['api', '--paginate', '--slurp', `repos/${repository}/actions/workflows/publish.yml/runs?head_sha=${head}&per_page=100`])
    .flatMap(page => page.workflow_runs).filter(item => item.head_sha === head);
  if (runs.length) {
    assert(release, 'Publication run exists without the expected release');
    if (runs.some(item => item.status !== 'completed' || item.conclusion === 'success')) {
      log(`Publication already queued, running or successful for ${plan.tag}.`); return plan.tag;
    }
    throw new Error(`Publication previously failed for ${plan.tag}; inspect npm and rerun only failed jobs. No new version allocated.`);
  }
  // Check again immediately before the first remote write. No branch bypass or bot commit.
  if (currentMain() !== head) { log('Skipping stale CI before release creation.'); return; }
  if (!release) {
    gh(['release', 'create', plan.tag, '--repo', repository, '--target', head,
      '--title', `Security Detections MCP ${plan.tag}`, '--generate-notes', '--latest',
      ...(plan.existing ? ['--verify-tag'] : [])], false);
  }
  // Another writer may have allocated this tag after checkout. Never dispatch
  // publication unless the remote tag still identifies this exact tested SHA.
  assert.equal(gh(['api', `repos/${repository}/commits/${plan.tag}`]).sha, head,
    'Remote release tag does not identify the tested commit; publication not dispatched');
  // GITHUB_TOKEN-created release events do not trigger workflows; dispatch is explicit.
  gh(['workflow', 'run', 'publish.yml', '--repo', repository, '--ref', plan.tag], false);
  log(`Created/reused ${plan.tag}; dispatched checked trusted publication.`);
  return plan.tag;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    assert.equal(process.env.GITHUB_REPOSITORY, repository);
    assert.equal(process.env.GITHUB_EVENT_NAME, 'workflow_run');
    const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
    assert(Number.isSafeInteger(event.workflow_run?.id), 'Missing CI run ID');
    const gh = (args, json = true) => {
      const output = execFileSync('gh', args, { encoding: 'utf8', timeout: 60000 });
      return json ? JSON.parse(output) : output;
    };
    const git = args => execFileSync('git', args, { encoding: 'utf8', timeout: 30000 });
    const run = gh(['api', `repos/${repository}/actions/runs/${event.workflow_run.id}`]);
    assert.equal(run.head_sha, event.workflow_run.head_sha, 'CI event/API commit mismatch');
    automateRelease({ run, head: git(['rev-parse', 'HEAD']).trim(),
      sourceVersion: JSON.parse(readFileSync('package.json', 'utf8')).version, npmVersion: await npmStableVersion(), git, gh });
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
