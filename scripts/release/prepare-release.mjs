import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compareVersions, repository, stableVersion, releaseCIReady } from './auto-release.mjs';
import { verifyRelease } from './verify-release.mjs';

export function validateRelease({ ref, tag, release, head, tagCommit, sourceVersion }) {
  assert.equal(ref, `refs/tags/${tag}`, 'Publishing requires a tag ref');
  assert.match(tag, /^v/, 'Release tag requires v prefix');
  stableVersion(tag.slice(1));
  assert.equal(release.tag_name, tag, 'Release/tag mismatch');
  assert.equal(release.draft, false, 'Draft releases cannot publish');
  assert.equal(release.prerelease, false, 'Prereleases cannot publish stable npm');
  assert.match(head, /^[a-f0-9]{40}$/);
  assert.equal(tagCommit, head, 'Tag must identify the exact checkout');
  assert(compareVersions(tag.slice(1), sourceVersion) >= 0, 'Release cannot precede source version');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    assert.equal(process.env.GITHUB_REPOSITORY, repository);
    assert(['release', 'workflow_dispatch'].includes(process.env.GITHUB_EVENT_NAME), 'Unsupported publishing event');
    const tag = process.env.GITHUB_REF_NAME;
    // Validate before interpolating the ref into git or API arguments.
    assert.match(tag, /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
    const git = args => execFileSync('git', args, { encoding: 'utf8', timeout: 30000 }).trim();
    const release = JSON.parse(execFileSync('gh', ['api', `repos/${repository}/releases/tags/${tag}`], { encoding: 'utf8', timeout: 30000 }));
    const gh = args => JSON.parse(execFileSync('gh', args, { encoding: 'utf8', timeout: 60000 }));
    assert(releaseCIReady(gh, git(['rev-parse', 'HEAD'])), 'Every required main CI workflow must pass for the release commit');
    const read = name => JSON.parse(readFileSync(name, 'utf8'));
    const metadata = () => ({ pkg: read('package.json'), lock: read('package-lock.json'), server: read('server.json') });
    verifyRelease(metadata());
    validateRelease({ ref: process.env.GITHUB_REF, tag, release, head: git(['rev-parse', 'HEAD']),
      tagCommit: git(['rev-parse', `${tag}^{commit}`]), sourceVersion: read('package.json').version });
    git(['merge-base', '--is-ancestor', 'HEAD', 'origin/main']);
    assert.equal(git(['status', '--porcelain']), '', 'Release checkout must start clean');
    // Derive build metadata from the immutable tag without pushing to protected main.
    execFileSync('npm', ['version', tag.slice(1), '--no-git-tag-version', '--allow-same-version'], { stdio: 'inherit', timeout: 30000 });
    verifyRelease({ ...metadata(), tag });
    const changed = git(['diff', '--name-only']).split('\n').filter(Boolean);
    assert(changed.every(file => ['package.json', 'package-lock.json', 'server.json'].includes(file)), 'Version materialization changed unexpected source files');
    console.log(`Release build metadata matches ${tag}; source remains on protected main.`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
