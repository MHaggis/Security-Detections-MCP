import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { publishTarball } from './publish-artifact.mjs';

/** Exercise the installed npm CLI against the actual immutable candidate archive. */
export function verifyNpmPublishParser(archive, expected, npmCli = process.env.npm_execpath) {
  assert(npmCli, 'An installed npm CLI path is required for the parser regression');
  archive = resolve(archive);
  const sandbox = mkdtempSync(join(tmpdir(), 'npm-publish-parser-'));
  const digest = () => createHash('sha256').update(readFileSync(archive)).digest('hex');
  const before = digest();
  try {
    const userconfig = join(sandbox, 'user.npmrc');
    const globalconfig = join(sandbox, 'global.npmrc');
    writeFileSync(userconfig, ''); writeFileSync(globalconfig, '');
    const cwd = join(sandbox, 'cwd');
    mkdirSync(join(cwd, 'release-assets'), { recursive: true });
    const copiedArchive = join(cwd, 'release-assets', basename(archive));
    copyFileSync(archive, copiedArchive);
    const copyDigest = () => createHash('sha256').update(readFileSync(copiedArchive)).digest('hex');
    assert.equal(copyDigest(), before, 'Dry-run candidate differs from retained tarball');
    // Deliberately allowlist process essentials: no CI OIDC variables, npm auth,
    // NODE_AUTH_TOKEN, project npm config, or application secrets are inherited.
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
      ['PATH','Path','SystemRoot','SYSTEMROOT','COMSPEC','ComSpec','PATHEXT','TEMP','TMP'].includes(key)));
    Object.assign(env, { NPM_CONFIG_USERCONFIG: userconfig, NPM_CONFIG_GLOBALCONFIG: globalconfig,
      NPM_CONFIG_CACHE: join(sandbox, 'cache'), NPM_CONFIG_UPDATE_NOTIFIER: 'false',
      NPM_CONFIG_AUDIT: 'false', NPM_CONFIG_FUND: 'false', GIT_TERMINAL_PROMPT: '0',
      GIT_SSH_COMMAND: process.platform === 'win32' ? 'cmd /c exit 1' : 'false' });
    // Supply a directory/file relative path to the same publisher helper. This
    // reproduces the original failure shape while the helper resolves it safely.
    const result = JSON.parse(publishTarball(join('release-assets', basename(archive)), { dryRun: true, cwd, env, npmCli }));
    assert.equal(result.name, expected.name, 'npm parsed a different package name');
    assert.equal(result.version, expected.version, 'npm parsed a different package version');
    assert.equal(result.filename, `${expected.name}-${expected.version}.tgz`);
    assert.equal(copyDigest(), before, 'npm dry run modified tested tarball bytes');
    assert.equal(digest(), before, 'Retained tarball bytes changed');
    return { name: result.name, version: result.version, sha256: before };
  } finally { rmSync(sandbox, { recursive: true, force: true }); }
}
