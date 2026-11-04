import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyNpmPublishParser } from './npm-publish-dry-run.mjs';

test('actual installed npm parses a local archive without git resolution, auth or lifecycle scripts', () => {
  const npmCli=process.env.npm_execpath;
  assert(npmCli,'Run this regression with npm run test:release');
  const directory=mkdtempSync(join(tmpdir(),'release-parser-fixture-'));
  try {
    const pkg={name:'security-detections-mcp',version:'9.9.9',scripts:{prepublishOnly:'node -e "process.exit(97)"',publish:'node -e "process.exit(98)"'}};
    writeFileSync(join(directory,'package.json'),JSON.stringify(pkg));
    const [packed]=JSON.parse(execFileSync(process.execPath,[npmCli,'pack','--ignore-scripts','--offline','--json'],
      {cwd:directory,encoding:'utf8',timeout:30000}));
    const archive=join(directory,packed.filename);
    const result=verifyNpmPublishParser(archive,pkg,npmCli);
    assert.equal(result.version,'9.9.9');
    assert.match(result.sha256,/^[a-f0-9]{64}$/);
    assert.throws(()=>verifyNpmPublishParser(archive,{name:pkg.name,version:'1.0.0'},npmCli),/different package version/);
  } finally {rmSync(directory,{recursive:true,force:true});}
});
