import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { repository, releaseCIReady } from './auto-release.mjs';
import { checkUnpublished } from './check-unpublished.mjs';
export function validateArtifact(artifact, bytes, version) {
  assert.equal(artifact.version,version);
  assert.equal(artifact.filename,`security-detections-mcp-${version}.tgz`,'Unexpected artifact filename');
  assert.match(artifact.sha256,/^[a-f0-9]{64}$/);
  assert.equal(createHash('sha256').update(bytes).digest('hex'),artifact.sha256,'Artifact digest mismatch');
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const gh=args=>JSON.parse(execFileSync('gh',args,{encoding:'utf8',timeout:60000}));
  const head=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
  assert.equal(process.env.GITHUB_REPOSITORY,repository);
  const main=gh(['api',`repos/${repository}/git/ref/heads/main`]).object.sha;
  assert.equal(main,head,'Main advanced while preparing publication; release current successful main instead');
  assert(releaseCIReady(gh,head),'Required CI no longer successful');
  const version=JSON.parse(readFileSync('package.json','utf8')).version;
  assert.equal(process.env.GITHUB_REF,`refs/tags/v${version}`);
  const artifact=JSON.parse(readFileSync('release-assets/package-artifact.json','utf8'));
  assert.equal(artifact.filename,`security-detections-mcp-${version}.tgz`);
  const path=join('release-assets',artifact.filename);
  validateArtifact(artifact,readFileSync(path),version);
  const packed=JSON.parse(execFileSync('tar',['-xOf',path,'package/package.json'],{encoding:'utf8'}));
  assert.equal(packed.name,'security-detections-mcp');assert.equal(packed.version,version);
  assert.equal(packed.mcpName,'io.github.mhaggis/security-detections-mcp');
  await checkUnpublished(version);
  execFileSync('npm',['publish',path,'--access','public','--ignore-scripts'],{stdio:'inherit',timeout:180000});
}
