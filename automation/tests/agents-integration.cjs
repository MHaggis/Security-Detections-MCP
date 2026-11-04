const assert = require('node:assert/strict');
const { mkdtempSync, rmSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const { openDatabase } = require('../dist/db.js');
const { FeedStore } = require('../dist/collectors/feed-store.js');
const { AutonomousLoop } = require('../dist/runners/autonomous-loop.js');
const { createAgentsAdapter } = require('../dist/runners/agents-adapter.js');

(async () => {
  const dir = mkdtempSync(join(tmpdir(), 'automation-real-agents-test-'));
  const path = join(dir, 'queue.sqlite');
  const db = openDatabase(path);
  const store = new FeedStore(path);
  const env = { PATH: process.env.PATH, AGENTS_CLI_PATH: process.env.AGENTS_CLI_PATH };
  const loop = new AutonomousLoop(path, createAgentsAdapter({ mode: 'dry-run', env, timeoutMs: 60000 }));
  try {
    store.ingest({ id: 'real-cli-fixture', title: 'Synthetic PowerShell T1059.001', content: 'Synthetic report for dry-run integration only.',
      url: 'https://example.invalid/test', publishedAt: new Date() }, 'fixture');
    assert.equal(await loop.processNext(), true);
    const job = db.prepare('SELECT * FROM jobs').get();
    assert.equal(job.status, 'simulated', job.error || 'Actual compiled agents CLI did not return a simulated result');
    const result = JSON.parse(job.result);
    assert.ok(result.pipeline.techniques.some(t => t.id === 'T1059.001'));
    assert.ok(result.pipeline.detections.length > 0);
    assert.ok(result.pipeline.warnings.some(w => /dry.run/i.test(w)));
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM approval_requests').get().n, 0);
    console.log('PASS: real compiled agents CLI -> adapter -> SQLite, dry-run only; no live APIs or PRs');
  } finally { loop.close(); store.close(); db.close(); rmSync(dir, { recursive: true, force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });
