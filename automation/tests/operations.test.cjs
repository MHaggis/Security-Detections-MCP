const { test } = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, rmSync, readFileSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const { execFileSync, spawnSync } = require('node:child_process');
const { openDatabase } = require('../dist/db.js');
const { FeedStore } = require('../dist/collectors/feed-store.js');
const { CronScheduler } = require('../dist/runners/cron-scheduler.js');
const { ReportGenerator } = require('../dist/reports/report-generator.js');
function setup(t) {
  const dir = mkdtempSync(join(tmpdir(), 'automation-ops-test-'));
  const path = join(dir, 'queue.sqlite');
  const db = openDatabase(path);
  t.after(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });
  return { dir, path, db };
}

test('scheduler persists valid UTC expressions and deduplicates pending collections without running timers', t => {
  const f = setup(t);
  const scheduler = new CronScheduler(f.path);
  try {
    const id = scheduler.addSchedule('Fixture hourly', '0 * * * *', 'feed_collection');
    const schedule = scheduler.getStatus()[0];
    assert.equal(schedule.id, id);
    assert.equal(schedule.last_run, null);
    assert.throws(() => scheduler.addSchedule('Invalid', 'not a cron', 'feed_collection'));
    assert.throws(() => scheduler.addSchedule('Unsupported', '0 * * * *', 'maintenance'), /Only feed_collection/);
    assert.equal(scheduler.createJob('feed_collection'), scheduler.createJob('feed_collection'));
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM jobs').get().n, 1);
    scheduler.removeSchedule(id);
    assert.equal(scheduler.getStatus().length, 0);
  } finally { scheduler.close(); }
});

test('compiled migration, status, approval, and report CLIs work from a different cwd', t => {
  const f = setup(t);
  const env = { PATH: process.env.PATH, AUTOMATION_DB_PATH: f.path };
  for (const [relative, args] of [
    ['db.js', []], ['runners/autonomous-loop.js', ['status']],
    ['runners/cron-scheduler.js', ['status']], ['hitl/approval-system.js', ['list']],
    ['reports/report-generator.js', ['weekly', join(f.dir, 'report.md')]],
  ]) {
    execFileSync(process.execPath, [join(__dirname, '../dist', relative), ...args], { cwd: f.dir, env });
  }
  assert.match(readFileSync(join(f.dir, 'report.md'), 'utf8'), /Coverage improvement is not measured/);
});

test('one-shot CLI exits nonzero for blocked work and never completes it', t => {
  const f = setup(t);
  const store = new FeedStore(f.path);
  store.ingest({ id: 'fixture', title: 'Synthetic report', content: 'T1059.001', url: 'https://example.invalid', publishedAt: new Date() }, 'test');
  store.close();
  const result = spawnSync(process.execPath, [join(__dirname, '../dist/runners/autonomous-loop.js'), 'once'], {
    cwd: f.dir, env: { PATH: process.env.PATH, AUTOMATION_DB_PATH: f.path, AUTOMATION_MODE: 'disabled' },
  });
  assert.equal(result.status, 1);
  assert.equal(f.db.prepare('SELECT status FROM jobs').get().status, 'blocked');
});

test('report includes queue states and excludes simulation from reviewed Navigator coverage', async t => {
  const f = setup(t);
  const pipeline = { detections: [{ technique_id: 'T1059.001', status: 'validated' }] };
  f.db.prepare('INSERT INTO jobs (id,job_type,status,result) VALUES (?,?,?,?)')
    .run('simulation', 'threat_analysis', 'simulated', JSON.stringify({ mode: 'dry-run', pipeline }));
  const generator = new ReportGenerator(f.path);
  const config = { type: 'weekly', outputPath: join(f.dir, 'summary.md'), includeNavigator: true };
  try {
    let layer = await generator.generateNavigatorLayer(config);
    assert.equal(layer.techniques.length, 0);
    f.db.prepare('INSERT INTO jobs (id,job_type,status,result) VALUES (?,?,?,?)')
      .run('reviewed', 'threat_analysis', 'reviewed', JSON.stringify({ mode: 'live', pipeline }));
    layer = await generator.generateNavigatorLayer(config);
    assert.deepEqual(layer.techniques, [{ techniqueID: 'T1059.001', score: 1, enabled: true }]);
    const text = await generator.generateMarkdownReport(config);
    assert.match(text, /simulated \| 1/);
    assert.match(text, /reviewed \| 1/);
  } finally { generator.close(); }
});
