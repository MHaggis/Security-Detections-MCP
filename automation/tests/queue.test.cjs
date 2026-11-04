const { test } = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const { openDatabase } = require('../dist/db.js');
const { FeedStore } = require('../dist/collectors/feed-store.js');
const { AutonomousLoop } = require('../dist/runners/autonomous-loop.js');
const { createAgentsAdapter, BlockedError } = require('../dist/runners/agents-adapter.js');
const { ApprovalSystem } = require('../dist/hitl/approval-system.js');
const livePaths = { SECURITY_CONTENT_PATH: __dirname, ATTACK_DATA_PATH: __dirname, ATTACK_RANGE_PATH: __dirname };
const cliPath = join(__dirname, 'fixtures/agents-cli.cjs');

function setup(t) {
  const dir = mkdtempSync(join(tmpdir(), 'automation-queue-test-'));
  const path = join(dir, 'queue.sqlite');
  const db = openDatabase(path);
  const store = new FeedStore(path);
  store.ingest({ id: 'feed1', title: 'T1059.001', content: 'Synthetic report', url: 'https://example.invalid/report', publishedAt: new Date() }, 'fixture');
  store.close();
  t.after(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });
  return { dir, path, db, job: () => db.prepare('SELECT * FROM jobs LIMIT 1').get(), feed: () => db.prepare('SELECT * FROM feed_items').get() };
}
const feed = { id: 'feed1', title: 'Synthetic report', content: 'T1059.001', url: '', feed_source: 'fixture' };

// AUTO-QUEUE-001: real SQLite transitions, bounded retries and atomic claims.
test('simulated CLI work is persisted as simulated, never completed', async t => {
  const f = setup(t);
  const loop = new AutonomousLoop(f.path, createAgentsAdapter({ cliPath, mode: 'dry-run', env: {} }));
  try {
    assert.equal(await loop.processNext(), true);
    assert.equal(f.job().status, 'simulated');
    assert.equal(f.feed().status, 'simulated');
    assert.equal(JSON.parse(f.job().result).pipeline.child_dry_run, 'true');
    assert.equal(await loop.processNext(), false);
  } finally { loop.close(); }
});

test('retries stop at max attempts and preserve failure reason', async t => {
  const f = setup(t);
  const loop = new AutonomousLoop(f.path, async () => { throw new Error('controlled failure'); });
  try {
    for (let attempt = 1; attempt <= 3; attempt++) {
      await loop.processNext();
      assert.equal(f.job().retry_count, attempt);
      assert.equal(f.job().status, attempt === 3 ? 'failed' : 'pending');
    }
    assert.equal(f.job().error, 'controlled failure');
    assert.equal(f.feed().status, 'failed');
    assert.equal(await loop.processNext(), false);
    assert.equal(f.job().result, null);
  } finally { loop.close(); }
});

test('disabled adapter blocks a claimed job without consuming retries', async t => {
  const f = setup(t);
  const loop = new AutonomousLoop(f.path, createAgentsAdapter({ mode: 'disabled', env: {} }));
  try {
    await loop.processNext();
    assert.equal(f.job().status, 'blocked');
    assert.equal(f.job().retry_count, 0);
    assert.equal(f.feed().status, 'blocked');
  } finally { loop.close(); }
});

test('two workers cannot claim the same job', async t => {
  const f = setup(t);
  let finish;
  const wait = new Promise(resolve => { finish = resolve; });
  let calls = 0;
  const invoke = async () => { calls++; await wait; return { status: 'simulated', mode: 'dry-run', pipeline: { workflow_id: 'fixture' } }; };
  const a = new AutonomousLoop(f.path, invoke);
  const b = new AutonomousLoop(f.path, invoke);
  try {
    const job = a.getNextJob();
    const processing = a.processJob(job);
    assert.equal(await b.processJob(job), false);
    finish();
    await processing;
    assert.equal(calls, 1);
  } finally { a.close(); b.close(); }
});

test('malformed payload and missing linked feed retry without false success', async t => {
  const f = setup(t);
  const loop = new AutonomousLoop(f.path, async () => { throw new Error('must not invoke'); });
  try {
    f.db.prepare("UPDATE jobs SET payload='not-json'").run();
    await loop.processNext();
    assert.equal(f.job().status, 'pending');
    f.db.prepare('UPDATE jobs SET payload=?').run(JSON.stringify({ feed_item_id: 'missing' }));
    await loop.processNext();
    assert.equal(f.job().error, 'Linked feed item not found');
    assert.equal(f.job().status, 'pending');
  } finally { loop.close(); }
});

test('unknown job type is blocked instead of completing', async t => {
  const f = setup(t);
  f.db.prepare("UPDATE jobs SET job_type='unknown'").run();
  const loop = new AutonomousLoop(f.path);
  try { await loop.processNext(); assert.equal(f.job().status, 'blocked'); } finally { loop.close(); }
});

// AUTO-ADAPTER-001: argv execution and fail-closed output contract.
test('untrusted report shell syntax reaches the child literally', async t => {
  const f = setup(t);
  const marker = join(f.dir, 'should-not-exist');
  const content = `$(touch ${marker}) ; echo "quotes"\n\`touch ${marker}\``;
  const result = await createAgentsAdapter({ cliPath, mode: 'dry-run', env: {} })({ ...feed, content });
  assert.ok(result.pipeline.input_content.includes(content));
  assert.equal(existsSync(marker), false);
});

for (const scenario of ['failure', 'malformed', 'empty', 'error']) {
  test(`child ${scenario} cannot report success`, async () => {
    const invoke = createAgentsAdapter({ cliPath, mode: 'dry-run', env: { TEST_SCENARIO: scenario } });
    await assert.rejects(invoke(feed));
  });
}
test('timeout terminates a hung child', async () => {
  await assert.rejects(createAgentsAdapter({ cliPath, mode: 'dry-run', timeoutMs: 50, env: { TEST_SCENARIO: 'timeout' } })(feed), /failed, timed out/);
});
test('missing CLI and missing live API configuration are blocked', async () => {
  await assert.rejects(createAgentsAdapter({ cliPath: '/does-not-exist/cli.js', mode: 'dry-run', env: {} })(feed), BlockedError);
  await assert.rejects(createAgentsAdapter({ cliPath, mode: 'live', env: {} })(feed), /ANTHROPIC_API_KEY/);
});
for (const scenario of ['incomplete', 'mock-live', 'coverage-exit', 'external-pr', 'temporary-artifact']) {
  test(`live ${scenario} result is blocked`, async () => {
    await assert.rejects(createAgentsAdapter({ cliPath, mode: 'live', env: { ...livePaths, ANTHROPIC_API_KEY: 'fixture-only', TEST_SCENARIO: scenario } })(feed), BlockedError);
  });
}

// AUTO-REVIEW-001: approval reviews stored artifacts and cannot replay external work.
test('valid live fixture awaits human review; approval never requeues it', async t => {
  const f = setup(t);
  const artifact = join(f.dir, 'detection.yml');
  writeFileSync(artifact, 'name: Synthetic detection');
  const loop = new AutonomousLoop(f.path, createAgentsAdapter({ cliPath, mode: 'live', env: { ...livePaths, ANTHROPIC_API_KEY: 'fixture-only', TEST_ARTIFACT: artifact } }));
  const approvals = new ApprovalSystem(f.path);
  try {
    await loop.processNext();
    assert.equal(f.job().status, 'awaiting_approval');
    const pending = approvals.getPendingApprovals();
    assert.equal(pending.length, 1);
    await approvals.approve(pending[0].id, 'reviewer');
    assert.equal(f.job().status, 'reviewed');
    assert.equal(f.feed().status, 'reviewed');
    assert.equal(await loop.processNext(), false);
    await assert.rejects(approvals.reject(pending[0].id, 'reviewer'), /already resolved/);
    assert.equal(f.job().status, 'reviewed');
  } finally { approvals.close(); loop.close(); }
});

test('missing live artifacts block instead of claiming review-ready results', async () => {
  await assert.rejects(createAgentsAdapter({ cliPath, mode: 'live', env: { ...livePaths, ANTHROPIC_API_KEY: 'fixture-only' } })(feed), /artifacts are missing/);
});

test('expired human review cancels rather than bypassing approval', async t => {
  const f = setup(t);
  const loop = new AutonomousLoop(f.path, async () => ({ status: 'awaiting_approval', mode: 'live', pipeline: { workflow_id: 'fixture' } }));
  const approvals = new ApprovalSystem(f.path);
  try {
    await loop.processNext();
    const pending = approvals.getPendingApprovals()[0];
    f.db.prepare("UPDATE approval_requests SET requested_at=datetime('now', '-48 hours')").run();
    await approvals.processExpiredApprovals();
    assert.equal(f.job().status, 'cancelled');
    assert.equal(approvals.getApproval(pending.id).status, 'expired');
    await assert.rejects(approvals.approve(pending.id, 'reviewer'), /already resolved/);
  } finally { approvals.close(); loop.close(); }
});


test('human rejection cancels a stored live result and cannot rerun it', async t => {
  const f = setup(t);
  const loop = new AutonomousLoop(f.path, async () => ({ status: 'awaiting_approval', mode: 'live', pipeline: { workflow_id: 'fixture' } }));
  const approvals = new ApprovalSystem(f.path);
  try {
    await loop.processNext();
    const pending = approvals.getPendingApprovals()[0];
    await assert.rejects(approvals.approve(pending.id, ' '), /Reviewer identity/);
    assert.equal(f.job().status, 'awaiting_approval');
    await approvals.reject(pending.id, 'reviewer', 'Evidence needs correction');
    assert.equal(f.job().status, 'cancelled');
    assert.equal(f.feed().status, 'cancelled');
    assert.equal(approvals.getApproval(pending.id).status, 'rejected');
    assert.equal(await loop.processNext(), false);
  } finally { approvals.close(); loop.close(); }
});


for (const scenario of ['failure', 'timeout', 'malformed', 'error']) {
  test(`uncertain live ${scenario} blocks without replaying external work`, async t => {
    const f = setup(t);
    const invocations = join(f.dir, 'invocations.txt');
    const loop = new AutonomousLoop(f.path, createAgentsAdapter({
      cliPath, mode: 'live', timeoutMs: scenario === 'timeout' ? 1000 : 5000,
      env: { ...livePaths, ANTHROPIC_API_KEY: 'fixture-only', TEST_SCENARIO: scenario, TEST_INVOCATIONS: invocations },
    }));
    try {
      await loop.processNext();
      assert.equal(f.job().status, 'blocked');
      assert.equal(f.feed().status, 'blocked');
      assert.equal(f.job().retry_count, 0);
      assert.equal(await loop.processNext(), false);
      assert.equal(readFileSync(invocations, 'utf8'), 'invoked\n');
    } finally { loop.close(); }
  });
}

test('failed persistence after a live result blocks instead of rerunning the child', async t => {
  const f = setup(t);
  const artifact = join(f.dir, 'detection.yml');
  const invocations = join(f.dir, 'invocations.txt');
  writeFileSync(artifact, 'name: Synthetic detection');
  f.db.exec("CREATE TRIGGER reject_approval BEFORE INSERT ON approval_requests BEGIN SELECT RAISE(ABORT, 'controlled persistence failure'); END");
  const loop = new AutonomousLoop(f.path, createAgentsAdapter({ cliPath, mode: 'live',
    env: { ...livePaths, ANTHROPIC_API_KEY: 'fixture-only', TEST_ARTIFACT: artifact, TEST_INVOCATIONS: invocations } }));
  try {
    await loop.processNext();
    assert.equal(f.job().status, 'blocked');
    assert.equal(f.feed().status, 'blocked');
    assert.equal(f.job().retry_count, 0);
    assert.equal(f.job().result, null);
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM approval_requests').get().n, 0);
    assert.equal(await loop.processNext(), false);
    assert.equal(readFileSync(invocations, 'utf8'), 'invoked\n');
  } finally { loop.close(); }
});
