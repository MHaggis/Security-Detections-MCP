const { test } = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, rmSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const { openDatabase } = require('../dist/db.js');
const { FeedStore, feedId } = require('../dist/collectors/feed-store.js');
const { MultiSourceCollector, parseFeed, fetchFeedText } = require('../dist/collectors/multi-source-collector.js');
const rss = '<?xml version="1.0"?><rss version="2.0"><channel><title>Fixture</title><link>https://example.invalid</link><description>Fixture</description><item><guid>fixture-1</guid><title>Synthetic threat</title><link>https://example.invalid/report</link><description>T1059.001</description><pubDate>Tue, 03 Nov 2026 12:00:00 GMT</pubDate></item></channel></rss>';
const source = { id: 'fixture', type: 'rss', name: 'Fixture', url: 'https://example.invalid/feed', enabled: true };
function setup(t) {
  const dir = mkdtempSync(join(tmpdir(), 'automation-feed-test-'));
  const path = join(dir, 'queue.sqlite');
  const db = openDatabase(path);
  t.after(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });
  return { dir, path, db };
}

// AUTO-COLLECT-001: fixture parsing and atomic durable enqueue, without network.
test('RSS ingestion queues exactly once across duplicate collections', async t => {
  const f = setup(t);
  const collector = new MultiSourceCollector(f.path, [source], async () => rss);
  try {
    assert.deepEqual(await collector.collectAll(), { fetched: 1, inserted: 1 });
    assert.deepEqual(await collector.collectAll(), { fetched: 1, inserted: 0 });
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM jobs').get().n, 1);
    const row = f.db.prepare('SELECT f.job_id, j.id FROM feed_items f JOIN jobs j ON f.job_id=j.id').get();
    assert.equal(row.id, row.job_id);
  } finally { collector.close(); }
});

test('job insert failure rolls back feed insert, allowing a later retry', async t => {
  const f = setup(t);
  const store = new FeedStore(f.path);
  const [item] = await parseFeed(source, rss);
  try {
    f.db.exec("CREATE TRIGGER fail_enqueue BEFORE INSERT ON jobs BEGIN SELECT RAISE(ABORT, 'controlled failure'); END");
    assert.throws(() => store.ingest(item, source.id), /controlled failure/);
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM feed_items').get().n, 0);
    f.db.exec('DROP TRIGGER fail_enqueue');
    assert.equal(store.ingest(item, source.id), true);
  } finally { store.close(); }
});

test('KEV JSON uses its own parser and source-qualified identity', async () => {
  const kev = { vulnerabilities: [{ cveID: 'CVE-2026-0001', vulnerabilityName: 'Synthetic fixture', dateAdded: '2026-11-03' }] };
  const [item] = await parseFeed({ ...source, type: 'kev' }, JSON.stringify(kev));
  assert.match(item.title, /CVE-2026-0001/);
  assert.equal(item.publishedAt.toISOString(), '2026-11-03T00:00:00.000Z');
  assert.notEqual(feedId('one', 'same-id'), feedId('two', 'same-id'));
  await assert.rejects(parseFeed({ ...source, type: 'kev' }, '{}'), /item array/);
});

test('malformed RSS, invalid dates, and failed collection surface errors', async t => {
  await assert.rejects(parseFeed(source, 'not-xml'));
  await assert.rejects(parseFeed(source, rss.replace('Tue, 03 Nov 2026 12:00:00 GMT', 'not-a-date')));
  const f = setup(t);
  const collector = new MultiSourceCollector(f.path, [source], async () => { throw new Error('controlled HTTP failure'); });
  try {
    await assert.rejects(collector.collectAll(), /controlled HTTP failure/);
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM jobs').get().n, 0);
  } finally { collector.close(); }
});

test('HTTP errors are rejected before parsing', async t => {
  t.mock.method(globalThis, 'fetch', async () => new Response('unavailable', { status: 503 }));
  await assert.rejects(fetchFeedText(source.url), /HTTP 503/);
});
