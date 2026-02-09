#!/usr/bin/env node
/**
 * CI Integration Test
 *
 * Downloads Sigma rules, indexes them, and validates the full pipeline.
 * This is the test that catches Windows EBUSY issues since it exercises
 * the complete lifecycle: init -> index -> query -> recreate -> re-index.
 *
 * Requires: SIGMA_PATHS env var pointing to a Sigma rules directory.
 * The CI workflow clones Sigma before running this.
 */

// Import from db.js (not db/connection.js) because the indexer uses db.js.
// They have separate singletons, so we need the same one the indexer writes to.
import { initDb, recreateDb, dbExists, searchDetections } from '../dist/db.js';
import { indexDetections } from '../dist/indexer.js';
import { platform } from 'os';

// helper to get db handle for direct queries
function getDb() {
  return initDb();
}

const SIGMA_PATHS = process.env.SIGMA_PATHS;

if (!SIGMA_PATHS) {
  console.error('SIGMA_PATHS env var is required. Set it to a directory with Sigma rules.');
  process.exit(1);
}

const sigmaDirs = SIGMA_PATHS.split(',').map(p => p.trim()).filter(p => p.length > 0);

const TESTS = [];
const RESULTS = { passed: 0, failed: 0 };

function test(name, fn) {
  TESTS.push({ name, fn });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function runTests() {
  console.log('==============================================================');
  console.log('  CI Integration Test - Full Indexing Pipeline');
  console.log(`  Platform: ${platform()}`);
  console.log(`  Sigma paths: ${sigmaDirs.join(', ')}`);
  console.log('==============================================================\n');

  for (const { name, fn } of TESTS) {
    try {
      await fn();
      console.log(`  PASS: ${name}`);
      RESULTS.passed++;
    } catch (error) {
      console.log(`  FAIL: ${name}`);
      console.log(`        ${error.message}`);
      RESULTS.failed++;
    }
  }

  console.log('\n' + '-'.repeat(60));
  console.log(`Results: ${RESULTS.passed} passed, ${RESULTS.failed} failed`);
  console.log('-'.repeat(60));

  process.exit(RESULTS.failed > 0 ? 1 : 0);
}

// =============================================================================
// FIRST INDEX CYCLE
// =============================================================================

let firstIndexResult;

test('Database initializes clean', () => {
  // Make sure we start fresh
  try { recreateDb(); } catch { /* might not exist yet */ }
  initDb();
  assert(dbExists(), 'Database should exist after init');
});

test('Sigma rules index successfully', () => {
  firstIndexResult = indexDetections(sigmaDirs, [], [], [], []);

  assert(firstIndexResult.sigma_indexed > 0, `Should index some Sigma rules, got ${firstIndexResult.sigma_indexed}`);
  console.log(`        Indexed: ${firstIndexResult.sigma_indexed} rules (${firstIndexResult.sigma_failed} failed to parse)`);
});

test('Indexed count is reasonable (500+ Sigma rules)', () => {
  assert(firstIndexResult.sigma_indexed >= 500,
    `Expected 500+ Sigma rules, got ${firstIndexResult.sigma_indexed}`);
});

test('Database has correct count after indexing', () => {
  const db = getDb();
  const row = db.prepare('SELECT COUNT(*) as cnt FROM detections').get();
  assert(row.cnt === firstIndexResult.sigma_indexed,
    `DB count (${row.cnt}) should match indexed count (${firstIndexResult.sigma_indexed})`);
});

// =============================================================================
// QUERY TESTS - verify data is actually usable
// =============================================================================

test('Full-text search returns results for "powershell"', () => {
  const db = getDb();
  const rows = db.prepare(`
    SELECT d.* FROM detections d
    JOIN detections_fts fts ON d.rowid = fts.rowid
    WHERE detections_fts MATCH 'powershell'
    LIMIT 5
  `).all();

  assert(rows.length > 0, 'Search for "powershell" should find results');
  console.log(`        Found ${rows.length} results for "powershell"`);
});

test('MITRE technique filtering works', () => {
  const db = getDb();
  const rows = db.prepare(`
    SELECT * FROM detections WHERE mitre_ids LIKE '%"T1059"%' LIMIT 5
  `).all();

  assert(rows.length > 0, 'Should find detections mapped to T1059 (Command and Scripting Interpreter)');
  console.log(`        Found ${rows.length} detections for T1059`);
});

test('Sigma rules have MITRE mappings (50%+ coverage)', () => {
  const db = getDb();
  const total = db.prepare('SELECT COUNT(*) as cnt FROM detections').get().cnt;
  const withMitre = db.prepare(`
    SELECT COUNT(*) as cnt FROM detections
    WHERE mitre_ids != '[]' AND mitre_ids IS NOT NULL
  `).get().cnt;

  const pct = (withMitre / total * 100).toFixed(1);
  console.log(`        MITRE coverage: ${pct}% (${withMitre}/${total})`);
  assert(withMitre > total * 0.5, `Only ${pct}% have MITRE mappings, expected >50%`);
});

test('Severity levels are valid', () => {
  const db = getDb();
  const rows = db.prepare(`
    SELECT DISTINCT severity FROM detections WHERE severity IS NOT NULL
  `).all();

  const valid = ['critical', 'high', 'medium', 'low', 'informational'];
  for (const row of rows) {
    assert(valid.includes(row.severity),
      `Invalid severity: "${row.severity}"`);
  }
  console.log(`        Severities found: ${rows.map(r => r.severity).join(', ')}`);
});

test('All detections have names', () => {
  const db = getDb();
  const missing = db.prepare(`
    SELECT COUNT(*) as cnt FROM detections WHERE name IS NULL OR name = ''
  `).get().cnt;

  assert(missing === 0, `${missing} detections are missing names`);
});

test('All detections have source_type=sigma', () => {
  const db = getDb();
  const notSigma = db.prepare(`
    SELECT COUNT(*) as cnt FROM detections WHERE source_type != 'sigma'
  `).get().cnt;

  assert(notSigma === 0, `${notSigma} detections have wrong source_type`);
});

test('Detections have file_path populated', () => {
  const db = getDb();
  const missing = db.prepare(`
    SELECT COUNT(*) as cnt FROM detections WHERE file_path IS NULL OR file_path = ''
  `).get().cnt;

  assert(missing === 0, `${missing} detections are missing file_path`);
});

test('No duplicate IDs', () => {
  const db = getDb();
  const dupes = db.prepare(`
    SELECT id, COUNT(*) as cnt FROM detections GROUP BY id HAVING cnt > 1
  `).all();

  assert(dupes.length === 0, `Found ${dupes.length} duplicate IDs`);
});

// =============================================================================
// RECREATE + RE-INDEX CYCLE - the exact thing that breaks on Windows
// =============================================================================

let secondIndexResult;

test('Database can be recreated after indexing (Windows EBUSY test)', () => {
  recreateDb();
  assert(!dbExists(), 'Database file should be deleted after recreate');
});

test('Re-initialize after recreate works', () => {
  initDb();
  assert(dbExists(), 'Database should exist after re-init');
});

test('Re-index after recreate works', () => {
  secondIndexResult = indexDetections(sigmaDirs, [], [], [], []);

  assert(secondIndexResult.sigma_indexed > 0,
    `Re-index should work, got ${secondIndexResult.sigma_indexed}`);
  console.log(`        Re-indexed: ${secondIndexResult.sigma_indexed} rules`);
});

test('Re-index count matches first index', () => {
  // Allow small variance in case of race conditions with file system
  const diff = Math.abs(firstIndexResult.sigma_indexed - secondIndexResult.sigma_indexed);
  assert(diff < 5,
    `First index (${firstIndexResult.sigma_indexed}) and re-index (${secondIndexResult.sigma_indexed}) should match (diff: ${diff})`);
});

test('Queries still work after recreate + re-index', () => {
  const db = getDb();
  const rows = db.prepare(`
    SELECT d.* FROM detections d
    JOIN detections_fts fts ON d.rowid = fts.rowid
    WHERE detections_fts MATCH 'credential'
    LIMIT 5
  `).all();

  assert(rows.length > 0, 'Search should still work after recreate cycle');
  console.log(`        Found ${rows.length} results for "credential" after re-index`);
});

// =============================================================================
// SEARCH API TEST
// =============================================================================

test('searchDetections API works after re-index', () => {
  const results = searchDetections('powershell', 5);
  assert(results.length > 0, 'searchDetections should return results');
  console.log(`        searchDetections found ${results.length} results`);
});

// Run
runTests();
