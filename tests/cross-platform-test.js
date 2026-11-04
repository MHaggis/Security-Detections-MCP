#!/usr/bin/env node
/**
 * Cross-Platform Compatibility Test Suite
 *
 * Validates that database lifecycle operations work correctly on all platforms,
 * especially Windows where file locking (EBUSY) is common with SQLite.
 *
 * Tests:
 * 1. Database creation and path handling
 * 2. Database recreation (the operation that fails on Windows with EBUSY)
 * 3. Multiple recreate cycles
 * 4. Concurrent-ish access patterns
 * 5. WAL/journal file cleanup
 */

import './isolated-db.js';
import { initDb, getDb, dbExists, recreateDb, closeDb, getDbPath, getCacheDir } from '../dist/db/connection.js';
import { getDbPath as getLegacyDbPath, initDb as initIndexerDb } from '../dist/db.js';
import { indexDetections, needsIndexing } from '../dist/indexer.js';
import { fileURLToPath } from 'url';
import { initPatternsSchema, extractAllPatterns } from '../dist/db/patterns.js';
import { existsSync } from 'fs';
import Database from 'better-sqlite3';
import { platform } from 'os';
import { sep } from 'path';

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
  console.log('  Cross-Platform Compatibility Test Suite');
  console.log(`  Platform: ${platform()} | Path separator: "${sep}"`);
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
// PATH HANDLING TESTS
// =============================================================================

test('DB path uses correct platform separators', () => {
  const dbPath = getDbPath();
  assert(dbPath.length > 0, 'DB path should not be empty');
  assert(dbPath.includes('security-detections-mcp'), 'DB path should contain project cache dir');
  assert(dbPath.endsWith('detections.sqlite'), 'DB path should end with detections.sqlite');
  console.log(`        Path: ${dbPath}`);
});

test('Both database entry points honor the isolated database path', () => {
  assert(getDbPath() === process.env.DETECTIONS_DB_PATH, 'Modular DB must use the explicit path');
  assert(getLegacyDbPath() === getDbPath(), 'Indexer and tools must use the same database');
});

test('Cache dir uses correct platform separators', () => {
  const cacheDir = getCacheDir();
  assert(cacheDir.length > 0, 'Cache dir should not be empty');

  if (platform() === 'win32') {
    assert(cacheDir.includes('\\'), 'Windows paths should use backslashes');
  }
});

// =============================================================================
// DATABASE LIFECYCLE TESTS
// =============================================================================

test('Database can be created fresh', () => {
  // Start clean
  closeDb();

  const db = initDb();
  assert(db !== null, 'initDb should return a database');
  assert(dbExists(), 'Database file should exist after init');
});

test('Database can be recreated without EBUSY error', () => {
  // This is the exact operation that fails on Windows
  initDb();

  // Write some data first so the db is actually active
  const db = getDb();
  db.exec("INSERT OR REPLACE INTO detections (id, name, source_type) VALUES ('test-1', 'Test Detection', 'sigma')");

  // Now recreate - this is where Windows throws EBUSY
  recreateDb();

  assert(!existsSync(getDbPath()), 'Database file should be deleted after recreate');

  // Re-init should work
  const newDb = initDb();
  assert(newDb !== null, 'Should be able to reinitialize after recreate');
  assert(dbExists(), 'Database should exist after reinit');
});

test('Multiple rapid recreate cycles work', () => {
  // Simulate what happens during re-indexing or rebuild_index calls
  for (let i = 0; i < 5; i++) {
    initDb();

    const db = getDb();
    db.exec(`INSERT OR REPLACE INTO detections (id, name, source_type) VALUES ('cycle-${i}', 'Cycle ${i}', 'sigma')`);

    recreateDb();
  }

  // Final init
  initDb();
  assert(dbExists(), 'Database should exist after multiple cycles');
});

test('Schema is intact after recreate', () => {
  recreateDb();
  initDb();
  initPatternsSchema();

  const db = getDb();
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
  const tableNames = tables.map(t => t.name);

  assert(tableNames.includes('detections'), 'detections table should exist');
  assert(tableNames.includes('stories'), 'stories table should exist');
  assert(tableNames.includes('kg_entities'), 'kg_entities table should exist');
  assert(tableNames.includes('kg_decisions'), 'kg_decisions table should exist');
});

test('Data operations work after recreate', () => {
  recreateDb();
  initDb();

  const db = getDb();

  // Insert
  db.exec("INSERT INTO detections (id, name, source_type) VALUES ('post-recreate', 'Post Recreate Test', 'sigma')");

  // Read back
  const row = db.prepare("SELECT * FROM detections WHERE id = 'post-recreate'").get();
  assert(row !== undefined, 'Should be able to read data after recreate');
  assert(row.name === 'Post Recreate Test', 'Data should match what was inserted');
});

// =============================================================================
// WAL/JOURNAL CLEANUP TESTS
// =============================================================================

test('WAL and journal files are cleaned up on recreate', () => {
  initDb();
  const dbPath = getDbPath();

  // Force WAL mode to create companion files
  const db = getDb();
  try {
    db.pragma('journal_mode = WAL');
    db.exec("INSERT INTO detections (id, name, source_type) VALUES ('wal-test', 'WAL Test', 'sigma')");
  } catch {
    // WAL mode might not create files if not supported, that's ok
  }

  recreateDb();

  // Companion files should also be gone
  assert(!existsSync(dbPath + '-wal'), 'WAL file should be cleaned up');
  assert(!existsSync(dbPath + '-shm'), 'SHM file should be cleaned up');
  assert(!existsSync(dbPath + '-journal'), 'Journal file should be cleaned up');
});

// =============================================================================
// CLOSE/REOPEN TESTS
// =============================================================================

test('Close and reopen works cleanly', () => {
  initDb();
  const db = getDb();
  db.exec("INSERT OR REPLACE INTO detections (id, name, source_type) VALUES ('close-test', 'Close Test', 'sigma')");

  closeDb();

  // Reopen
  initDb();
  const db2 = getDb();
  const row = db2.prepare("SELECT * FROM detections WHERE id = 'close-test'").get();
  assert(row !== undefined, 'Data should persist after close/reopen');
});

test('Multiple close calls dont crash', () => {
  initDb();
  closeDb();
  closeDb();
  closeDb();
  // No assert needed - just verifying it doesn't throw
});

// =============================================================================
// FINAL CLEANUP
// =============================================================================

test('Indexing closes existing query and indexer handles before replacing the database', () => {
  const queryConnection = initDb();
  const indexerConnection = initIndexerDb();
  const fixturePath = fileURLToPath(new URL('./fixtures/jamf_protect', import.meta.url));
  const result = indexDetections([], [], [], [], [], [], [], [fixturePath]);
  assert(result.jamf_protect_indexed === 3, 'All fixture detections must be indexed');
  assert(!queryConnection.open, 'The old query connection must be closed');
  assert(!indexerConnection.open, 'The old indexer connection must be closed');
  assert(getDb().prepare('SELECT COUNT(*) AS count FROM detections').get().count === 3,
    'Reopened query connection must read the replacement database');
  // Check indexDetections cleanup before needsIndexing can close a leaked handle.
  recreateDb();
});

test('Index build commits native rows, FTS and source-qualified links together', () => {
  const sigmaPath = fileURLToPath(new URL('./fixtures/source-identity/sigma', import.meta.url));
  const elasticPath = fileURLToPath(new URL('./fixtures/source-identity/elastic', import.meta.url));
  const result = indexDetections([sigmaPath], [], [], [elasticPath]);
  assert(result.sigma_indexed === 1 && result.elastic_indexed === 1 && result.total === 2,
    'Both colliding source rules must commit with accurate counters');
  const database = getDb();
  assert(database.prepare('SELECT COUNT(*) n FROM detections').get().n === 2, 'Both rows must persist');
  assert(database.prepare("SELECT COUNT(*) n FROM detections_fts WHERE detections_fts MATCH 'FastPass'").get().n === 2,
    'Both rows must be searchable after commit');
  assert(database.prepare('SELECT COUNT(DISTINCT source_type) n FROM detection_techniques').get().n === 2,
    'Both sources must have materialized technique links');
});

test('Unexpected traversal errors roll back writes; missing paths and rejected rules remain compatible', () => {
  const sigmaPath = fileURLToPath(new URL('./fixtures/source-identity/sigma', import.meta.url));
  const regularFile = fileURLToPath(new URL('./fixtures/source-identity/sigma/okta_fastpass_phishing_detection.yml', import.meta.url));
  let failure;
  try {
    indexDetections([sigmaPath, regularFile], []);
  } catch (error) {
    failure = error;
  }
  assert(failure?.code === 'ENOTDIR', 'Traversing a regular file as a directory must propagate its I/O error');
  assert(getDb().prepare('SELECT COUNT(*) n FROM detections').get().n === 0, 'Earlier source writes must roll back');
  const rejectedRules = fileURLToPath(new URL('./fixtures/jamf_protect', import.meta.url));
  const result = indexDetections([`${getCacheDir()}/missing-optional-source`, sigmaPath, rejectedRules], []);
  assert(result.sigma_indexed === 1 && result.sigma_failed === 3, 'Missing paths skip; parser rejection counters remain accurate');
  assert(getDb().prepare('SELECT COUNT(*) n FROM detections').get().n === 1, 'Valid row must commit despite expected parser rejection');
  recreateDb();
});

test('Unexpected SQLite error rolls back earlier writes and a subsequent rebuild succeeds', () => {
  const fixturePath = fileURLToPath(new URL('./fixtures/jamf_protect', import.meta.url));
  const originalPrepare = Database.prototype.prepare;
  let completedWrites = 0;
  let failure;
  Database.prototype.prepare = function(sql) {
    const statement = originalPrepare.call(this, sql);
    if (/INSERT INTO detections\s/i.test(sql)) {
      const originalRun = statement.run;
      const database = this;
      statement.run = function(...args) {
        if (completedWrites === 1) {
          // A real SQLite failure after an earlier successful row + FTS + edge write.
          database.exec('INSERT INTO deliberately_missing_index_test_table VALUES (1)');
        }
        const result = originalRun.apply(this, args);
        completedWrites++;
        return result;
      };
    }
    return statement;
  };
  try {
    indexDetections([], [], [], [], [], [], [], [fixturePath]);
  } catch (error) {
    failure = error;
  } finally {
    Database.prototype.prepare = originalPrepare;
  }
  assert(failure?.code === 'SQLITE_ERROR', 'Native SQLite error must propagate');
  assert(completedWrites === 1, 'Failure must occur after exactly one successful write');
  const database = getDb();
  assert(database.prepare('SELECT COUNT(*) n FROM detections').get().n === 0, 'No partially built detection rows may remain');
  assert(database.prepare('SELECT COUNT(*) n FROM detections_fts').get().n === 0, 'No partially built FTS rows may remain');
  assert(database.prepare('SELECT COUNT(*) n FROM detection_techniques').get().n === 0, 'No partially built edges may remain');
  assert(needsIndexing(), 'Failed empty replacement must be recognized as requiring a rebuild');
  const retry = indexDetections([], [], [], [], [], [], [], [fixturePath]);
  assert(retry.jamf_protect_indexed === 3 && retry.total === 3, 'A subsequent rebuild must succeed');
  assert(getDb().prepare('SELECT COUNT(*) n FROM detections').get().n === 3, 'Retry must persist all rows');
  recreateDb();
});

test('Pattern extraction rolls back partial writes and preserves existing patterns', () => {
  const sigmaPath = fileURLToPath(new URL('./fixtures/source-identity/sigma', import.meta.url));
  const elasticPath = fileURLToPath(new URL('./fixtures/source-identity/elastic', import.meta.url));
  indexDetections([sigmaPath], [], [], [elasticPath]);
  const database = getDb();
  initPatternsSchema();
  database.exec("INSERT INTO detection_patterns(id,pattern_type,pattern_content) VALUES ('existing','manual','{}')");
  database.exec("CREATE TEMP TRIGGER fail_pattern_summary BEFORE INSERT ON kg_learnings BEGIN SELECT RAISE(ABORT, 'forced late pattern summary failure'); END");
  const originalPrepare = Database.prototype.prepare;
  let completedWrites = 0;
  let failure;
  Database.prototype.prepare = function(sql) {
    const statement = originalPrepare.call(this, sql);
    if (/INSERT INTO detection_patterns\s/i.test(sql)) {
      const originalRun = statement.run;
      statement.run = function(...args) {
        const result = originalRun.apply(this, args);
        completedWrites++;
        return result;
      };
    }
    return statement;
  };
  try {
    extractAllPatterns();
  } catch (error) {
    failure = error;
  } finally {
    Database.prototype.prepare = originalPrepare;
  }
  assert(failure?.code === 'SQLITE_CONSTRAINT_TRIGGER' && completedWrites >= 2, 'Native failure must occur after multiple inserted patterns');
  assert(database.prepare('SELECT COUNT(*) n FROM detection_patterns').get().n === 1, 'New partial patterns must roll back');
  assert(database.prepare("SELECT id FROM detection_patterns WHERE id='existing'").get(), 'Existing pattern must remain');
  assert(database.prepare('SELECT COUNT(*) n FROM kg_learnings').get().n === 0, 'Failed extraction must not publish a completion learning');
  assert(database.prepare('SELECT COUNT(*) n FROM style_conventions').get().n === 0, 'Partial conventions must roll back');
  database.exec('DROP TRIGGER fail_pattern_summary');
  const retry = extractAllPatterns();
  assert(retry.total_patterns >= 2, 'Subsequent extraction must succeed');
  assert(database.prepare('SELECT COUNT(*) n FROM detection_patterns').get().n > 1, 'Successful patterns must persist');
  assert(database.prepare('SELECT COUNT(*) n FROM kg_learnings').get().n === 1, 'Successful summary must commit');
  recreateDb();
});

test('Index checks release their connection before a later database replacement', () => {
  assert(needsIndexing(), 'The replacement database should be empty');
  // needsIndexing must not leave a hidden handle that prevents this on Windows.
  recreateDb();
  assert(!dbExists(), 'No hidden connection should prevent database deletion');
});

test('Clean up test data', () => {
  recreateDb();
  initDb();
  assert(dbExists(), 'Final state: database should exist');
});

// Run
runTests();
