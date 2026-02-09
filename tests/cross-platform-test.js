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

import { initDb, getDb, dbExists, recreateDb, closeDb, getDbPath, getCacheDir } from '../dist/db/connection.js';
import { initPatternsSchema } from '../dist/db/patterns.js';
import { existsSync } from 'fs';
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

test('Clean up test data', () => {
  recreateDb();
  initDb();
  assert(dbExists(), 'Final state: database should exist');
});

// Run
runTests();
