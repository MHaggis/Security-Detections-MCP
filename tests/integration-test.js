#!/usr/bin/env node
/**
 * Comprehensive Integration Test Suite for Security Detections MCP
 * 
 * Tests:
 * 1. Database connectivity and schema
 * 2. Detection indexing accuracy
 * 3. Pattern extraction coverage
 * 4. Field reference completeness
 * 5. Tool functionality
 * 6. Data normalization
 */

import { initDb, getDb, dbExists } from '../dist/db/connection.js';
import { getStats, listBySource, listByMitre, searchDetections, getDetectionById } from '../dist/db/detections.js';
import { initPatternsSchema, getPatternStats, getPatternsByTechnique, getFieldReference, extractAllPatterns } from '../dist/db/patterns.js';
import { listStories, getStoryByName } from '../dist/db/stories.js';

const TESTS = [];
const RESULTS = { passed: 0, failed: 0, warnings: 0 };

function test(name, fn) {
  TESTS.push({ name, fn });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function warn(message) {
  console.log(`  ⚠️  WARNING: ${message}`);
  RESULTS.warnings++;
}

async function runTests() {
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║     Security Detections MCP - Integration Test Suite         ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  initDb();
  initPatternsSchema();

  for (const { name, fn } of TESTS) {
    try {
      await fn();
      console.log(`✅ ${name}`);
      RESULTS.passed++;
    } catch (error) {
      console.log(`❌ ${name}`);
      console.log(`   Error: ${error.message}`);
      RESULTS.failed++;
    }
  }

  console.log('\n' + '─'.repeat(60));
  console.log(`Results: ${RESULTS.passed} passed, ${RESULTS.failed} failed, ${RESULTS.warnings} warnings`);
  console.log('─'.repeat(60));
  
  process.exit(RESULTS.failed > 0 ? 1 : 0);
}

// =============================================================================
// DATABASE TESTS
// =============================================================================

test('Database exists and is accessible', () => {
  assert(dbExists(), 'Database file should exist');
  const db = getDb();
  assert(db !== null, 'Should be able to get database connection');
});

test('Detection schema has required tables', () => {
  const db = getDb();
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
  const tableNames = tables.map(t => t.name);
  
  assert(tableNames.includes('detections'), 'detections table should exist');
  assert(tableNames.includes('stories'), 'stories table should exist');
  assert(tableNames.includes('detection_patterns'), 'detection_patterns table should exist');
  assert(tableNames.includes('field_reference'), 'field_reference table should exist');
});

// =============================================================================
// DETECTION INDEXING TESTS
// =============================================================================

test('All content sources are indexed', () => {
  const stats = getStats();
  
  assert(stats.sigma > 0, 'Sigma rules should be indexed');
  assert(stats.splunk_escu > 0, 'Splunk ESCU detections should be indexed');
  assert(stats.elastic >= 0, 'Elastic rules check (may be 0 if not configured)');
  assert(stats.kql >= 0, 'KQL rules check (may be 0 if not configured)');
  
  console.log(`   Indexed: ${stats.sigma} Sigma, ${stats.splunk_escu} Splunk, ${stats.elastic} Elastic, ${stats.kql} KQL`);
});

test('Detections have required fields populated', () => {
  const db = getDb();
  
  // Check Splunk detections have queries
  const splunkNoQuery = db.prepare(`
    SELECT COUNT(*) as cnt FROM detections 
    WHERE source_type = 'splunk_escu' AND (query IS NULL OR query = '')
  `).get();
  
  if (splunkNoQuery.cnt > 0) {
    warn(`${splunkNoQuery.cnt} Splunk detections missing queries`);
  }
  
  // Check detections have names
  const noName = db.prepare(`
    SELECT COUNT(*) as cnt FROM detections WHERE name IS NULL OR name = ''
  `).get();
  assert(noName.cnt === 0, 'All detections should have names');
});

test('MITRE mappings are indexed correctly', () => {
  const stats = getStats();
  const total = stats.total;
  const withMitre = stats.mitre_coverage;
  
  const coverage = (withMitre / total * 100).toFixed(1);
  console.log(`   MITRE coverage: ${coverage}% (${withMitre}/${total})`);
  
  assert(withMitre > total * 0.5, 'At least 50% of detections should have MITRE mappings');
});

test('Severity levels are normalized', () => {
  const stats = getStats();
  const validSeverities = ['critical', 'high', 'medium', 'low', 'informational'];
  
  for (const severity of Object.keys(stats.by_severity)) {
    assert(validSeverities.includes(severity.toLowerCase()), 
      `Invalid severity: ${severity}`);
  }
});

// =============================================================================
// CONTENT NORMALIZATION TESTS
// =============================================================================

test('Sigma rules have consistent structure', () => {
  const sigmaRules = listBySource('sigma', 100);
  let withMitre = 0;
  
  for (const rule of sigmaRules.slice(0, 50)) {
    assert(rule.id, `Sigma rule "${rule.name}" should have an ID`);
    assert(rule.name, 'Sigma rule should have a name');
    if (rule.mitre_ids && rule.mitre_ids.length > 0) {
      withMitre++;
    }
  }
  
  // Allow some rules without MITRE mappings (edge cases)
  const coverage = (withMitre / 50 * 100).toFixed(1);
  assert(withMitre >= 40, `Only ${coverage}% of Sigma rules have MITRE mappings`);
  console.log(`   ${coverage}% of sampled Sigma rules have MITRE mappings`);
});

test('Splunk detections have consistent structure', () => {
  const splunkDetections = listBySource('splunk_escu', 100);
  
  for (const det of splunkDetections.slice(0, 10)) {
    assert(det.id, `Splunk detection should have an ID`);
    assert(det.name, 'Splunk detection should have a name');
    assert(det.query, `Splunk detection "${det.name}" should have a query`);
  }
});

test('KQL rules have consistent structure (if indexed)', () => {
  const kqlRules = listBySource('kql', 50);
  
  if (kqlRules.length === 0) {
    console.log('   (No KQL rules indexed - skipping)');
    return;
  }
  
  for (const rule of kqlRules.slice(0, 10)) {
    assert(rule.id, 'KQL rule should have an ID');
    assert(rule.name, 'KQL rule should have a name');
  }
});

// =============================================================================
// PATTERN EXTRACTION TESTS
// =============================================================================

test('Patterns are extracted from content', () => {
  const stats = getPatternStats();
  
  assert(stats.total_patterns > 0, 'Should have extracted patterns');
  console.log(`   ${stats.total_patterns} patterns across ${stats.by_technique} techniques`);
});

test('Major data models are captured', () => {
  const db = getDb();
  const dataModels = db.prepare(`
    SELECT DISTINCT data_model FROM detection_patterns 
    WHERE data_model IS NOT NULL
  `).all().map(r => r.data_model);
  
  const expectedDataModels = ['Endpoint.Processes', 'Endpoint.Filesystem', 'Endpoint.Registry'];
  
  for (const dm of expectedDataModels) {
    assert(dataModels.includes(dm), `Data model ${dm} should be captured`);
  }
  
  console.log(`   ${dataModels.length} unique data models captured`);
});

test('Field references cover major data models', () => {
  const db = getDb();
  const fieldModels = db.prepare(`
    SELECT DISTINCT data_model FROM field_reference
  `).all().map(r => r.data_model);
  
  assert(fieldModels.includes('Endpoint.Processes'), 'Endpoint.Processes fields should be captured');
  assert(fieldModels.includes('Endpoint.Filesystem'), 'Endpoint.Filesystem fields should be captured');
  
  console.log(`   Field references for ${fieldModels.length} data models`);
});

test('Pattern retrieval returns aggregated data', () => {
  // Test with a common technique
  const patterns = getPatternsByTechnique('T1059.001', 'splunk_escu');
  
  if (patterns.count === 0) {
    warn('No patterns found for T1059.001 - may need to run extract_patterns');
    return;
  }
  
  assert(patterns.macros.length > 0, 'Should have aggregated macros');
  assert(patterns.fields.length > 0, 'Should have aggregated fields');
  
  console.log(`   T1059.001: ${patterns.macros.length} macros, ${patterns.fields.length} fields`);
});

// =============================================================================
// SEARCH AND RETRIEVAL TESTS
// =============================================================================

test('Search function returns relevant results', () => {
  const results = searchDetections('powershell', 10);
  
  assert(results.length > 0, 'Search for "powershell" should return results');
  
  // Check relevance
  const hasRelevant = results.some(r => 
    r.name.toLowerCase().includes('powershell') || 
    (r.description && r.description.toLowerCase().includes('powershell'))
  );
  assert(hasRelevant, 'Results should be relevant to search term');
});

test('MITRE technique lookup works', () => {
  const results = listByMitre('T1059.001', 10);
  
  assert(results.length > 0, 'Should find detections for T1059.001');
  
  for (const det of results) {
    assert(det.mitre_ids.includes('T1059.001'), 
      `Detection "${det.name}" should have T1059.001 mapping`);
  }
});

test('Detection by ID retrieval works', () => {
  const detections = listBySource('splunk_escu', 1);
  if (detections.length === 0) return;
  
  const id = detections[0].id;
  const retrieved = getDetectionById(id);
  
  assert(retrieved !== null, 'Should retrieve detection by ID');
  assert(retrieved.id === id, 'Retrieved detection should have correct ID');
});

// =============================================================================
// STORIES TESTS
// =============================================================================

test('Stories are indexed', () => {
  const stats = getStats();
  
  if (stats.stories_count === 0) {
    warn('No stories indexed');
    return;
  }
  
  assert(stats.stories_count > 0, 'Stories should be indexed');
  console.log(`   ${stats.stories_count} stories indexed`);
});

test('Story retrieval works', () => {
  const stories = listStories(5);
  
  if (stories.length === 0) {
    console.log('   (No stories to test)');
    return;
  }
  
  const story = getStoryByName(stories[0].name);
  assert(story !== null, 'Should retrieve story by name');
});

// =============================================================================
// PERFORMANCE TESTS
// =============================================================================

test('Search performance is acceptable (<500ms)', () => {
  const start = Date.now();
  searchDetections('credential', 50);
  const elapsed = Date.now() - start;
  
  assert(elapsed < 500, `Search took ${elapsed}ms, should be <500ms`);
  console.log(`   Search completed in ${elapsed}ms`);
});

test('Pattern retrieval performance is acceptable (<200ms)', () => {
  const start = Date.now();
  getPatternsByTechnique('T1003.001');
  const elapsed = Date.now() - start;
  
  assert(elapsed < 200, `Pattern retrieval took ${elapsed}ms, should be <200ms`);
  console.log(`   Pattern retrieval in ${elapsed}ms`);
});

// =============================================================================
// DATA QUALITY TESTS
// =============================================================================

test('No duplicate detection IDs', () => {
  const db = getDb();
  const dupes = db.prepare(`
    SELECT id, COUNT(*) as cnt FROM detections GROUP BY id HAVING cnt > 1
  `).all();
  
  assert(dupes.length === 0, `Found ${dupes.length} duplicate IDs`);
});

test('MITRE technique IDs are valid format', () => {
  const db = getDb();
  const techniques = db.prepare(`
    SELECT DISTINCT mitre_ids FROM detections WHERE mitre_ids IS NOT NULL LIMIT 100
  `).all();
  
  const techPattern = /^T\d{4}(\.\d{3})?$/;
  let invalid = 0;
  
  for (const row of techniques) {
    const ids = JSON.parse(row.mitre_ids);
    for (const id of ids) {
      if (!techPattern.test(id)) {
        invalid++;
        if (invalid <= 3) console.log(`   Invalid: ${id}`);
      }
    }
  }
  
  if (invalid > 0) {
    warn(`${invalid} invalid MITRE technique ID formats found`);
  }
});

// Run all tests
runTests();
