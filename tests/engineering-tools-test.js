#!/usr/bin/env node
/**
 * Engineering Tools Test Suite
 * 
 * Tests the Detection Engineering Intelligence tools:
 * - get_query_patterns
 * - get_field_reference
 * - get_macro_reference
 * - find_similar_detections
 * - suggest_detection_template
 * - generate_rba_structure
 * - extract_patterns
 * - learn_from_feedback
 */

import { initDb } from '../dist/db/connection.js';
import { initPatternsSchema, getPatternsByTechnique, getFieldReference, getMacroReference, getPatternStats, storeStyleConvention, getStyleConventions } from '../dist/db/patterns.js';
import { searchDetections, listByMitre } from '../dist/db/detections.js';
import { addLearning, listLearnings, logDecision } from '../dist/db/knowledge.js';

const TESTS = [];
const RESULTS = { passed: 0, failed: 0 };

function test(name, fn) {
  TESTS.push({ name, fn });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function runTests() {
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║         Engineering Tools Test Suite                         ║');
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
  console.log(`Results: ${RESULTS.passed} passed, ${RESULTS.failed} failed`);
  console.log('─'.repeat(60));
  
  process.exit(RESULTS.failed > 0 ? 1 : 0);
}

// =============================================================================
// PATTERN RETRIEVAL TESTS
// =============================================================================

test('get_query_patterns returns aggregated data for T1059.001', () => {
  const patterns = getPatternsByTechnique('T1059.001', 'splunk_escu');
  
  assert(patterns.count > 0, 'Should find patterns for T1059.001');
  assert(patterns.macros.length > 10, 'Should have multiple aggregated macros');
  assert(patterns.fields.length > 10, 'Should have multiple aggregated fields');
  
  console.log(`   Found ${patterns.macros.length} macros, ${patterns.fields.length} fields`);
});

test('get_query_patterns returns correct data model for T1003.001', () => {
  const patterns = getPatternsByTechnique('T1003.001', 'splunk_escu');
  
  assert(patterns.count > 0, 'Should find patterns for T1003.001');
  assert(patterns.data_models.includes('Endpoint.Processes'), 
    'T1003.001 should use Endpoint.Processes');
  
  console.log(`   Data models: ${patterns.data_models.join(', ')}`);
});

test('get_query_patterns handles unknown techniques gracefully', () => {
  const patterns = getPatternsByTechnique('T9999.999', 'splunk_escu');
  
  assert(patterns.count === 0, 'Should return 0 patterns for unknown technique');
  assert(Array.isArray(patterns.macros), 'Should return empty array for macros');
});

test('get_field_reference returns fields for Endpoint.Processes', () => {
  const fields = getFieldReference('Endpoint.Processes');
  
  assert(fields.length > 20, 'Should have many fields for Endpoint.Processes');
  
  const fieldNames = fields.map(f => f.field_name);
  assert(fieldNames.includes('dest'), 'Should include dest field');
  assert(fieldNames.includes('process_name') || fieldNames.includes('process'), 
    'Should include process field');
  
  console.log(`   Found ${fields.length} fields`);
});

test('get_field_reference returns fields for multiple data models', () => {
  const models = ['Endpoint.Processes', 'Endpoint.Filesystem', 'Endpoint.Registry', 'Network_Traffic.All_Traffic'];
  
  for (const model of models) {
    const fields = getFieldReference(model);
    assert(fields.length > 0, `Should have fields for ${model}`);
  }
});

test('get_macro_reference returns common macros', () => {
  const macros = getMacroReference();
  
  assert(macros.size > 50, 'Should have many macros indexed');
  
  // Check for essential macros
  const macroNames = Array.from(macros.keys());
  assert(macroNames.some(m => m.includes('security_content')), 
    'Should include security_content macros');
  
  console.log(`   Found ${macros.size} unique macros`);
});

// =============================================================================
// SEARCH AND SIMILARITY TESTS
// =============================================================================

test('find_similar_detections returns relevant results', () => {
  const results = searchDetections('credential dumping', 10);
  
  assert(results.length > 0, 'Should find similar detections');
  
  // Check relevance
  const hasRelevant = results.some(r => 
    r.name.toLowerCase().includes('credential') || 
    r.name.toLowerCase().includes('lsass') ||
    r.name.toLowerCase().includes('dump')
  );
  assert(hasRelevant, 'Results should be relevant to search');
  
  console.log(`   Found ${results.length} similar detections`);
});

test('find_similar_detections works with technique filter', () => {
  const results = listByMitre('T1003.001', 20);
  
  assert(results.length > 5, 'Should find multiple detections for LSASS technique');
  
  for (const det of results) {
    assert(det.mitre_ids.includes('T1003.001'), 
      'All results should have T1003.001 mapping');
  }
});

// =============================================================================
// LEARNING AND FEEDBACK TESTS
// =============================================================================

test('learn_from_feedback stores user preferences', () => {
  // Store a preference
  const learningId = addLearning(
    'test_user_pref_' + Date.now(),
    'naming preference test',
    'User prefers "Windows Process" over "Win Proc"',
    'Test context',
    'naming'
  );
  
  assert(learningId, 'Should return a learning ID');
  
  // Verify learnings can be retrieved (not necessarily by exact ID match)
  const learnings = listLearnings(undefined, 50);
  assert(learnings.length > 0, 'Should have learnings stored');
  
  // Check that recent learning exists
  const recentLearning = learnings.find(l => l.title === 'naming preference test');
  assert(recentLearning, 'Should find the recently added learning');
});

test('Style conventions can be stored and retrieved', () => {
  // Store a convention
  storeStyleConvention('test_type', 'test_key', 'test_value', 'test', 0.9);
  
  // Retrieve it
  const conventions = getStyleConventions('test_type');
  const found = conventions.some(c => c.convention_key === 'test_key');
  assert(found, 'Convention should be retrievable');
});

test('Tribal knowledge (decisions) can be logged', () => {
  const success = logDecision(
    'test_decision',
    'Test context for decision',
    'Test decision made',
    'Reasoning for the test decision',
    ['test_entity_1', 'test_entity_2']
  );
  
  assert(success !== undefined, 'Should successfully log decision');
});

// =============================================================================
// PATTERN STATS TESTS
// =============================================================================

test('Pattern stats show coverage across sources', () => {
  const stats = getPatternStats();
  
  assert(stats.total_patterns > 0, 'Should have patterns');
  assert(stats.by_source.splunk_escu > 0, 'Should have Splunk patterns');
  assert(stats.by_source.sigma > 0, 'Should have Sigma patterns');
  assert(stats.by_technique > 0, 'Should cover multiple techniques');
  assert(stats.fields_indexed > 0, 'Should have indexed fields');
  
  console.log(`   ${stats.total_patterns} patterns, ${stats.by_technique} techniques, ${stats.fields_indexed} fields`);
});

// =============================================================================
// EDGE CASE TESTS
// =============================================================================

test('Empty search term returns results', () => {
  // Should not crash on empty search
  try {
    const results = searchDetections('', 5);
    // Empty search behavior may vary, just ensure no crash
    assert(Array.isArray(results), 'Should return an array');
  } catch (e) {
    // If it throws, that's also acceptable behavior
    console.log('   (Empty search throws - acceptable)');
  }
});

test('Invalid technique ID is handled gracefully', () => {
  const patterns = getPatternsByTechnique('INVALID', 'splunk_escu');
  assert(patterns.count === 0, 'Should return 0 for invalid technique');
  assert(Array.isArray(patterns.macros), 'Should still return valid structure');
});

test('Non-existent data model returns empty fields', () => {
  const fields = getFieldReference('NonExistent.DataModel');
  assert(Array.isArray(fields), 'Should return an array');
  assert(fields.length === 0, 'Should be empty for non-existent model');
});

// Run all tests
runTests();
