#!/usr/bin/env node
/**
 * Sublime parser fixture test.
 *
 * Exercises parseSublimeFile against a checked-in fixture shaped like the
 * delivr.to Sublime rules (delivr-to/detections/sublime-rules), which are
 * indexed through SUBLIME_PATHS alongside sublime-security/sublime-rules but
 * omit `id`, attack_types and tactics_and_techniques.
 */

import { parseSublimeFile } from '../dist/parsers/sublime.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = join(__dirname, 'fixtures', 'sublime');

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
  console.log('  Sublime Parser - Fixture Test');
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

const DELIVR_FIXTURE = join(FIXTURE_DIR, 'delivr_attachment_svg_script.yml');

test('delivr.to-shaped rule parses as a sublime detection', () => {
  const d = parseSublimeFile(DELIVR_FIXTURE);
  assert(d !== null, 'parser should return a detection');
  assert(d.source_type === 'sublime', `source_type should be sublime, got ${d.source_type}`);
  assert(d.name === 'Attachment: SVG File with Script Element', `unexpected name ${d.name}`);
  assert(d.severity === 'medium', `severity should be medium, got ${d.severity}`);
  assert(d.query.includes('type.inbound'), 'query should carry the MQL source');
  assert(d.detection_type === 'Rule', `detection_type should be Rule, got ${d.detection_type}`);
  assert(d.platforms.includes('email'), 'platforms should include email');
});

test('missing id falls back to a stable path-derived id', () => {
  const a = parseSublimeFile(DELIVR_FIXTURE);
  const b = parseSublimeFile(DELIVR_FIXTURE);
  assert(/^sublime-[0-9a-f]{32}$/.test(a.id), `id should be sublime-<32 hex>, got ${a.id}`);
  assert(a.id === b.id, 'generated id should be deterministic');
});

test('twitter-only author is used as the author name', () => {
  const d = parseSublimeFile(DELIVR_FIXTURE);
  assert(d.author === 'delivr_to', `author should be delivr_to, got ${d.author}`);
});

test('references and tags are preserved; absent ATT&CK hints yield no MITRE ids', () => {
  const d = parseSublimeFile(DELIVR_FIXTURE);
  assert(d.references.length === 1 && d.references[0].startsWith('https://delivr.to/'), 'delivr.to reference should be kept');
  assert(d.tags.includes('Suspicious Attachment'), 'tags should be kept');
  assert(Array.isArray(d.mitre_ids) && d.mitre_ids.length === 0, `mitre_ids should be empty, got ${JSON.stringify(d.mitre_ids)}`);
});

runTests();
