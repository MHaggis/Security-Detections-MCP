#!/usr/bin/env node
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseSplunkFile } from '../dist/parsers/splunk.js';

function parseFixture(name) {
  const detection = parseSplunkFile(fileURLToPath(new URL(`./fixtures/splunk/${name}.yml`, import.meta.url)));
  assert.ok(detection, `${name} should parse`);
  return detection;
}

for (const format of ['current', 'legacy']) {
  test(`Splunk ${format} metadata preserves technique, story, CVE, and asset associations`, () => {
    const detection = parseFixture(format);
    assert.equal(detection.source_type, 'splunk_escu');
    assert.deepEqual(detection.mitre_ids, ['T1059.001']);
    assert.deepEqual(detection.mitre_tactics, ['execution']);
    assert.deepEqual(detection.analytic_stories, ['Synthetic PowerShell Story']);
    assert.deepEqual(detection.tags, ['Synthetic PowerShell Story']);
    assert.deepEqual(detection.cves, ['CVE-2026-0001']);
    assert.equal(detection.asset_type, 'Endpoint');
    assert.equal(detection.security_domain, 'endpoint');
    assert.equal(detection.date_created, format === 'current' ? '2026-10-01' : '2025-01-01');
    assert.equal(detection.date_modified, format === 'current' ? '2026-10-02' : null);
  });
}

test('top-level metadata takes precedence with per-field legacy fallback', () => {
  const detection = parseFixture('mixed');
  assert.deepEqual(detection.mitre_ids, ['T1059.001']);
  assert.deepEqual(detection.mitre_tactics, ['execution']);
  assert.deepEqual(detection.analytic_stories, ['Current Story']);
  assert.deepEqual(detection.tags, ['Current Story']);
  assert.equal(detection.asset_type, 'Endpoint');
  assert.equal(detection.security_domain, 'endpoint');
  assert.deepEqual(detection.cves, ['CVE-2026-0001']);
  assert.equal(detection.date_created, '2026-10-01');
});

test('explicit empty top-level metadata clears legacy associations', () => {
  const detection = parseFixture('empty');
  for (const field of ['mitre_ids', 'mitre_tactics', 'analytic_stories', 'tags', 'cves']) {
    assert.deepEqual(detection[field], [], `${field} should stay empty`);
  }
  assert.equal(detection.asset_type, null);
  assert.equal(detection.security_domain, null);
  assert.equal(detection.date_created, null);
  assert.equal(detection.date_modified, null);
});

test('unreadable Splunk files return null', () => {
  assert.equal(parseSplunkFile(fileURLToPath(new URL('./fixtures/splunk/missing.yml', import.meta.url))), null);
});
