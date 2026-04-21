#!/usr/bin/env node
/**
 * Jamf Protect parser fixture test.
 *
 * Directly exercises parseJamfProtectFile against checked-in fixtures so we
 * can catch regressions in MITRE extraction, severity normalization, and
 * macOS field handling without needing a full indexing run.
 */

import { parseJamfProtectFile } from '../dist/parsers/jamf_protect.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = join(__dirname, 'fixtures', 'jamf_protect');

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
  console.log('  Jamf Protect Parser - Fixture Test');
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

// applescript_gather_clipboard: MitreCategories=[LivingOffTheLand, CredentialAccess]
test('applescript_gather_clipboard parses with both a MITRE tactic and a Jamf-specific label mapped', () => {
  const d = parseJamfProtectFile(join(FIXTURE_DIR, 'applescript_gather_clipboard.yaml'));
  assert(d !== null, 'parser should return a detection');
  assert(d.source_type === 'jamf_protect', `source_type should be jamf_protect, got ${d.source_type}`);
  assert(d.id.startsWith('jamf-96cea4cc-a944-4220-9f8d-99d91622a6f5-'), `id should embed uuid with uniqueness suffix, got ${d.id}`);
  assert(d.name === 'AppleScript Clipboard Activity', `label preferred over name, got ${d.name}`);
  assert(d.severity === 'informational', `severity should be lowercased, got ${d.severity}`);
  assert(d.platforms.includes('macos'), 'platforms should include macos');
  assert(d.asset_type === 'Endpoint', 'asset_type should be Endpoint');
  assert(d.security_domain === 'endpoint', 'security_domain should be endpoint');
  assert(d.logsource_category === 'GPProcessEvent', `logsource_category should be GPProcessEvent, got ${d.logsource_category}`);
  assert(d.data_sources.includes('Process Events'), 'data_sources should derive Process Events from GPProcessEvent');

  // MitreCategories: [LivingOffTheLand, CredentialAccess]
  // CredentialAccess → tactic credential-access
  // LivingOffTheLand → techniques T1059, T1218 + tactics execution, defense-evasion
  assert(d.mitre_tactics.includes('credential-access'), `mitre_tactics should include credential-access, got ${JSON.stringify(d.mitre_tactics)}`);
  assert(d.mitre_tactics.includes('execution'), `LivingOffTheLand should map to execution tactic, got ${JSON.stringify(d.mitre_tactics)}`);
  assert(d.mitre_tactics.includes('defense-evasion'), `LivingOffTheLand should map to defense-evasion tactic, got ${JSON.stringify(d.mitre_tactics)}`);
  assert(d.mitre_ids.includes('T1059'), `LivingOffTheLand should map to T1059, got ${JSON.stringify(d.mitre_ids)}`);
  assert(d.mitre_ids.includes('T1218'), `LivingOffTheLand should map to T1218, got ${JSON.stringify(d.mitre_ids)}`);

  // Raw Jamf labels preserved in tags for searchability
  assert(d.tags.includes('LivingOffTheLand'), 'raw Jamf label LivingOffTheLand should be preserved in tags');
  assert(d.tags.includes('CredentialAccess'), 'raw tactic label should be preserved in tags');
  assert(d.tags.includes('Collection'), 'categories value should be preserved in tags');

  // Process name extraction: signingInfo.appid == "com.apple.osascript" → osascript
  assert(d.process_names.includes('osascript'), `should extract osascript from appid pattern, got ${JSON.stringify(d.process_names)}`);
});

// known_vulnerable_log4j_jar_installation: MitreCategories=null, inputType=GPFSEvent
test('known_vulnerable_log4j_jar_installation handles null MitreCategories', () => {
  const d = parseJamfProtectFile(join(FIXTURE_DIR, 'known_vulnerable_log4j_jar_installation.yaml'));
  assert(d !== null, 'parser should return a detection even with null MitreCategories');
  assert(d.mitre_ids.length === 0, `mitre_ids should be empty for null MitreCategories, got ${JSON.stringify(d.mitre_ids)}`);
  assert(d.mitre_tactics.length === 0, `mitre_tactics should be empty for null MitreCategories, got ${JSON.stringify(d.mitre_tactics)}`);
  assert(d.logsource_category === 'GPFSEvent', `logsource_category should be GPFSEvent, got ${d.logsource_category}`);
  assert(d.data_sources.includes('File System Events'), 'data_sources should map GPFSEvent → File System Events');
});

// hidden_account_created_dscl: MitreCategories=[Persistence]
test('hidden_account_created_dscl extracts Persistence tactic and dscl process name', () => {
  const d = parseJamfProtectFile(join(FIXTURE_DIR, 'hidden_account_created_dscl.yaml'));
  assert(d !== null, 'parser should return a detection');
  assert(d.mitre_tactics.includes('persistence'), `mitre_tactics should include persistence, got ${JSON.stringify(d.mitre_tactics)}`);
  assert(d.process_names.includes('dscl'), `should extract dscl from lastPathComponent pattern, got ${JSON.stringify(d.process_names)}`);
});

test('parser returns null on unreadable file', () => {
  const d = parseJamfProtectFile(join(FIXTURE_DIR, 'does-not-exist.yaml'));
  assert(d === null, 'parser should return null for missing file');
});

runTests();
