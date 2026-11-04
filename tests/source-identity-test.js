import './isolated-db.js';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { createSchema } from '../dist/db/schema.js';
import * as legacy from '../dist/db.js';
import * as modular from '../dist/db/detections.js';
import { getDb } from '../dist/db/connection.js';
import { getActorTechniques, getActorCoverage } from '../dist/db/attack.js';
import { searchTools } from '../dist/tools/detections/search.js';

const collision = 'ee39a9f7-5a79-4b0a-9815-d36b3cf28d3e';
const rule = (source_type, name, mitre_ids = ['T1566']) => ({
  id: collision, source_type, name, description: name, query: name, raw_yaml: name,
  mitre_ids, references: [], falsepositives: [], tags: [], cves: [], analytic_stories: [],
  data_sources: [], process_names: [], file_paths: [], registry_paths: [], mitre_tactics: [],
  platforms: [], kql_tags: [], kql_keywords: [], sublime_attack_types: [],
  sublime_detection_methods: [], sublime_tactics: [], file_path: 'test-fixture',
});
for (const [label, writer] of [['legacy', legacy], ['modular', modular]]) {
  legacy.clearDb();
  writer.insertDetection(rule('sigma', 'Sigma FastPass'));
  assert.equal(writer.getDetectionById(collision).source_type, 'sigma');
  assert.equal(writer.getRawYaml(collision), 'Sigma FastPass');
  writer.insertDetection(rule('elastic', 'Elastic FastPass', ['T1078']));
  for (const reader of [legacy, modular]) {
    assert.equal(reader.getDetectionCount(), 2);
    assert.equal(reader.getDetectionById(collision, 'sigma').name, 'Sigma FastPass');
    assert.equal(reader.getRawYaml(collision, 'elastic'), 'Elastic FastPass');
    assert.throws(() => reader.getDetectionById(collision), /multiple sources.*elastic, sigma/);
    assert.throws(() => reader.getRawYaml(collision), /Specify source_type/);
    assert.equal(reader.getDetectionById(collision, 'kql'), null);
  }
  assert.deepEqual(modular.listByMitre('T1566').map(d => d.source_type), ['sigma']);
  writer.insertDetection(rule('sigma', 'Updated FastPass', ['T1059']));
  assert.equal(writer.getDetectionCount(), 2);
  assert.equal(modular.listByMitre('T1566').length, 0);
  assert.deepEqual(modular.listByMitre('T1059').map(d => d.source_type), ['sigma']);
  assert.equal(modular.listByMitre('T1078')[0].name, 'Elastic FastPass');
  assert.equal(modular.searchDetections('FastPass').length, 2);
  assert.equal(modular.searchDetections('Updated').length, 1);
  modular.populateJunctionTables();
  modular.populateJunctionTables();
  assert.equal(getDb().prepare('SELECT COUNT(*) n FROM detection_techniques').get().n, 2);
  console.log(`PASS ${label}: collision retention, scoped update/read, ambiguity, FTS and exact edges`);
}

// Counts use logical pairs, including when both rules cover the same technique.
legacy.insertDetection(rule('sigma', 'Sigma Shared', ['T1078']));
const db = getDb();
db.exec("INSERT INTO attack_actors(actor_id,name) VALUES ('test-actor','Test actor'); INSERT INTO actor_techniques(actor_id,technique_id) VALUES ('test-actor','T1078')");
assert.equal(getActorTechniques('test-actor')[0].detection_count, 2);
const coverage = getActorCoverage('test-actor', 'kql');
assert.equal(coverage.covered_techniques.length, 0);
assert.equal(getActorCoverage('test-actor', 'sigma').covered_techniques[0].detection_count, 1);
const getTool = searchTools.find(t => t.name === 'get_by_id');
assert.equal((await getTool.handler({ id: collision, source_type: 'sigma' })).source_type, 'sigma');
await assert.rejects(getTool.handler({ id: collision }), /multiple sources/);
console.log('PASS actor counts and source filtering; MCP tool source/ambiguity behavior');

// Upgrade the actual previous table shape, including FTS, rowids and materialized links.
const upgrade = new Database(':memory:');
createSchema(upgrade);
const oldFts = upgrade.prepare("SELECT sql FROM sqlite_master WHERE name='detections_fts'").get().sql;
const oldTriggers = upgrade.prepare("SELECT sql FROM sqlite_master WHERE type='trigger' AND tbl_name='detections' AND name NOT LIKE 'detections_edges_%'").all();
const tableSql = upgrade.prepare("SELECT sql FROM sqlite_master WHERE name='detections'").get().sql;
upgrade.exec('PRAGMA foreign_keys=OFF; DROP TABLE detection_techniques; DROP TABLE detections_fts; DROP TABLE detections');
upgrade.exec(tableSql.replace('id TEXT NOT NULL', 'id TEXT PRIMARY KEY').replace(',\n      PRIMARY KEY (source_type, id)', ''));
upgrade.exec("CREATE TABLE detection_techniques(detection_id TEXT NOT NULL, technique_id TEXT NOT NULL, PRIMARY KEY(detection_id,technique_id)); INSERT INTO detections(rowid,id,name,source_type,mitre_ids) VALUES (42,'old','Migrated needle','sigma','[\"T1566\"]'); INSERT INTO detection_techniques VALUES ('old','T1566'); PRAGMA foreign_keys=ON");
upgrade.exec(oldFts);
for (const trigger of oldTriggers) upgrade.exec(trigger.sql);
upgrade.exec("INSERT INTO detections_fts(detections_fts) VALUES ('rebuild')");
assert.equal(upgrade.prepare("SELECT count(*) n FROM detections_fts WHERE detections_fts MATCH 'needle'").get().n, 1);
createSchema(upgrade);
createSchema(upgrade);
assert.equal(upgrade.prepare('SELECT rowid FROM detections').get().rowid, 42);
assert.equal(upgrade.prepare("SELECT count(*) n FROM detections_fts WHERE detections_fts MATCH 'needle'").get().n, 1);
assert.deepEqual(upgrade.prepare('SELECT * FROM detection_techniques').get(), {source_type:'sigma', detection_id:'old', technique_id:'T1566'});
upgrade.exec("INSERT INTO detections(id,name,source_type) VALUES ('old','Other','elastic')");
assert.equal(upgrade.prepare('SELECT count(*) n FROM detections').get().n, 2);
assert.throws(() => upgrade.exec("INSERT INTO detection_techniques VALUES ('kql','old','T1078')"), /FOREIGN KEY/);
upgrade.exec("DELETE FROM detections WHERE source_type='sigma'");
assert.equal(upgrade.prepare('SELECT count(*) n FROM detection_techniques').get().n, 0);
upgrade.close();

const invalid = new Database(':memory:');
invalid.exec("CREATE TABLE detections(id TEXT PRIMARY KEY,name TEXT NOT NULL,source_type TEXT NOT NULL); CREATE TABLE detection_techniques(detection_id TEXT,technique_id TEXT); INSERT INTO detections VALUES ('old','Old','sigma'); INSERT INTO detection_techniques VALUES ('orphan','T1566')");
assert.throws(() => createSchema(invalid), /orphan/);
assert.equal(invalid.prepare('SELECT count(*) n FROM detections').get().n, 1);
assert.equal(invalid.pragma('table_info(detections)').find(c => c.name === 'id').pk, 1);
assert.equal(invalid.prepare('SELECT count(*) n FROM detection_techniques').get().n, 1);
invalid.close();
const invalidCopy = new Database(':memory:');
invalidCopy.exec("CREATE TABLE detections(id TEXT PRIMARY KEY,name TEXT NOT NULL,source_type TEXT NOT NULL); INSERT INTO detections VALUES (NULL,'Old nullable ID','sigma')");
assert.throws(() => createSchema(invalidCopy), /NOT NULL/);
assert.equal(invalidCopy.prepare('SELECT count(*) n FROM detections').get().n, 1);
assert.equal(invalidCopy.prepare('SELECT id FROM detections').get().id, null);
assert.equal(invalidCopy.prepare("SELECT count(*) n FROM sqlite_master WHERE name='detections_identity_new'").get().n, 0);
invalidCopy.close();
console.log('PASS legacy migration, repeat initialization, rowid/FTS/edge preservation, FK rejection and failed-migration rollback');

const { parseSigmaFile } = await import('../dist/parsers/sigma.js');
const { parseElasticFile } = await import('../dist/parsers/elastic.js');
const { fileURLToPath } = await import('node:url');
const sigma = parseSigmaFile(fileURLToPath(new URL('./fixtures/source-identity/sigma/okta_fastpass_phishing_detection.yml', import.meta.url)));
const elastic = parseElasticFile(fileURLToPath(new URL('./fixtures/source-identity/elastic/initial_access_okta_fastpass_phishing.toml', import.meta.url)));
assert.equal(sigma.id, elastic.id);
legacy.clearDb();
legacy.insertDetection(sigma);
legacy.insertDetection(elastic);
assert.equal(legacy.getDetectionCount(), 2);
assert.equal(modular.getDetectionById(collision, 'sigma').name, sigma.name);
assert.equal(modular.getDetectionById(collision, 'elastic').query, elastic.query);
legacy.closeDb();
const { closeDb } = await import('../dist/db/connection.js');
closeDb();

const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = await import('@modelcontextprotocol/sdk/client/stdio.js');
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [fileURLToPath(new URL('../dist/index.js', import.meta.url))],
  env: { DETECTIONS_DB_PATH: process.env.DETECTIONS_DB_PATH, SIGMA_PATHS: fileURLToPath(new URL('./fixtures/source-identity/sigma', import.meta.url)) },
  stderr: 'pipe',
});
const client = new Client({ name: 'identity-test', version: '1.0.0' });
try {
  await client.connect(transport, { timeout: 30000 });
  const ambiguous = await client.callTool({name:'get_by_id', arguments:{id:collision}});
  assert.equal(ambiguous.isError, true);
  assert.match(ambiguous.content[0].text, /multiple sources.*elastic, sigma/);
  for (const source_type of ['sigma', 'elastic']) {
    const qualified = await client.callTool({name:'get_by_id', arguments:{id:collision, source_type}});
    assert(!qualified.isError);
    assert.equal(JSON.parse(qualified.content[0].text).source_type, source_type);
    const raw = await client.callTool({name:'get_raw_yaml', arguments:{id:collision, source_type}});
    assert.equal(JSON.parse(raw.content[0].text).yaml, source_type === 'sigma' ? sigma.raw_yaml : elastic.raw_yaml);
  }
} finally {
  await client.close();
  await transport.close();
}
console.log('PASS real Sigma/Elastic UUID collision through parsers, database and MCP stdio qualified/ambiguous reads');
