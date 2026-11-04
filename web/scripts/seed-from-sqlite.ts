/**
 * Seed Supabase from the existing MCP SQLite database.
 *
 * Usage: npx tsx scripts/seed-from-sqlite.ts
 *
 * Reads from ~/.cache/security-detections-mcp/detections.sqlite
 * and pushes all data to the Supabase project configured in .env.local
 */
import { createClient } from '@supabase/supabase-js';
import Database from 'better-sqlite3';
import { join } from 'path';
import { homedir } from 'os';
import { existsSync } from 'fs';
import { config } from 'dotenv';

// Load .env.local
config({ path: join(import.meta.dirname, '..', '.env.local') });

const SQLITE_PATH = process.env.DETECTIONS_DB_PATH || join(homedir(), '.cache', 'security-detections-mcp', 'detections.sqlite');

if (!existsSync(SQLITE_PATH)) {
  console.error(`SQLite database not found at ${SQLITE_PATH}`);
  console.error('Run the MCP server first to build the database.');
  process.exit(1);
}

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error('Missing NEXT_PUBLIC_SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in .env.local');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);
const sqlite = new Database(SQLITE_PATH, { readonly: true });
const SYNC_SOURCE_TYPE = process.env.SYNC_SOURCE_TYPE || 'nightly_full';
const MAX_SYNC_ERROR_CHARS = 2000;

async function main() {
  let syncRunId: string | null = null;
  let preRunDetections = 0;

  try {
    console.log('=== Seeding Supabase from SQLite ===');
    console.log(`SQLite: ${SQLITE_PATH}`);
    console.log(`Supabase: ${supabaseUrl}`);
    console.log(`Sync source: ${SYNC_SOURCE_TYPE}`);
    console.log('');

    preRunDetections = await getDetectionCount();
    syncRunId = await startSyncRun(preRunDetections);

    await seedDetections();
    // The database trigger reconciles technique edges atomically with each detection batch.
    await seedTechniqueTactics();
    await seedAttackTechniques();
    await seedAttackActors();
    await seedAttackSoftware();
    await seedActorTechniques();
    await seedSoftwareTechniques();
    await seedProcedureReference();
    await seedStories();

    const postRunDetections = await getDetectionCount();
    const detectionsAdded = Math.max(postRunDetections - preRunDetections, 0);

    await completeSyncRun(syncRunId, {
      detectionsTotal: postRunDetections,
      detectionsAdded,
      detectionsUpdated: 0,
    });

    console.log('\n=== Seed complete! ===');
  } catch (err) {
    if (syncRunId) {
      await failSyncRun(syncRunId, formatSyncError(err));
    }
    throw err;
  } finally {
    sqlite.close();
  }
}

async function getDetectionCount(): Promise<number> {
  const { count, error } = await supabase
    .from('detections')
    .select('id', { count: 'exact', head: true });

  if (error || count === null) {
    throw new Error(`Failed to query detection count: ${error?.message || 'count unavailable'}`);
  }

  return count;
}

async function startSyncRun(preRunDetections: number): Promise<string> {
  const { data, error } = await supabase
    .from('sync_runs')
    .insert({
      source_type: SYNC_SOURCE_TYPE,
      started_at: new Date().toISOString(),
      detections_total: preRunDetections,
      detections_added: 0,
      detections_updated: 0,
      status: 'running',
      error: null,
    })
    .select('id')
    .single();

  if (error || !data?.id) {
    throw new Error(`Failed to create sync run: ${error?.message || 'missing sync run id'}`);
  }

  console.log(`Started sync run: ${data.id}`);
  return data.id as string;
}

async function completeSyncRun(
  syncRunId: string,
  metrics: { detectionsTotal: number; detectionsAdded: number; detectionsUpdated: number }
): Promise<void> {
  const { error } = await supabase
    .from('sync_runs')
    .update({
      completed_at: new Date().toISOString(),
      detections_total: metrics.detectionsTotal,
      detections_added: metrics.detectionsAdded,
      detections_updated: metrics.detectionsUpdated,
      status: 'completed',
      error: null,
    })
    .eq('id', syncRunId);

  if (error) {
    throw new Error(`Failed to finalize sync run ${syncRunId}: ${error.message}`);
  }
}

async function failSyncRun(syncRunId: string, errorMessage: string): Promise<void> {
  const { error } = await supabase
    .from('sync_runs')
    .update({
      completed_at: new Date().toISOString(),
      status: 'failed',
      error: errorMessage,
    })
    .eq('id', syncRunId);

  if (error) {
    console.error(`Failed to mark sync run ${syncRunId} as failed: ${error.message}`);
  }
}

function formatSyncError(err: unknown): string {
  const message = err instanceof Error
    ? `${err.message}${err.stack ? `\n${err.stack}` : ''}`
    : String(err);
  return message.slice(0, MAX_SYNC_ERROR_CHARS);
}

const CONFLICT_KEYS: Record<string, string> = {
  detections: 'source_type,id', technique_tactics: 'technique_id,tactic_name',
  attack_techniques: 'technique_id', attack_actors: 'actor_id', attack_software: 'software_id',
  actor_techniques: 'actor_id,technique_id', software_techniques: 'software_id,technique_id',
  procedure_reference: 'id', stories: 'id',
};

async function upsertBatch(table: string, rows: Record<string, unknown>[], batchSize = 500) {
  const onConflict = CONFLICT_KEYS[table];
  if (!onConflict) throw new Error(`Missing conflict key for ${table}`);
  for (let i = 0; i < rows.length; i += batchSize) {
    const { error } = await supabase.from(table).upsert(rows.slice(i, i + batchSize), { onConflict });
    if (error) throw new Error(`${table} batch ${i} failed: ${error.message}`);
  }
  return rows.length;
}

function optionalRows(table: string): Record<string, unknown>[] {
  const exists = sqlite.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table);
  if (!exists) {
    console.log(`  ${table} not present in SQLite, skipping`);
    return [];
  }
  return sqlite.prepare(`SELECT * FROM ${table}`).all() as Record<string, unknown>[];
}

function parseJsonSafe(val: string | null): unknown {
  if (!val) return [];
  try {
    return JSON.parse(val);
  } catch {
    return [];
  }
}

function parseTechniqueIds(value: unknown): string[] {
  const parsed: unknown = typeof value === 'string' ? JSON.parse(value) : value;
  if (!Array.isArray(parsed) || parsed.some(id => typeof id !== 'string' || !id)) {
    throw new Error('Invalid mitre_ids in SQLite; refusing to erase technique edges');
  }
  return parsed;
}

async function seedDetections() {
  console.log('Seeding detections...');
  const rows = sqlite.prepare('SELECT * FROM detections').all() as Record<string, unknown>[];
  console.log(`  Found ${rows.length} detections in SQLite`);

  const mapped = rows.map(row => ({
    id: row.id,
    name: row.name,
    description: row.description,
    query: row.query,
    source_type: row.source_type,
    mitre_ids: parseTechniqueIds(row.mitre_ids),
    mitre_tactics: parseJsonSafe(row.mitre_tactics as string),
    severity: row.severity,
    author: row.author,
    logsource_category: row.logsource_category,
    logsource_product: row.logsource_product,
    logsource_service: row.logsource_service,
    status: row.status,
    date_created: row.date_created,
    date_modified: row.date_modified,
    refs: parseJsonSafe(row.refs as string),
    tags: parseJsonSafe(row.tags as string),
    cves: parseJsonSafe(row.cves as string),
    data_sources: parseJsonSafe(row.data_sources as string),
    process_names: parseJsonSafe(row.process_names as string),
    file_paths: parseJsonSafe(row.file_paths as string),
    registry_paths: parseJsonSafe(row.registry_paths as string),
    platforms: parseJsonSafe(row.platforms as string),
    detection_type: row.detection_type,
    asset_type: row.asset_type,
    security_domain: row.security_domain,
    raw_yaml: row.raw_yaml,
    analytic_stories: parseJsonSafe(row.analytic_stories as string),
    falsepositives: parseJsonSafe(row.falsepositives as string),
    kql_category: row.kql_category,
    kql_tags: parseJsonSafe(row.kql_tags as string),
    kql_keywords: parseJsonSafe(row.kql_keywords as string),
    sublime_attack_types: parseJsonSafe(row.sublime_attack_types as string),
    sublime_detection_methods: parseJsonSafe(row.sublime_detection_methods as string),
    sublime_tactics: parseJsonSafe(row.sublime_tactics as string),
  }));

  const count = await upsertBatch('detections', mapped);
  console.log(`  Inserted ${count} detections`);
}

async function seedTechniqueTactics() {
  console.log('Seeding technique_tactics...');
  const rows = sqlite.prepare('SELECT * FROM technique_tactics').all() as Record<string, unknown>[];
  console.log(`  Found ${rows.length} rows`);
  const count = await upsertBatch('technique_tactics', rows);
  console.log(`  Inserted ${count} rows`);
}

async function seedAttackTechniques() {
  console.log('Seeding attack_techniques...');
  {
    const rows = optionalRows('attack_techniques');
    console.log(`  Found ${rows.length} rows`);
    const mapped = rows.map(row => ({
      technique_id: row.technique_id,
      name: row.name,
      description: row.description,
      platforms: parseJsonSafe(row.platforms as string),
      data_sources: parseJsonSafe(row.data_sources as string),
      is_subtechnique: Boolean(row.is_subtechnique),
      parent_technique_id: row.parent_technique_id,
      url: row.url,
    }));
    const count = await upsertBatch('attack_techniques', mapped);
    console.log(`  Inserted ${count} rows`);
  }
}

async function seedAttackActors() {
  console.log('Seeding attack_actors...');
  {
    const rows = optionalRows('attack_actors');
    console.log(`  Found ${rows.length} rows`);
    const mapped = rows.map(row => ({
      actor_id: row.actor_id,
      name: row.name,
      aliases: parseJsonSafe(row.aliases as string),
      description: row.description,
      external_references: parseJsonSafe(row.external_references as string),
      created: row.created,
      modified: row.modified,
    }));
    const count = await upsertBatch('attack_actors', mapped);
    console.log(`  Inserted ${count} rows`);
  }
}

async function seedAttackSoftware() {
  console.log('Seeding attack_software...');
  {
    const rows = optionalRows('attack_software');
    console.log(`  Found ${rows.length} rows`);
    const mapped = rows.map(row => ({
      software_id: row.software_id,
      name: row.name,
      software_type: row.software_type,
      description: row.description,
      platforms: parseJsonSafe(row.platforms as string),
      aliases: parseJsonSafe(row.aliases as string),
    }));
    const count = await upsertBatch('attack_software', mapped);
    console.log(`  Inserted ${count} rows`);
  }
}

async function seedActorTechniques() {
  console.log('Seeding actor_techniques...');
  {
    const rows = optionalRows('actor_techniques');
    console.log(`  Found ${rows.length} rows`);
    const count = await upsertBatch('actor_techniques', rows);
    console.log(`  Inserted ${count} rows`);
  }
}

async function seedSoftwareTechniques() {
  console.log('Seeding software_techniques...');
  {
    const rows = optionalRows('software_techniques');
    console.log(`  Found ${rows.length} rows`);
    const count = await upsertBatch('software_techniques', rows);
    console.log(`  Inserted ${count} rows`);
  }
}

async function seedProcedureReference() {
  console.log('Seeding procedure_reference...');
  {
    const rows = optionalRows('procedure_reference');
    console.log(`  Found ${rows.length} rows`);
    const mapped = rows.map(row => ({
      id: row.id,
      technique_id: row.technique_id,
      name: row.name,
      category: row.category,
      description: row.description,
      source: row.source,
      indicators: parseJsonSafe(row.indicators as string),
      detection_count: row.detection_count,
      confidence: row.confidence,
    }));
    const count = await upsertBatch('procedure_reference', mapped);
    console.log(`  Inserted ${count} rows`);
  }
}

async function seedStories() {
  console.log('Seeding stories...');
  {
    const rows = optionalRows('stories');
    console.log(`  Found ${rows.length} rows`);
    const mapped = rows.map(row => ({
      id: row.id,
      name: row.name,
      description: row.description,
      narrative: row.narrative,
      author: row.author,
      date: row.date,
      version: row.version,
      status: row.status,
      refs: parseJsonSafe(row.refs as string),
      category: row.category,
      usecase: row.usecase,
      detection_names: parseJsonSafe(row.detection_names as string),
    }));
    const count = await upsertBatch('stories', mapped);
    console.log(`  Inserted ${count} rows`);
  }
}

main().catch(err => {
  console.error('Seed failed:', err);
  process.exit(1);
});
