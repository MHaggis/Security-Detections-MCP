/**
 * Seed Supabase from the existing MCP SQLite database.
 *
 * Usage: npx tsx scripts/seed-from-sqlite.ts
 *
 * Reads from ~/.cache/security-detections-mcp/detections.sqlite
 * and pushes all data to the Supabase project configured in .env.local
 */
import { createClient } from '@supabase/supabase-js';
import { createCatalogPostgres } from './catalog-postgres.mjs';
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

const transport = process.env.CATALOG_SEED_TRANSPORT || 'postgres';
if (!['postgres', 'http'].includes(transport)) {
  console.error('Invalid CATALOG_SEED_TRANSPORT; expected postgres or explicit legacy http');
  process.exit(1);
}
const databaseUrl = process.env.SUPABASE_CATALOG_DATABASE_URL;
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
if (transport === 'postgres' && !databaseUrl) {
  console.error('Missing SUPABASE_CATALOG_DATABASE_URL; direct catalog sync fails closed');
  process.exit(1);
}
if (transport === 'http' && (!supabaseUrl || !supabaseKey)) {
  console.error('Explicit HTTP transport requires Supabase URL and service role key');
  process.exit(1);
}
// HTTP is an explicit compatibility/test option, never a fallback from PostgreSQL.
const direct = transport === 'postgres' ? createCatalogPostgres(databaseUrl!) : null;
const supabase = transport === 'http' ? createClient(supabaseUrl!, supabaseKey!) : null;
const sqlite = new Database(SQLITE_PATH, { readonly: true });
const SYNC_SOURCE_TYPE = process.env.SYNC_SOURCE_TYPE || 'nightly_full';
const MAX_SYNC_ERROR_CHARS = 2000;

async function main() {
  let syncRunId: string | null = null;
  let preRunDetections = 0;

  try {
    console.log('=== Seeding Supabase from SQLite ===');
    console.log(`SQLite: ${SQLITE_PATH}`);
    console.log(`Catalog transport: ${transport}`);
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
    if (direct) await direct.close();
  }
}

async function getDetectionCount(): Promise<number> {
  if (direct) return direct.count();
  const { count, error } = await supabase!
    .from('detections')
    .select('id', { count: 'exact', head: true });

  if (error || count === null) {
    throw new Error(`Failed to query detection count: ${error?.message || 'count unavailable'}`);
  }

  return count;
}

async function startSyncRun(preRunDetections: number): Promise<string> {
  if (direct) return direct.start(SYNC_SOURCE_TYPE, preRunDetections);
  const { data, error } = await supabase!
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
  if (direct) return direct.complete(syncRunId, metrics);
  const { error } = await supabase!
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
  if (direct) {
    try { await direct.fail(syncRunId, errorMessage); }
    catch { console.error('Failed to mark catalog sync failed'); }
    return;
  }
  const { error } = await supabase!
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

// Keep trigger-backed catalog writes below hosted statement limits. A canceled
// PostgreSQL statement rolls back its complete batch, so only SQLSTATE 57014 is
// eligible for a smaller retry when the server reports a statement timeout.
// Explicit cancellation and network/constraint/permission failures propagate.
async function upsertBatch(table: string, rows: Record<string, unknown>[], batchSize = 100) {
  const onConflict = CONFLICT_KEYS[table];
  if (!onConflict) throw new Error(`Missing conflict key for ${table}`);

  async function writeBatch(batch: Record<string, unknown>[], offset: number): Promise<void> {
    const json = JSON.stringify(batch);
    if (Buffer.byteLength(json, 'utf8') > 2 * 1024 * 1024) {
      if (batch.length === 1) throw new Error(`${table} batch ${offset} failed: single row exceeds 2 MiB transport limit`);
      const middle = Math.floor(batch.length / 2);
      await writeBatch(batch.slice(0, middle), offset);
      await writeBatch(batch.slice(middle), offset + middle);
      return;
    }
    const payload = Buffer.from(json, 'utf8').toString('base64');
    const { data, error } = direct
      ? await direct.write(table, payload)
      : await supabase!.rpc('seed_catalog_batch', { p_table: table, p_payload: payload });
    if (!error) {
      if (!data || data.processed !== batch.length) {
        throw new Error(`${table} batch ${offset} failed: invalid catalog acknowledgement`);
      }
      return;
    }
    if (error.code === '57014' && /statement timeout/i.test(error.message) && batch.length > 1) {
      const middle = Math.floor(batch.length / 2);
      console.warn(`${table} batch ${offset} canceled (57014); splitting ${batch.length} rows into ${middle} and ${batch.length - middle}`);
      await writeBatch(batch.slice(0, middle), offset);
      await writeBatch(batch.slice(middle), offset + middle);
      return;
    }
    throw new Error(`${table} batch ${offset} failed: ${error.message}`);
  }

  for (let i = 0; i < rows.length; i += batchSize) {
    await writeBatch(rows.slice(i, i + batchSize), i);
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
  console.log(`  Processed ${count} detections`);
}

async function seedTechniqueTactics() {
  console.log('Seeding technique_tactics...');
  const rows = sqlite.prepare('SELECT * FROM technique_tactics').all() as Record<string, unknown>[];
  console.log(`  Found ${rows.length} rows`);
  const count = await upsertBatch('technique_tactics', rows);
  console.log(`  Processed ${count} rows`);
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
    console.log(`  Processed ${count} rows`);
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
    console.log(`  Processed ${count} rows`);
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
    console.log(`  Processed ${count} rows`);
  }
}

async function seedActorTechniques() {
  console.log('Seeding actor_techniques...');
  {
    const rows = optionalRows('actor_techniques');
    console.log(`  Found ${rows.length} rows`);
    const count = await upsertBatch('actor_techniques', rows);
    console.log(`  Processed ${count} rows`);
  }
}

async function seedSoftwareTechniques() {
  console.log('Seeding software_techniques...');
  {
    const rows = optionalRows('software_techniques');
    console.log(`  Found ${rows.length} rows`);
    const count = await upsertBatch('software_techniques', rows);
    console.log(`  Processed ${count} rows`);
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
    console.log(`  Processed ${count} rows`);
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
    console.log(`  Processed ${count} rows`);
  }
}

main().catch(err => {
  console.error('Seed failed:', err);
  process.exit(1);
});
