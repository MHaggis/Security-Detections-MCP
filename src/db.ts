import Database from 'better-sqlite3';
import { homedir, platform } from 'os';
import { join } from 'path';
import { mkdirSync, existsSync, unlinkSync } from 'fs';
import type { Detection, IndexStats, AnalyticStory } from './types.js';

const CACHE_DIR = join(homedir(), '.cache', 'security-detections-mcp');
const DB_PATH = join(CACHE_DIR, 'detections.sqlite');

let db: Database.Database | null = null;

export function getDbPath(): string {
  return DB_PATH;
}

export function initDb(): Database.Database {
  if (db) return db;
  
  // Ensure cache directory exists
  if (!existsSync(CACHE_DIR)) {
    mkdirSync(CACHE_DIR, { recursive: true });
  }
  
  db = new Database(DB_PATH);
  
  // Create main detections table with all enhanced fields
  db.exec(`
    CREATE TABLE IF NOT EXISTS detections (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      query TEXT,
      source_type TEXT NOT NULL,
      mitre_ids TEXT,
      logsource_category TEXT,
      logsource_product TEXT,
      logsource_service TEXT,
      severity TEXT,
      status TEXT,
      author TEXT,
      date_created TEXT,
      date_modified TEXT,
      refs TEXT,
      falsepositives TEXT,
      tags TEXT,
      file_path TEXT,
      raw_yaml TEXT,
      cves TEXT,
      analytic_stories TEXT,
      data_sources TEXT,
      detection_type TEXT,
      asset_type TEXT,
      security_domain TEXT,
      process_names TEXT,
      file_paths TEXT,
      registry_paths TEXT,
      mitre_tactics TEXT,
      platforms TEXT,
      kql_category TEXT,
      kql_tags TEXT,
      kql_keywords TEXT
    )
  `);
  
  // Create FTS5 virtual table for full-text search with all searchable fields
  db.exec(`
    CREATE VIRTUAL TABLE IF NOT EXISTS detections_fts USING fts5(
      id,
      name,
      description,
      query,
      mitre_ids,
      tags,
      cves,
      analytic_stories,
      data_sources,
      process_names,
      file_paths,
      registry_paths,
      mitre_tactics,
      platforms,
      kql_category,
      kql_tags,
      kql_keywords,
      content='detections',
      content_rowid='rowid'
    )
  `);
  
  // Create triggers to keep FTS in sync
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS detections_ai AFTER INSERT ON detections BEGIN
      INSERT INTO detections_fts(rowid, id, name, description, query, mitre_ids, tags, cves, analytic_stories, data_sources, process_names, file_paths, registry_paths, mitre_tactics, platforms, kql_category, kql_tags, kql_keywords)
      VALUES (NEW.rowid, NEW.id, NEW.name, NEW.description, NEW.query, NEW.mitre_ids, NEW.tags, NEW.cves, NEW.analytic_stories, NEW.data_sources, NEW.process_names, NEW.file_paths, NEW.registry_paths, NEW.mitre_tactics, NEW.platforms, NEW.kql_category, NEW.kql_tags, NEW.kql_keywords);
    END
  `);
  
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS detections_ad AFTER DELETE ON detections BEGIN
      INSERT INTO detections_fts(detections_fts, rowid, id, name, description, query, mitre_ids, tags, cves, analytic_stories, data_sources, process_names, file_paths, registry_paths, mitre_tactics, platforms, kql_category, kql_tags, kql_keywords)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.description, OLD.query, OLD.mitre_ids, OLD.tags, OLD.cves, OLD.analytic_stories, OLD.data_sources, OLD.process_names, OLD.file_paths, OLD.registry_paths, OLD.mitre_tactics, OLD.platforms, OLD.kql_category, OLD.kql_tags, OLD.kql_keywords);
    END
  `);
  
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS detections_au AFTER UPDATE ON detections BEGIN
      INSERT INTO detections_fts(detections_fts, rowid, id, name, description, query, mitre_ids, tags, cves, analytic_stories, data_sources, process_names, file_paths, registry_paths, mitre_tactics, platforms, kql_category, kql_tags, kql_keywords)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.description, OLD.query, OLD.mitre_ids, OLD.tags, OLD.cves, OLD.analytic_stories, OLD.data_sources, OLD.process_names, OLD.file_paths, OLD.registry_paths, OLD.mitre_tactics, OLD.platforms, OLD.kql_category, OLD.kql_tags, OLD.kql_keywords);
      INSERT INTO detections_fts(rowid, id, name, description, query, mitre_ids, tags, cves, analytic_stories, data_sources, process_names, file_paths, registry_paths, mitre_tactics, platforms, kql_category, kql_tags, kql_keywords)
      VALUES (NEW.rowid, NEW.id, NEW.name, NEW.description, NEW.query, NEW.mitre_ids, NEW.tags, NEW.cves, NEW.analytic_stories, NEW.data_sources, NEW.process_names, NEW.file_paths, NEW.registry_paths, NEW.mitre_tactics, NEW.platforms, NEW.kql_category, NEW.kql_tags, NEW.kql_keywords);
    END
  `);
  
  // Create indexes for common queries
  db.exec(`CREATE INDEX IF NOT EXISTS idx_source_type ON detections(source_type)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_severity ON detections(severity)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logsource_product ON detections(logsource_product)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logsource_category ON detections(logsource_category)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_detection_type ON detections(detection_type)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_asset_type ON detections(asset_type)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_security_domain ON detections(security_domain)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_kql_category ON detections(kql_category)`);
  
  // Create stories table (optional - provides rich context for analytic stories)
  db.exec(`
    CREATE TABLE IF NOT EXISTS stories (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      narrative TEXT,
      author TEXT,
      date TEXT,
      version INTEGER,
      status TEXT,
      refs TEXT,
      category TEXT,
      usecase TEXT,
      detection_names TEXT
    )
  `);
  
  // Create FTS5 for stories (narrative is key for semantic search!)
  db.exec(`
    CREATE VIRTUAL TABLE IF NOT EXISTS stories_fts USING fts5(
      id,
      name,
      description,
      narrative,
      category,
      usecase,
      content='stories',
      content_rowid='rowid'
    )
  `);
  
  // Triggers for stories FTS
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS stories_ai AFTER INSERT ON stories BEGIN
      INSERT INTO stories_fts(rowid, id, name, description, narrative, category, usecase)
      VALUES (NEW.rowid, NEW.id, NEW.name, NEW.description, NEW.narrative, NEW.category, NEW.usecase);
    END
  `);
  
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS stories_ad AFTER DELETE ON stories BEGIN
      INSERT INTO stories_fts(stories_fts, rowid, id, name, description, narrative, category, usecase)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.description, OLD.narrative, OLD.category, OLD.usecase);
    END
  `);
  
  db.exec(`CREATE INDEX IF NOT EXISTS idx_story_category ON stories(category)`);
  
  return db;
}

export function clearDb(): void {
  const database = initDb();
  database.exec('DELETE FROM detections');
}

// Safely delete a file with retry logic for Windows (EBUSY/EPERM)
function safeUnlink(filePath: string, maxRetries = 5, delayMs = 100): void {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      if (existsSync(filePath)) {
        unlinkSync(filePath);
      }
      return;
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException).code;
      if ((code === 'EBUSY' || code === 'EPERM' || code === 'EACCES') && attempt < maxRetries - 1) {
        const end = Date.now() + delayMs * (attempt + 1);
        while (Date.now() < end) { /* wait */ }
        continue;
      }
      throw err;
    }
  }
}

// Force recreation of the database (needed when schema changes)
// Handles Windows file locking with retry logic
export function recreateDb(): void {
  if (db) {
    db.close();
    db = null;
  }

  // Small delay on Windows to let file handles fully release
  if (platform() === 'win32') {
    const end = Date.now() + 100;
    while (Date.now() < end) { /* wait */ }
  }

  // Delete main db and SQLite journal/WAL files
  safeUnlink(DB_PATH);
  safeUnlink(DB_PATH + '-wal');
  safeUnlink(DB_PATH + '-shm');
  safeUnlink(DB_PATH + '-journal');
}

export function insertDetection(detection: Detection): void {
  const database = initDb();
  
  const stmt = database.prepare(`
    INSERT OR REPLACE INTO detections 
    (id, name, description, query, source_type, mitre_ids, logsource_category, 
     logsource_product, logsource_service, severity, status, author, 
     date_created, date_modified, refs, falsepositives, tags, file_path, raw_yaml,
     cves, analytic_stories, data_sources, detection_type, asset_type, security_domain,
     process_names, file_paths, registry_paths, mitre_tactics, platforms, kql_category, kql_tags, kql_keywords)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  
  stmt.run(
    detection.id,
    detection.name,
    detection.description,
    detection.query,
    detection.source_type,
    JSON.stringify(detection.mitre_ids),
    detection.logsource_category,
    detection.logsource_product,
    detection.logsource_service,
    detection.severity,
    detection.status,
    detection.author,
    detection.date_created,
    detection.date_modified,
    JSON.stringify(detection.references),
    JSON.stringify(detection.falsepositives),
    JSON.stringify(detection.tags),
    detection.file_path,
    detection.raw_yaml,
    JSON.stringify(detection.cves),
    JSON.stringify(detection.analytic_stories),
    JSON.stringify(detection.data_sources),
    detection.detection_type,
    detection.asset_type,
    detection.security_domain,
    JSON.stringify(detection.process_names),
    JSON.stringify(detection.file_paths),
    JSON.stringify(detection.registry_paths),
    JSON.stringify(detection.mitre_tactics),
    JSON.stringify(detection.platforms),
    detection.kql_category,
    JSON.stringify(detection.kql_tags),
    JSON.stringify(detection.kql_keywords)
  );
}

function rowToDetection(row: Record<string, unknown>): Detection {
  return {
    id: row.id as string,
    name: row.name as string,
    description: row.description as string || '',
    query: row.query as string || '',
    source_type: row.source_type as 'sigma' | 'splunk_escu' | 'elastic' | 'kql',
    mitre_ids: JSON.parse(row.mitre_ids as string || '[]'),
    logsource_category: row.logsource_category as string | null,
    logsource_product: row.logsource_product as string | null,
    logsource_service: row.logsource_service as string | null,
    severity: row.severity as string | null,
    status: row.status as string | null,
    author: row.author as string | null,
    date_created: row.date_created as string | null,
    date_modified: row.date_modified as string | null,
    references: JSON.parse(row.refs as string || '[]'),
    falsepositives: JSON.parse(row.falsepositives as string || '[]'),
    tags: JSON.parse(row.tags as string || '[]'),
    file_path: row.file_path as string,
    raw_yaml: row.raw_yaml as string,
    cves: JSON.parse(row.cves as string || '[]'),
    analytic_stories: JSON.parse(row.analytic_stories as string || '[]'),
    data_sources: JSON.parse(row.data_sources as string || '[]'),
    detection_type: row.detection_type as string | null,
    asset_type: row.asset_type as string | null,
    security_domain: row.security_domain as string | null,
    process_names: JSON.parse(row.process_names as string || '[]'),
    file_paths: JSON.parse(row.file_paths as string || '[]'),
    registry_paths: JSON.parse(row.registry_paths as string || '[]'),
    mitre_tactics: JSON.parse(row.mitre_tactics as string || '[]'),
    platforms: JSON.parse(row.platforms as string || '[]'),
    kql_category: row.kql_category as string | null,
    kql_tags: JSON.parse(row.kql_tags as string || '[]'),
    kql_keywords: JSON.parse(row.kql_keywords as string || '[]'),
  };
}

export function searchDetections(query: string, limit: number = 50): Detection[] {
  const database = initDb();
  
  // Use FTS5 for search
  const stmt = database.prepare(`
    SELECT d.* FROM detections d
    JOIN detections_fts fts ON d.rowid = fts.rowid
    WHERE detections_fts MATCH ?
    ORDER BY rank
    LIMIT ?
  `);
  
  const rows = stmt.all(query, limit) as Record<string, unknown>[];
  return rows.map(rowToDetection);
}

export function getDetectionById(id: string): Detection | null {
  const database = initDb();
  
  const stmt = database.prepare('SELECT * FROM detections WHERE id = ?');
  const row = stmt.get(id) as Record<string, unknown> | undefined;
  
  return row ? rowToDetection(row) : null;
}

export function listDetections(limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare('SELECT * FROM detections ORDER BY name LIMIT ? OFFSET ?');
  const rows = stmt.all(limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listBySource(sourceType: 'sigma' | 'splunk_escu' | 'elastic' | 'kql', limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare('SELECT * FROM detections WHERE source_type = ? ORDER BY name LIMIT ? OFFSET ?');
  const rows = stmt.all(sourceType, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByMitre(techniqueId: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  // Search in JSON array
  const stmt = database.prepare(`
    SELECT * FROM detections 
    WHERE mitre_ids LIKE ? 
    ORDER BY name 
    LIMIT ? OFFSET ?
  `);
  const rows = stmt.all(`%"${techniqueId}"%`, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByLogsource(
  category?: string,
  product?: string,
  service?: string,
  limit: number = 100,
  offset: number = 0
): Detection[] {
  const database = initDb();
  
  let sql = 'SELECT * FROM detections WHERE 1=1';
  const params: (string | number)[] = [];
  
  if (category) {
    sql += ' AND logsource_category = ?';
    params.push(category);
  }
  if (product) {
    sql += ' AND logsource_product = ?';
    params.push(product);
  }
  if (service) {
    sql += ' AND logsource_service = ?';
    params.push(service);
  }
  
  sql += ' ORDER BY name LIMIT ? OFFSET ?';
  params.push(limit, offset);
  
  const stmt = database.prepare(sql);
  const rows = stmt.all(...params) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listBySeverity(level: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare('SELECT * FROM detections WHERE severity = ? ORDER BY name LIMIT ? OFFSET ?');
  const rows = stmt.all(level, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

// New query methods for enhanced fields

export function listByCve(cveId: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare(`
    SELECT * FROM detections 
    WHERE cves LIKE ? 
    ORDER BY name 
    LIMIT ? OFFSET ?
  `);
  const rows = stmt.all(`%"${cveId}"%`, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByAnalyticStory(story: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare(`
    SELECT * FROM detections 
    WHERE analytic_stories LIKE ? 
    ORDER BY name 
    LIMIT ? OFFSET ?
  `);
  const rows = stmt.all(`%${story}%`, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByProcessName(processName: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare(`
    SELECT * FROM detections 
    WHERE process_names LIKE ? 
    ORDER BY name 
    LIMIT ? OFFSET ?
  `);
  const rows = stmt.all(`%${processName}%`, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByDetectionType(detectionType: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare('SELECT * FROM detections WHERE detection_type = ? ORDER BY name LIMIT ? OFFSET ?');
  const rows = stmt.all(detectionType, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByDataSource(dataSource: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare(`
    SELECT * FROM detections 
    WHERE data_sources LIKE ? 
    ORDER BY name 
    LIMIT ? OFFSET ?
  `);
  const rows = stmt.all(`%${dataSource}%`, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByKqlCategory(category: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare(`
    SELECT * FROM detections
    WHERE source_type = 'kql' AND kql_category = ?
    ORDER BY name
    LIMIT ? OFFSET ?
  `);
  const rows = stmt.all(category, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByKqlTag(tag: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare(`
    SELECT * FROM detections
    WHERE source_type = 'kql' AND kql_tags LIKE ?
    ORDER BY name
    LIMIT ? OFFSET ?
  `);
  const rows = stmt.all(`%"${tag}"%`, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByKqlDatasource(dataSource: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare(`
    SELECT * FROM detections
    WHERE source_type = 'kql' AND data_sources LIKE ?
    ORDER BY name
    LIMIT ? OFFSET ?
  `);
  const rows = stmt.all(`%${dataSource}%`, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByMitreTactic(tactic: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare(`
    SELECT * FROM detections 
    WHERE mitre_tactics LIKE ? 
    ORDER BY name 
    LIMIT ? OFFSET ?
  `);
  const rows = stmt.all(`%"${tactic}"%`, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function getStats(): IndexStats {
  const database = initDb();
  
  const total = (database.prepare('SELECT COUNT(*) as count FROM detections').get() as { count: number }).count;
  const sigma = (database.prepare("SELECT COUNT(*) as count FROM detections WHERE source_type = 'sigma'").get() as { count: number }).count;
  const splunk = (database.prepare("SELECT COUNT(*) as count FROM detections WHERE source_type = 'splunk_escu'").get() as { count: number }).count;
  const elastic = (database.prepare("SELECT COUNT(*) as count FROM detections WHERE source_type = 'elastic'").get() as { count: number }).count;
  const kql = (database.prepare("SELECT COUNT(*) as count FROM detections WHERE source_type = 'kql'").get() as { count: number }).count;
  
  // Count by severity
  const severityRows = database.prepare(`
    SELECT severity, COUNT(*) as count FROM detections 
    WHERE severity IS NOT NULL 
    GROUP BY severity
  `).all() as { severity: string; count: number }[];
  
  const by_severity: Record<string, number> = {};
  for (const row of severityRows) {
    by_severity[row.severity] = row.count;
  }
  
  // Count by logsource product
  const productRows = database.prepare(`
    SELECT logsource_product, COUNT(*) as count FROM detections 
    WHERE logsource_product IS NOT NULL 
    GROUP BY logsource_product
    ORDER BY count DESC
    LIMIT 20
  `).all() as { logsource_product: string; count: number }[];
  
  const by_logsource_product: Record<string, number> = {};
  for (const row of productRows) {
    by_logsource_product[row.logsource_product] = row.count;
  }
  
  // Count detections with MITRE mappings
  const mitre_coverage = (database.prepare(`
    SELECT COUNT(*) as count FROM detections 
    WHERE mitre_ids != '[]' AND mitre_ids IS NOT NULL
  `).get() as { count: number }).count;
  
  // Count detections with CVE mappings
  const cve_coverage = (database.prepare(`
    SELECT COUNT(*) as count FROM detections 
    WHERE cves != '[]' AND cves IS NOT NULL
  `).get() as { count: number }).count;
  
  // Count by MITRE tactic
  const tacticRows = database.prepare(`
    SELECT mitre_tactics FROM detections 
    WHERE mitre_tactics != '[]' AND mitre_tactics IS NOT NULL
  `).all() as { mitre_tactics: string }[];
  
  const by_mitre_tactic: Record<string, number> = {};
  for (const row of tacticRows) {
    const tactics = JSON.parse(row.mitre_tactics) as string[];
    for (const tactic of tactics) {
      by_mitre_tactic[tactic] = (by_mitre_tactic[tactic] || 0) + 1;
    }
  }
  
  // Count by detection type
  const typeRows = database.prepare(`
    SELECT detection_type, COUNT(*) as count FROM detections 
    WHERE detection_type IS NOT NULL 
    GROUP BY detection_type
  `).all() as { detection_type: string; count: number }[];
  
  const by_detection_type: Record<string, number> = {};
  for (const row of typeRows) {
    by_detection_type[row.detection_type] = row.count;
  }
  
  // Count stories (optional table)
  let stories_count = 0;
  const by_story_category: Record<string, number> = {};
  try {
    stories_count = (database.prepare('SELECT COUNT(*) as count FROM stories').get() as { count: number }).count;
    
    const categoryRows = database.prepare(`
      SELECT category, COUNT(*) as count FROM stories 
      WHERE category IS NOT NULL 
      GROUP BY category
    `).all() as { category: string; count: number }[];
    
    for (const row of categoryRows) {
      by_story_category[row.category] = row.count;
    }
  } catch {
    // Stories table might not exist or be empty - that's fine
  }
  
  return {
    total,
    sigma,
    splunk_escu: splunk,
    elastic,
    kql,
    by_severity,
    by_logsource_product,
    mitre_coverage,
    cve_coverage,
    by_mitre_tactic,
    by_detection_type,
    stories_count,
    by_story_category,
    by_elastic_index: {},  // Could be populated if needed
  };
}

export function getRawYaml(id: string): string | null {
  const database = initDb();
  
  const stmt = database.prepare('SELECT raw_yaml FROM detections WHERE id = ?');
  const row = stmt.get(id) as { raw_yaml: string } | undefined;
  
  return row?.raw_yaml || null;
}

export function dbExists(): boolean {
  return existsSync(DB_PATH);
}

export function getDetectionCount(): number {
  if (!dbExists()) return 0;
  const database = initDb();
  return (database.prepare('SELECT COUNT(*) as count FROM detections').get() as { count: number }).count;
}

// Story-related functions

export function insertStory(story: AnalyticStory): void {
  const database = initDb();
  
  const stmt = database.prepare(`
    INSERT OR REPLACE INTO stories 
    (id, name, description, narrative, author, date, version, status, refs, category, usecase, detection_names)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  
  stmt.run(
    story.id,
    story.name,
    story.description,
    story.narrative,
    story.author,
    story.date,
    story.version,
    story.status,
    JSON.stringify(story.references),
    story.category,
    story.usecase,
    JSON.stringify(story.detection_names)
  );
}

function rowToStory(row: Record<string, unknown>): AnalyticStory {
  return {
    id: row.id as string,
    name: row.name as string,
    description: row.description as string || '',
    narrative: row.narrative as string || '',
    author: row.author as string | null,
    date: row.date as string | null,
    version: row.version as number | null,
    status: row.status as string | null,
    references: JSON.parse(row.refs as string || '[]'),
    category: row.category as string | null,
    usecase: row.usecase as string | null,
    detection_names: JSON.parse(row.detection_names as string || '[]'),
  };
}

export function getStoryByName(name: string): AnalyticStory | null {
  const database = initDb();
  
  const stmt = database.prepare('SELECT * FROM stories WHERE name = ?');
  const row = stmt.get(name) as Record<string, unknown> | undefined;
  
  return row ? rowToStory(row) : null;
}

export function getStoryById(id: string): AnalyticStory | null {
  const database = initDb();
  
  const stmt = database.prepare('SELECT * FROM stories WHERE id = ?');
  const row = stmt.get(id) as Record<string, unknown> | undefined;
  
  return row ? rowToStory(row) : null;
}

export function searchStories(query: string, limit: number = 20): AnalyticStory[] {
  const database = initDb();
  
  try {
    const stmt = database.prepare(`
      SELECT s.* FROM stories s
      JOIN stories_fts fts ON s.rowid = fts.rowid
      WHERE stories_fts MATCH ?
      ORDER BY rank
      LIMIT ?
    `);
    
    const rows = stmt.all(query, limit) as Record<string, unknown>[];
    return rows.map(rowToStory);
  } catch {
    // If no stories indexed, return empty
    return [];
  }
}

export function listStories(limit: number = 100, offset: number = 0): AnalyticStory[] {
  const database = initDb();
  
  try {
    const stmt = database.prepare('SELECT * FROM stories ORDER BY name LIMIT ? OFFSET ?');
    const rows = stmt.all(limit, offset) as Record<string, unknown>[];
    return rows.map(rowToStory);
  } catch {
    return [];
  }
}

export function listStoriesByCategory(category: string, limit: number = 100, offset: number = 0): AnalyticStory[] {
  const database = initDb();
  
  try {
    const stmt = database.prepare('SELECT * FROM stories WHERE category = ? ORDER BY name LIMIT ? OFFSET ?');
    const rows = stmt.all(category, limit, offset) as Record<string, unknown>[];
    return rows.map(rowToStory);
  } catch {
    return [];
  }
}

export function getStoryCount(): number {
  const database = initDb();
  try {
    return (database.prepare('SELECT COUNT(*) as count FROM stories').get() as { count: number }).count;
  } catch {
    return 0;
  }
}

// =============================================================================
// COMPLETION HELPER FUNCTIONS - For autocomplete suggestions
// =============================================================================

export function getDistinctTechniqueIds(prefix: string, limit: number = 10): string[] {
  const database = initDb();
  
  // Get all technique IDs and filter by prefix
  const rows = database.prepare(`
    SELECT DISTINCT mitre_ids FROM detections 
    WHERE mitre_ids != '[]' AND mitre_ids IS NOT NULL
  `).all() as { mitre_ids: string }[];
  
  const techniqueSet = new Set<string>();
  for (const row of rows) {
    const ids = JSON.parse(row.mitre_ids) as string[];
    for (const id of ids) {
      if (id.toUpperCase().startsWith(prefix.toUpperCase())) {
        techniqueSet.add(id);
      }
    }
  }
  
  return Array.from(techniqueSet).sort().slice(0, limit);
}

export function getDistinctCves(prefix: string, limit: number = 10): string[] {
  const database = initDb();
  
  // Get all CVEs and filter by prefix
  const rows = database.prepare(`
    SELECT DISTINCT cves FROM detections 
    WHERE cves != '[]' AND cves IS NOT NULL
  `).all() as { cves: string }[];
  
  const cveSet = new Set<string>();
  for (const row of rows) {
    const cvelist = JSON.parse(row.cves) as string[];
    for (const cve of cvelist) {
      if (cve.toUpperCase().startsWith(prefix.toUpperCase())) {
        cveSet.add(cve);
      }
    }
  }
  
  return Array.from(cveSet).sort().slice(0, limit);
}

export function getDistinctProcessNames(prefix: string, limit: number = 10): string[] {
  const database = initDb();
  
  // Get all process names and filter by prefix
  const rows = database.prepare(`
    SELECT DISTINCT process_names FROM detections 
    WHERE process_names != '[]' AND process_names IS NOT NULL
  `).all() as { process_names: string }[];
  
  const processSet = new Set<string>();
  for (const row of rows) {
    const procs = JSON.parse(row.process_names) as string[];
    for (const proc of procs) {
      if (proc.toLowerCase().startsWith(prefix.toLowerCase())) {
        processSet.add(proc);
      }
    }
  }
  
  return Array.from(processSet).sort().slice(0, limit);
}

// =============================================================================
// INPUT VALIDATION - With did-you-mean suggestions
// =============================================================================

export interface ValidationResult {
  valid: boolean;
  error?: string;
  suggestion?: string;
  similar?: string[];
}

export function validateTechniqueId(id: string): ValidationResult {
  // Check format: T followed by 4 digits, optionally .3 more digits
  if (!id.match(/^T\d{4}(\.\d{3})?$/)) {
    return { 
      valid: false, 
      error: 'Invalid technique ID format', 
      suggestion: 'Use format T####.### (e.g., T1059.001)' 
    };
  }
  
  const database = initDb();
  
  // Check if this exact technique has detections
  const exact = database.prepare(`
    SELECT 1 FROM detections WHERE mitre_ids LIKE ? LIMIT 1
  `).get(`%"${id}"%`);
  
  if (exact) {
    return { valid: true };
  }
  
  // Find similar techniques that we DO have
  const similar = getDistinctTechniqueIds(id.substring(0, 5), 5);
  
  // Also check if we have parent or sub-techniques
  const baseId = id.split('.')[0];
  const parentMatch = database.prepare(`
    SELECT 1 FROM detections WHERE mitre_ids LIKE ? LIMIT 1
  `).get(`%"${baseId}"%`);
  
  if (parentMatch) {
    return {
      valid: true,
      suggestion: `No exact match for ${id}, but found coverage for ${baseId}`,
      similar: similar.length > 0 ? similar : undefined,
    };
  }
  
  if (similar.length > 0) {
    return {
      valid: false,
      error: `No detections found for ${id}`,
      suggestion: 'Try one of the similar techniques',
      similar,
    };
  }
  
  return {
    valid: true,
    suggestion: `No existing detections for ${id} - this is a gap`,
  };
}

// =============================================================================
// Lightweight technique ID extraction - returns ONLY unique technique IDs
// =============================================================================
export interface TechniqueIdFilters {
  source_type?: 'sigma' | 'splunk_escu' | 'elastic';
  tactic?: string;
  severity?: string;
}

export function getTechniqueIds(filters: TechniqueIdFilters = {}): string[] {
  const database = initDb();
  
  let sql = "SELECT DISTINCT mitre_ids FROM detections WHERE mitre_ids != '[]' AND mitre_ids IS NOT NULL";
  const params: string[] = [];
  
  if (filters.source_type) {
    sql += ' AND source_type = ?';
    params.push(filters.source_type);
  }
  if (filters.tactic) {
    sql += ' AND mitre_tactics LIKE ?';
    params.push(`%"${filters.tactic}"%`);
  }
  if (filters.severity) {
    sql += ' AND severity = ?';
    params.push(filters.severity);
  }
  
  const stmt = database.prepare(sql);
  const rows = stmt.all(...params) as { mitre_ids: string }[];
  
  // Extract and dedupe all technique IDs
  const techniqueSet = new Set<string>();
  for (const row of rows) {
    const ids = JSON.parse(row.mitre_ids) as string[];
    for (const id of ids) {
      techniqueSet.add(id);
    }
  }
  
  return Array.from(techniqueSet).sort();
}

// Threat profiles for gap analysis
const THREAT_PROFILES: Record<string, string[]> = {
  ransomware: [
    'T1486', 'T1490', 'T1027', 'T1547.001', 'T1059.001', 'T1059.003',
    'T1562.001', 'T1112', 'T1070.004', 'T1048', 'T1567', 'T1078',
    'T1566.001', 'T1204.002', 'T1055', 'T1543.003'
  ],
  apt: [
    'T1003.001', 'T1003.002', 'T1003.003', 'T1021.001', 'T1021.002',
    'T1053.005', 'T1071.001', 'T1071.004', 'T1105', 'T1027', 'T1055',
    'T1078', 'T1136', 'T1098', 'T1087', 'T1069', 'T1018', 'T1082'
  ],
  'initial-access': [
    'T1566.001', 'T1566.002', 'T1190', 'T1078', 'T1133', 'T1200',
    'T1091', 'T1195.002', 'T1199', 'T1189'
  ],
  persistence: [
    'T1547.001', 'T1547.004', 'T1543.003', 'T1053.005', 'T1136.001',
    'T1098', 'T1505.003', 'T1546.001', 'T1574.001', 'T1574.002'
  ],
  'credential-access': [
    'T1003.001', 'T1003.002', 'T1003.003', 'T1003.004', 'T1003.006',
    'T1555', 'T1552.001', 'T1110', 'T1558.003', 'T1539', 'T1606.001'
  ],
  'defense-evasion': [
    'T1027', 'T1070.001', 'T1070.004', 'T1055', 'T1036', 'T1562.001',
    'T1218', 'T1112', 'T1140', 'T1202', 'T1564.001'
  ]
};

// Coverage analysis result
export interface CoverageReport {
  summary: {
    total_techniques: number;
    total_detections: number;
    coverage_by_tactic: Record<string, { covered: number; total: number; percent: number }>;
  };
  top_covered: Array<{ technique: string; detection_count: number }>;
  weak_coverage: Array<{ technique: string; detection_count: number }>;
}

// Analyze coverage efficiently
export function analyzeCoverage(sourceType?: 'sigma' | 'splunk_escu' | 'elastic'): CoverageReport {
  const database = initDb();
  
  // Get all technique IDs covered
  let countSql = 'SELECT COUNT(DISTINCT id) as count FROM detections';
  if (sourceType) countSql += ' WHERE source_type = ?';
  const totalDetections = sourceType 
    ? (database.prepare(countSql).get(sourceType) as { count: number }).count
    : (database.prepare(countSql).get() as { count: number }).count;
  
  // Get techniques with counts
  let sql = "SELECT mitre_ids, mitre_tactics FROM detections WHERE mitre_ids != '[]'";
  if (sourceType) sql += ' AND source_type = ?';
  
  const rows = sourceType
    ? database.prepare(sql).all(sourceType) as { mitre_ids: string; mitre_tactics: string }[]
    : database.prepare(sql).all() as { mitre_ids: string; mitre_tactics: string }[];
  
  // Count techniques and tactics
  const techCounts: Record<string, number> = {};
  const tacticCounts: Record<string, Set<string>> = {};
  
  const allTactics = [
    'reconnaissance', 'resource-development', 'initial-access', 'execution',
    'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
    'discovery', 'lateral-movement', 'collection', 'command-and-control',
    'exfiltration', 'impact'
  ];
  
  for (const t of allTactics) {
    tacticCounts[t] = new Set();
  }
  
  for (const row of rows) {
    const ids = JSON.parse(row.mitre_ids) as string[];
    const tactics = JSON.parse(row.mitre_tactics || '[]') as string[];
    
    for (const id of ids) {
      techCounts[id] = (techCounts[id] || 0) + 1;
      for (const tactic of tactics) {
        if (tacticCounts[tactic]) {
          tacticCounts[tactic].add(id);
        }
      }
    }
  }
  
  // Build coverage by tactic (approx totals from ATT&CK)
  const tacticTotals: Record<string, number> = {
    'reconnaissance': 10, 'resource-development': 8, 'initial-access': 10,
    'execution': 14, 'persistence': 20, 'privilege-escalation': 14,
    'defense-evasion': 43, 'credential-access': 17, 'discovery': 31,
    'lateral-movement': 9, 'collection': 17, 'command-and-control': 18,
    'exfiltration': 9, 'impact': 14
  };
  
  const coverageByTactic: Record<string, { covered: number; total: number; percent: number }> = {};
  for (const tactic of allTactics) {
    const covered = tacticCounts[tactic].size;
    const total = tacticTotals[tactic];
    coverageByTactic[tactic] = {
      covered,
      total,
      percent: Math.round((covered / total) * 100)
    };
  }
  
  // Top covered and weak coverage
  const sorted = Object.entries(techCounts).sort((a, b) => b[1] - a[1]);
  const topCovered = sorted.slice(0, 10).map(([t, c]) => ({ technique: t, detection_count: c }));
  const weakCoverage = sorted.filter(([_, c]) => c === 1).slice(0, 10).map(([t, c]) => ({ technique: t, detection_count: c }));
  
  return {
    summary: {
      total_techniques: Object.keys(techCounts).length,
      total_detections: totalDetections,
      coverage_by_tactic: coverageByTactic,
    },
    top_covered: topCovered,
    weak_coverage: weakCoverage,
  };
}

// Gap analysis result
export interface GapAnalysis {
  threat_profile: string;
  total_gaps: number;
  critical_gaps: Array<{ technique: string; priority: string; reason: string }>;
  covered: string[];
  recommendations: string[];
}

// Identify gaps based on threat profile
export function identifyGaps(
  threatProfile: string,
  sourceType?: 'sigma' | 'splunk_escu' | 'elastic'
): GapAnalysis {
  const targetTechniques = THREAT_PROFILES[threatProfile.toLowerCase()] || THREAT_PROFILES['apt'];
  
  // Get what we have coverage for
  const coveredTechs = new Set(getTechniqueIds({ source_type: sourceType }));
  
  // Find gaps
  const gaps: Array<{ technique: string; priority: string; reason: string }> = [];
  const covered: string[] = [];
  
  for (const tech of targetTechniques) {
    if (coveredTechs.has(tech)) {
      covered.push(tech);
    } else {
      // Check if we have sub-technique coverage
      const hasSubCoverage = Array.from(coveredTechs).some(t => t.startsWith(tech + '.'));
      const hasParentCoverage = coveredTechs.has(tech.split('.')[0]);
      
      let priority = 'P0';
      let reason = 'No detection coverage';
      
      if (hasSubCoverage) {
        priority = 'P2';
        reason = 'Has sub-technique coverage but not parent';
      } else if (hasParentCoverage) {
        priority = 'P1';
        reason = 'Has parent technique coverage, may catch this';
      }
      
      gaps.push({ technique: tech, priority, reason });
    }
  }
  
  // Sort by priority
  gaps.sort((a, b) => a.priority.localeCompare(b.priority));
  
  // Generate recommendations
  const recommendations = [
    `${covered.length}/${targetTechniques.length} techniques covered for ${threatProfile}`,
    `${gaps.filter(g => g.priority === 'P0').length} critical gaps (P0) need immediate attention`,
  ];
  
  if (gaps.length > 0) {
    recommendations.push(`Top priority: ${gaps[0].technique} - ${gaps[0].reason}`);
  }
  
  return {
    threat_profile: threatProfile,
    total_gaps: gaps.length,
    critical_gaps: gaps.slice(0, 15),
    covered,
    recommendations,
  };
}

// Detection suggestion
export interface DetectionSuggestion {
  technique_id: string;
  existing_detections: Array<{ id: string; name: string; source: string }>;
  data_sources_needed: string[];
  detection_ideas: string[];
}

// Suggest detections for a technique
export function suggestDetections(
  techniqueId: string,
  sourceType?: 'sigma' | 'splunk_escu' | 'elastic'
): DetectionSuggestion {
  const database = initDb();
  
  // Find existing detections for this technique
  let sql = "SELECT id, name, source_type, data_sources FROM detections WHERE mitre_ids LIKE ?";
  const params: string[] = [`%"${techniqueId}"%`];
  
  if (sourceType) {
    sql += ' AND source_type = ?';
    params.push(sourceType);
  }
  sql += ' LIMIT 10';
  
  const rows = database.prepare(sql).all(...params) as { 
    id: string; name: string; source_type: string; data_sources: string 
  }[];
  
  const existingDetections = rows.map(r => ({
    id: r.id,
    name: r.name,
    source: r.source_type
  }));
  
  // Collect data sources from existing detections
  const dataSources = new Set<string>();
  for (const row of rows) {
    const ds = JSON.parse(row.data_sources || '[]') as string[];
    ds.forEach(d => dataSources.add(d));
  }
  
  // Generate detection ideas based on technique pattern
  const ideas: string[] = [];
  const techBase = techniqueId.split('.')[0];
  
  const ideaMap: Record<string, string[]> = {
    'T1059': ['Monitor process creation for script interpreters', 'Track command-line arguments for encoded commands', 'Alert on unusual parent-child process relationships'],
    'T1003': ['Monitor LSASS access patterns', 'Track credential dumping tool signatures', 'Alert on suspicious memory access'],
    'T1547': ['Monitor registry run key modifications', 'Track startup folder changes', 'Alert on new autostart entries'],
    'T1055': ['Monitor for CreateRemoteThread', 'Track process injection patterns', 'Alert on memory allocation in remote processes'],
    'T1027': ['Detect encoded/obfuscated scripts', 'Monitor for packed executables', 'Track file entropy anomalies'],
    'T1071': ['Monitor for beaconing patterns', 'Track DNS query anomalies', 'Alert on unusual HTTP/S traffic'],
    'T1486': ['Monitor for mass file modifications', 'Track encryption-related API calls', 'Alert on ransom note creation'],
    'T1490': ['Monitor vssadmin/wbadmin usage', 'Track backup deletion attempts', 'Alert on bcdedit modifications'],
  };
  
  ideas.push(...(ideaMap[techBase] || ['Review MITRE ATT&CK for detection guidance', 'Check data source requirements', 'Consider behavioral vs signature detection']));
  
  return {
    technique_id: techniqueId,
    existing_detections: existingDetections,
    data_sources_needed: Array.from(dataSources).slice(0, 10),
    detection_ideas: ideas,
  };
}

// Generate Navigator layer directly from detections
export interface NavigatorLayerOptions {
  name: string;
  description?: string;
  source_type?: 'sigma' | 'splunk_escu' | 'elastic';
  tactic?: string;
  severity?: string;
}

export function generateNavigatorLayer(options: NavigatorLayerOptions): object {
  const techniqueIds = getTechniqueIds({
    source_type: options.source_type,
    tactic: options.tactic,
    severity: options.severity,
  });
  
  // Build techniques array with scores based on detection count
  const database = initDb();
  const techniques = [];
  
  // Color gradient: red (no coverage) -> yellow (low) -> green (good)
  function getColorForScore(score: number): string {
    if (score >= 80) return '#1a8c1a';  // Dark green - excellent
    if (score >= 60) return '#8ec843';  // Light green - good
    if (score >= 40) return '#ffe766';  // Yellow - moderate
    if (score >= 20) return '#ff9933';  // Orange - low
    return '#ff6666';                    // Red - minimal
  }
  
  for (const techId of techniqueIds) {
    let countSql = 'SELECT COUNT(*) as count FROM detections WHERE mitre_ids LIKE ?';
    const countParams: string[] = [`%"${techId}"%`];
    
    if (options.source_type) {
      countSql += ' AND source_type = ?';
      countParams.push(options.source_type);
    }
    if (options.tactic) {
      countSql += ' AND mitre_tactics LIKE ?';
      countParams.push(`%"${options.tactic}"%`);
    }
    
    const count = (database.prepare(countSql).get(...countParams) as { count: number }).count;
    const score = Math.min(count * 20, 100); // Scale: 1 detection = 20, max 100
    
    techniques.push({
      techniqueID: techId,
      score,
      comment: `${count} detection(s)`,
      color: getColorForScore(score),
      enabled: true,
      showSubtechniques: false,
    });
  }
  
  // ATT&CK Navigator layer format
  return {
    name: options.name,
    versions: {
      attack: '18',
      navigator: '5.1.0',
      layer: '4.5',
    },
    domain: 'enterprise-attack',
    description: options.description || `Generated from ${techniqueIds.length} techniques`,
    filters: { platforms: ['Windows', 'Linux', 'macOS'] },
    sorting: 0,
    layout: { layout: 'side', aggregateFunction: 'average', showID: true, showName: true },
    hideDisabled: false,
    techniques,
    gradient: {
      colors: ['#ff6666', '#ffe766', '#8ec843'],
      minValue: 0,
      maxValue: 100,
    },
    legendItems: [],
    metadata: [],
    links: [],
    showTacticRowBackground: false,
    tacticRowBackground: '#dddddd',
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
    selectVisibleTechniques: false,
  };
}

// =============================================================================
// LIGHTWEIGHT DETECTION LIST FUNCTIONS - For fast name+ID retrieval
// =============================================================================

export interface DetectionListItem {
  name: string;
  id: string;
  source_type: string;
  mitre_ids: string[];
  severity: string | null;
}

export interface SourceComparisonResult {
  topic: string;
  total_found: number;
  by_source: Record<string, DetectionListItem[]>;
  by_tactic: Record<string, Record<string, number>>;
  summary: {
    source_counts: Record<string, number>;
    tactic_coverage: Record<string, string[]>;
  };
}

function rowToListItem(row: Record<string, unknown>): DetectionListItem {
  return {
    name: row.name as string,
    id: row.id as string,
    source_type: row.source_type as string,
    mitre_ids: JSON.parse(row.mitre_ids as string || '[]'),
    severity: row.severity as string | null,
  };
}

// Get just name+ID list for a search query - NO full detection bloat
export function searchDetectionList(query: string, limit: number = 500): DetectionListItem[] {
  const database = initDb();
  
  const stmt = database.prepare(`
    SELECT d.id, d.name, d.source_type, d.mitre_ids, d.severity 
    FROM detections d
    JOIN detections_fts fts ON d.rowid = fts.rowid
    WHERE detections_fts MATCH ?
    ORDER BY rank
    LIMIT ?
  `);
  
  const rows = stmt.all(query, limit) as Record<string, unknown>[];
  return rows.map(rowToListItem);
}

// Get name+ID list filtered by source
export function listDetectionsBySourceLight(
  sourceType: 'sigma' | 'splunk_escu' | 'elastic' | 'kql',
  nameFilter?: string,
  limit: number = 500
): DetectionListItem[] {
  const database = initDb();
  
  let sql = 'SELECT id, name, source_type, mitre_ids, severity FROM detections WHERE source_type = ?';
  const params: (string | number)[] = [sourceType];
  
  if (nameFilter) {
    sql += ' AND name LIKE ?';
    params.push(`%${nameFilter}%`);
  }
  
  sql += ' ORDER BY name LIMIT ?';
  params.push(limit);
  
  const stmt = database.prepare(sql);
  const rows = stmt.all(...params) as Record<string, unknown>[];
  return rows.map(rowToListItem);
}

// Compare detections across sources for a topic - returns clean structured comparison
export function compareDetectionsBySource(topic: string, limit: number = 100): SourceComparisonResult {
  const database = initDb();
  
  // Search for the topic
  const stmt = database.prepare(`
    SELECT d.id, d.name, d.source_type, d.mitre_ids, d.severity, d.mitre_tactics
    FROM detections d
    JOIN detections_fts fts ON d.rowid = fts.rowid
    WHERE detections_fts MATCH ?
    ORDER BY d.source_type, d.name
    LIMIT ?
  `);
  
  const rows = stmt.all(topic, limit * 4) as Record<string, unknown>[];
  
  // Group by source
  const bySource: Record<string, DetectionListItem[]> = {
    sigma: [],
    splunk_escu: [],
    elastic: [],
    kql: [],
  };
  
  // Track tactics per source
  const byTactic: Record<string, Record<string, number>> = {};
  
  for (const row of rows) {
    const item = rowToListItem(row);
    const source = item.source_type;
    
    if (bySource[source]) {
      if (bySource[source].length < limit) {
        bySource[source].push(item);
      }
    }
    
    // Count tactics
    const tactics = JSON.parse(row.mitre_tactics as string || '[]') as string[];
    for (const tactic of tactics) {
      if (!byTactic[tactic]) byTactic[tactic] = {};
      byTactic[tactic][source] = (byTactic[tactic][source] || 0) + 1;
    }
  }
  
  // Build summary
  const sourceCounts: Record<string, number> = {};
  for (const [source, items] of Object.entries(bySource)) {
    sourceCounts[source] = items.length;
  }
  
  // Find tactic coverage gaps
  const tacticCoverage: Record<string, string[]> = {};
  for (const [tactic, sources] of Object.entries(byTactic)) {
    tacticCoverage[tactic] = Object.keys(sources);
  }
  
  return {
    topic,
    total_found: rows.length,
    by_source: bySource,
    by_tactic: byTactic,
    summary: {
      source_counts: sourceCounts,
      tactic_coverage: tacticCoverage,
    },
  };
}

// Get detection names and IDs matching a pattern, grouped by source
export function getDetectionNamesByPattern(
  pattern: string,
  sourceType?: 'sigma' | 'splunk_escu' | 'elastic' | 'kql'
): { source: string; detections: Array<{ name: string; id: string }> }[] {
  const database = initDb();
  
  let sql = `
    SELECT id, name, source_type FROM detections 
    WHERE name LIKE ?
  `;
  const params: string[] = [`%${pattern}%`];
  
  if (sourceType) {
    sql += ' AND source_type = ?';
    params.push(sourceType);
  }
  
  sql += ' ORDER BY source_type, name';
  
  const rows = database.prepare(sql).all(...params) as { id: string; name: string; source_type: string }[];
  
  // Group by source
  const grouped: Record<string, Array<{ name: string; id: string }>> = {};
  for (const row of rows) {
    if (!grouped[row.source_type]) grouped[row.source_type] = [];
    grouped[row.source_type].push({ name: row.name, id: row.id });
  }
  
  return Object.entries(grouped).map(([source, detections]) => ({ source, detections }));
}

// Quick count of detections by source for a topic
export function countDetectionsBySource(topic: string): Record<string, number> {
  const database = initDb();
  
  const stmt = database.prepare(`
    SELECT d.source_type, COUNT(*) as count
    FROM detections d
    JOIN detections_fts fts ON d.rowid = fts.rowid
    WHERE detections_fts MATCH ?
    GROUP BY d.source_type
  `);
  
  const rows = stmt.all(topic) as { source_type: string; count: number }[];
  
  const result: Record<string, number> = { sigma: 0, splunk_escu: 0, elastic: 0, kql: 0 };
  for (const row of rows) {
    result[row.source_type] = row.count;
  }
  return result;
}

// =============================================================================
// SAVED QUERIES / QUICK RESULTS CACHE
// =============================================================================

export function initSavedQueriesTable(): void {
  const database = initDb();
  
  database.exec(`
    CREATE TABLE IF NOT EXISTS saved_queries (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      query_type TEXT NOT NULL,
      query_params TEXT,
      result_json TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      expires_at TEXT
    )
  `);
  
  database.exec(`CREATE INDEX IF NOT EXISTS idx_saved_query_type ON saved_queries(query_type)`);
  database.exec(`CREATE INDEX IF NOT EXISTS idx_saved_query_name ON saved_queries(name)`);
}

export function saveQueryResult(
  name: string,
  queryType: string,
  queryParams: Record<string, unknown>,
  result: unknown,
  ttlMinutes?: number
): string {
  const database = initDb();
  initSavedQueriesTable();
  
  const id = `sq_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const expiresAt = ttlMinutes 
    ? new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString()
    : null;
  
  const stmt = database.prepare(`
    INSERT OR REPLACE INTO saved_queries (id, name, query_type, query_params, result_json, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  
  stmt.run(id, name, queryType, JSON.stringify(queryParams), JSON.stringify(result), expiresAt);
  return id;
}

export function getSavedQuery(name: string): unknown | null {
  const database = initDb();
  initSavedQueriesTable();
  
  const stmt = database.prepare(`
    SELECT result_json, expires_at FROM saved_queries 
    WHERE name = ? 
    ORDER BY created_at DESC 
    LIMIT 1
  `);
  
  const row = stmt.get(name) as { result_json: string; expires_at: string | null } | undefined;
  
  if (!row) return null;
  
  // Check expiry
  if (row.expires_at && new Date(row.expires_at) < new Date()) {
    return null;
  }
  
  return JSON.parse(row.result_json);
}

export function listSavedQueries(queryType?: string): Array<{ id: string; name: string; query_type: string; created_at: string }> {
  const database = initDb();
  initSavedQueriesTable();
  
  let sql = 'SELECT id, name, query_type, created_at FROM saved_queries';
  const params: string[] = [];
  
  if (queryType) {
    sql += ' WHERE query_type = ?';
    params.push(queryType);
  }
  
  sql += ' ORDER BY created_at DESC LIMIT 50';
  
  return database.prepare(sql).all(...params) as Array<{ id: string; name: string; query_type: string; created_at: string }>;
}

export function deleteSavedQuery(name: string): boolean {
  const database = initDb();
  initSavedQueriesTable();
  
  const result = database.prepare('DELETE FROM saved_queries WHERE name = ?').run(name);
  return result.changes > 0;
}
