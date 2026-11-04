import { migrateDetectionIdentity } from './identity.js';
/**
 * Database Schema Module
 * 
 * Contains all CREATE TABLE statements, FTS5 virtual tables,
 * triggers, and indexes for the security detections database.
 */

import type Database from 'better-sqlite3';

/**
 * Create all database tables, indexes, and triggers.
 * Called once during database initialization.
 */
export function createSchema(db: Database.Database): void {
  const foreignKeys = db.pragma('foreign_keys', { simple: true });
  db.pragma('foreign_keys = OFF');
  try {
    db.transaction(() => {
      const migrated = migrateDetectionIdentity(db);
      createDetectionsTable(db);
      createDetectionsFts(db);
      createDetectionsTriggers(db);
      createDetectionsIndexes(db);
      createStoriesTable(db);
      createStoriesFts(db);
      createStoriesTriggers(db);
      createStoriesIndexes(db);
      createProcedureReferenceTable(db);
      createJunctionTables(db);
      createDetectionEdgeTriggers(db);
      createAttackTables(db);
      if (migrated) db.exec("INSERT INTO detections_fts(detections_fts) VALUES ('rebuild')");
      const violations = db.pragma('foreign_key_check') as unknown[];
      if (violations.length) throw new Error('Detection identity migration failed foreign key validation');
    })();
  } finally {
    db.pragma(`foreign_keys = ${foreignKeys ? 'ON' : 'OFF'}`);
  }
}

/**
 * Create the main detections table with all enhanced fields.
 */
function createDetectionsTable(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS detections (
      id TEXT NOT NULL,
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
      kql_keywords TEXT,
      sublime_attack_types TEXT,
      sublime_detection_methods TEXT,
      sublime_tactics TEXT,
      PRIMARY KEY (source_type, id)
    )
  `);
}

/**
 * Create FTS5 virtual table for full-text search on detections.
 */
function createDetectionsFts(db: Database.Database): void {
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
      sublime_attack_types,
      sublime_detection_methods,
      sublime_tactics,
      content='detections',
      content_rowid='rowid'
    )
  `);
}

/**
 * Create triggers to keep FTS in sync with detections table.
 */
function createDetectionsTriggers(db: Database.Database): void {
  // After INSERT trigger
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS detections_ai AFTER INSERT ON detections BEGIN
      INSERT INTO detections_fts(rowid, id, name, description, query, mitre_ids, tags, cves, analytic_stories, data_sources, process_names, file_paths, registry_paths, mitre_tactics, platforms, kql_category, kql_tags, kql_keywords, sublime_attack_types, sublime_detection_methods, sublime_tactics)
      VALUES (NEW.rowid, NEW.id, NEW.name, NEW.description, NEW.query, NEW.mitre_ids, NEW.tags, NEW.cves, NEW.analytic_stories, NEW.data_sources, NEW.process_names, NEW.file_paths, NEW.registry_paths, NEW.mitre_tactics, NEW.platforms, NEW.kql_category, NEW.kql_tags, NEW.kql_keywords, NEW.sublime_attack_types, NEW.sublime_detection_methods, NEW.sublime_tactics);
    END
  `);

  // After DELETE trigger
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS detections_ad AFTER DELETE ON detections BEGIN
      INSERT INTO detections_fts(detections_fts, rowid, id, name, description, query, mitre_ids, tags, cves, analytic_stories, data_sources, process_names, file_paths, registry_paths, mitre_tactics, platforms, kql_category, kql_tags, kql_keywords, sublime_attack_types, sublime_detection_methods, sublime_tactics)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.description, OLD.query, OLD.mitre_ids, OLD.tags, OLD.cves, OLD.analytic_stories, OLD.data_sources, OLD.process_names, OLD.file_paths, OLD.registry_paths, OLD.mitre_tactics, OLD.platforms, OLD.kql_category, OLD.kql_tags, OLD.kql_keywords, OLD.sublime_attack_types, OLD.sublime_detection_methods, OLD.sublime_tactics);
    END
  `);

  // After UPDATE trigger
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS detections_au AFTER UPDATE ON detections BEGIN
      INSERT INTO detections_fts(detections_fts, rowid, id, name, description, query, mitre_ids, tags, cves, analytic_stories, data_sources, process_names, file_paths, registry_paths, mitre_tactics, platforms, kql_category, kql_tags, kql_keywords, sublime_attack_types, sublime_detection_methods, sublime_tactics)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.description, OLD.query, OLD.mitre_ids, OLD.tags, OLD.cves, OLD.analytic_stories, OLD.data_sources, OLD.process_names, OLD.file_paths, OLD.registry_paths, OLD.mitre_tactics, OLD.platforms, OLD.kql_category, OLD.kql_tags, OLD.kql_keywords, OLD.sublime_attack_types, OLD.sublime_detection_methods, OLD.sublime_tactics);
      INSERT INTO detections_fts(rowid, id, name, description, query, mitre_ids, tags, cves, analytic_stories, data_sources, process_names, file_paths, registry_paths, mitre_tactics, platforms, kql_category, kql_tags, kql_keywords, sublime_attack_types, sublime_detection_methods, sublime_tactics)
      VALUES (NEW.rowid, NEW.id, NEW.name, NEW.description, NEW.query, NEW.mitre_ids, NEW.tags, NEW.cves, NEW.analytic_stories, NEW.data_sources, NEW.process_names, NEW.file_paths, NEW.registry_paths, NEW.mitre_tactics, NEW.platforms, NEW.kql_category, NEW.kql_tags, NEW.kql_keywords, NEW.sublime_attack_types, NEW.sublime_detection_methods, NEW.sublime_tactics);
    END
  `);
}

/**
 * Create indexes for common detection queries.
 */
function createDetectionsIndexes(db: Database.Database): void {
  db.exec(`CREATE INDEX IF NOT EXISTS idx_detection_id ON detections(id)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_source_type ON detections(source_type)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_severity ON detections(severity)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logsource_product ON detections(logsource_product)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logsource_category ON detections(logsource_category)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_detection_type ON detections(detection_type)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_asset_type ON detections(asset_type)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_security_domain ON detections(security_domain)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_kql_category ON detections(kql_category)`);
}

/**
 * Create the stories table for analytic stories.
 */
function createStoriesTable(db: Database.Database): void {
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
}

/**
 * Create FTS5 virtual table for full-text search on stories.
 */
function createStoriesFts(db: Database.Database): void {
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
}

/**
 * Create triggers to keep stories FTS in sync.
 */
function createStoriesTriggers(db: Database.Database): void {
  // After INSERT trigger
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS stories_ai AFTER INSERT ON stories BEGIN
      INSERT INTO stories_fts(rowid, id, name, description, narrative, category, usecase)
      VALUES (NEW.rowid, NEW.id, NEW.name, NEW.description, NEW.narrative, NEW.category, NEW.usecase);
    END
  `);

  // After DELETE trigger
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS stories_ad AFTER DELETE ON stories BEGIN
      INSERT INTO stories_fts(stories_fts, rowid, id, name, description, narrative, category, usecase)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.description, OLD.narrative, OLD.category, OLD.usecase);
    END
  `);
}

/**
 * Create indexes for common story queries.
 */
function createStoriesIndexes(db: Database.Database): void {
  db.exec(`CREATE INDEX IF NOT EXISTS idx_story_category ON stories(category)`);
}

/**
 * Create the procedure_reference table for storing auto-extracted
 * and hand-curated procedure-level ATT&CK coverage data.
 */
function createProcedureReferenceTable(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS procedure_reference (
      id TEXT PRIMARY KEY,
      technique_id TEXT NOT NULL,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      description TEXT NOT NULL,
      source TEXT NOT NULL DEFAULT 'auto',
      indicators TEXT NOT NULL,
      detection_count INTEGER DEFAULT 0,
      confidence REAL DEFAULT 1.0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_proc_ref_technique ON procedure_reference(technique_id)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_proc_ref_source ON procedure_reference(source)`);
}

/**
 * Create the saved queries table for caching.
 * Called on-demand when first accessed.
 */
export function createSavedQueriesTable(db: Database.Database): void {
  db.exec(`
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
  
  db.exec(`CREATE INDEX IF NOT EXISTS idx_saved_query_type ON saved_queries(query_type)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_saved_query_name ON saved_queries(name)`);
}

/**
 * Create junction tables for materialized many-to-many relationships.
 * Replaces JSON LIKE scans with indexed JOINs.
 */
function createJunctionTables(db: Database.Database): void {
  // Detection → Technique many-to-many
  db.exec(`
    CREATE TABLE IF NOT EXISTS detection_techniques (
      source_type TEXT NOT NULL,
      detection_id TEXT NOT NULL,
      technique_id TEXT NOT NULL,
      PRIMARY KEY (source_type, detection_id, technique_id),
      FOREIGN KEY (source_type, detection_id) REFERENCES detections(source_type, id) ON DELETE CASCADE ON UPDATE CASCADE
    )
  `);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_dt_technique ON detection_techniques(technique_id)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_dt_detection ON detection_techniques(detection_id)`);

  // Technique → Tactic many-to-many (populated from detections + STIX)
  db.exec(`
    CREATE TABLE IF NOT EXISTS technique_tactics (
      technique_id TEXT NOT NULL,
      tactic_name TEXT NOT NULL,
      source TEXT NOT NULL DEFAULT 'detection',
      PRIMARY KEY (technique_id, tactic_name)
    )
  `);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_tt_tactic ON technique_tactics(tactic_name)`);
}

/**
 * Create tables for MITRE ATT&CK STIX data (threat actors, software, techniques).
 * Populated from enterprise-attack.json when ATTACK_STIX_PATH is configured.
 */
function createAttackTables(db: Database.Database): void {
  // Full ATT&CK technique catalog from STIX
  db.exec(`
    CREATE TABLE IF NOT EXISTS attack_techniques (
      technique_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      platforms TEXT,
      data_sources TEXT,
      is_subtechnique INTEGER DEFAULT 0,
      parent_technique_id TEXT,
      url TEXT
    )
  `);

  // Threat actor catalog from STIX intrusion-sets
  db.exec(`
    CREATE TABLE IF NOT EXISTS attack_actors (
      actor_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      aliases TEXT,
      description TEXT,
      external_references TEXT,
      created TEXT,
      modified TEXT
    )
  `);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_actor_name ON attack_actors(name)`);

  // Software (malware + tools) from STIX
  db.exec(`
    CREATE TABLE IF NOT EXISTS attack_software (
      software_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      software_type TEXT,
      description TEXT,
      platforms TEXT,
      aliases TEXT
    )
  `);

  // Actor → Technique junction with procedure context
  db.exec(`
    CREATE TABLE IF NOT EXISTS actor_techniques (
      actor_id TEXT NOT NULL,
      technique_id TEXT NOT NULL,
      description TEXT,
      PRIMARY KEY (actor_id, technique_id)
    )
  `);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_at_technique ON actor_techniques(technique_id)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_at_actor ON actor_techniques(actor_id)`);

  // Software → Technique junction
  db.exec(`
    CREATE TABLE IF NOT EXISTS software_techniques (
      software_id TEXT NOT NULL,
      technique_id TEXT NOT NULL,
      description TEXT,
      PRIMARY KEY (software_id, technique_id)
    )
  `);
}

/** Keep technique links exact even when callers use the legacy insertion API. */
function createDetectionEdgeTriggers(db: Database.Database): void {
  for (const event of ['INSERT', 'UPDATE'] as const) {
    db.exec(`CREATE TRIGGER IF NOT EXISTS detections_edges_${event.toLowerCase()}
      AFTER ${event} ON detections BEGIN
      DELETE FROM detection_techniques WHERE source_type = NEW.source_type AND detection_id = NEW.id;
      INSERT OR IGNORE INTO detection_techniques(source_type, detection_id, technique_id)
        SELECT NEW.source_type, NEW.id, value FROM json_each(COALESCE(NEW.mitre_ids, '[]')) WHERE type = 'text';
      END`);
  }
}
