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
  createDetectionsTable(db);
  createDetectionsFts(db);
  createDetectionsTriggers(db);
  createDetectionsIndexes(db);
  createStoriesTable(db);
  createStoriesFts(db);
  createStoriesTriggers(db);
  createStoriesIndexes(db);
}

/**
 * Create the main detections table with all enhanced fields.
 */
function createDetectionsTable(db: Database.Database): void {
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
      INSERT INTO detections_fts(rowid, id, name, description, query, mitre_ids, tags, cves, analytic_stories, data_sources, process_names, file_paths, registry_paths, mitre_tactics, platforms, kql_category, kql_tags, kql_keywords)
      VALUES (NEW.rowid, NEW.id, NEW.name, NEW.description, NEW.query, NEW.mitre_ids, NEW.tags, NEW.cves, NEW.analytic_stories, NEW.data_sources, NEW.process_names, NEW.file_paths, NEW.registry_paths, NEW.mitre_tactics, NEW.platforms, NEW.kql_category, NEW.kql_tags, NEW.kql_keywords);
    END
  `);

  // After DELETE trigger
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS detections_ad AFTER DELETE ON detections BEGIN
      INSERT INTO detections_fts(detections_fts, rowid, id, name, description, query, mitre_ids, tags, cves, analytic_stories, data_sources, process_names, file_paths, registry_paths, mitre_tactics, platforms, kql_category, kql_tags, kql_keywords)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.description, OLD.query, OLD.mitre_ids, OLD.tags, OLD.cves, OLD.analytic_stories, OLD.data_sources, OLD.process_names, OLD.file_paths, OLD.registry_paths, OLD.mitre_tactics, OLD.platforms, OLD.kql_category, OLD.kql_tags, OLD.kql_keywords);
    END
  `);

  // After UPDATE trigger
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS detections_au AFTER UPDATE ON detections BEGIN
      INSERT INTO detections_fts(detections_fts, rowid, id, name, description, query, mitre_ids, tags, cves, analytic_stories, data_sources, process_names, file_paths, registry_paths, mitre_tactics, platforms, kql_category, kql_tags, kql_keywords)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.description, OLD.query, OLD.mitre_ids, OLD.tags, OLD.cves, OLD.analytic_stories, OLD.data_sources, OLD.process_names, OLD.file_paths, OLD.registry_paths, OLD.mitre_tactics, OLD.platforms, OLD.kql_category, OLD.kql_tags, OLD.kql_keywords);
      INSERT INTO detections_fts(rowid, id, name, description, query, mitre_ids, tags, cves, analytic_stories, data_sources, process_names, file_paths, registry_paths, mitre_tactics, platforms, kql_category, kql_tags, kql_keywords)
      VALUES (NEW.rowid, NEW.id, NEW.name, NEW.description, NEW.query, NEW.mitre_ids, NEW.tags, NEW.cves, NEW.analytic_stories, NEW.data_sources, NEW.process_names, NEW.file_paths, NEW.registry_paths, NEW.mitre_tactics, NEW.platforms, NEW.kql_category, NEW.kql_tags, NEW.kql_keywords);
    END
  `);
}

/**
 * Create indexes for common detection queries.
 */
function createDetectionsIndexes(db: Database.Database): void {
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
