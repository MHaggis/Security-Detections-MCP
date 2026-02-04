/**
 * Database Connection Module
 * 
 * Manages SQLite connection singleton, path management, and database lifecycle.
 */

import Database from 'better-sqlite3';
import { homedir } from 'os';
import { join } from 'path';
import { mkdirSync, existsSync, unlinkSync } from 'fs';
import { createSchema } from './schema.js';

const CACHE_DIR = join(homedir(), '.cache', 'security-detections-mcp');
const DB_PATH = join(CACHE_DIR, 'detections.sqlite');

let db: Database.Database | null = null;

// Lazy-loaded to avoid circular dependency
let knowledgeSchemaCreated = false;

/**
 * Get the path to the SQLite database file.
 */
export function getDbPath(): string {
  return DB_PATH;
}

/**
 * Get the cache directory path.
 */
export function getCacheDir(): string {
  return CACHE_DIR;
}

/**
 * Initialize and return the database connection singleton.
 * Creates the database file and schema if they don't exist.
 */
export function initDb(): Database.Database {
  if (db) return db;
  
  // Ensure cache directory exists
  if (!existsSync(CACHE_DIR)) {
    mkdirSync(CACHE_DIR, { recursive: true });
  }
  
  db = new Database(DB_PATH);
  
  // Create all tables and indexes
  createSchema(db);
  
  // Create knowledge graph tables
  createKnowledgeTables(db);
  knowledgeSchemaCreated = true;
  
  return db;
}

/**
 * Create knowledge graph tables directly (avoid circular imports)
 */
function createKnowledgeTables(database: Database.Database): void {
  // Entities
  database.exec(`
    CREATE TABLE IF NOT EXISTS kg_entities (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      entity_type TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Relations
  database.exec(`
    CREATE TABLE IF NOT EXISTS kg_relations (
      id TEXT PRIMARY KEY,
      from_entity TEXT NOT NULL,
      to_entity TEXT NOT NULL,
      relation_type TEXT NOT NULL,
      reasoning TEXT,
      confidence REAL DEFAULT 1.0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Observations
  database.exec(`
    CREATE TABLE IF NOT EXISTS kg_observations (
      id TEXT PRIMARY KEY,
      entity_name TEXT NOT NULL,
      observation TEXT NOT NULL,
      source TEXT,
      confidence REAL DEFAULT 1.0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Decisions
  database.exec(`
    CREATE TABLE IF NOT EXISTS kg_decisions (
      id TEXT PRIMARY KEY,
      decision_type TEXT NOT NULL,
      context TEXT NOT NULL,
      decision TEXT NOT NULL,
      reasoning TEXT NOT NULL,
      entities_involved TEXT,
      outcome TEXT,
      session_id TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Learnings
  database.exec(`
    CREATE TABLE IF NOT EXISTS kg_learnings (
      id TEXT PRIMARY KEY,
      learning_type TEXT NOT NULL,
      title TEXT NOT NULL,
      insight TEXT NOT NULL,
      evidence TEXT,
      applications TEXT,
      times_applied INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      last_applied TEXT
    )
  `);

  // Indexes
  database.exec(`CREATE INDEX IF NOT EXISTS idx_entities_type ON kg_entities(entity_type)`);
  database.exec(`CREATE INDEX IF NOT EXISTS idx_entities_name ON kg_entities(name)`);
  database.exec(`CREATE INDEX IF NOT EXISTS idx_relations_from ON kg_relations(from_entity)`);
  database.exec(`CREATE INDEX IF NOT EXISTS idx_relations_to ON kg_relations(to_entity)`);
  database.exec(`CREATE INDEX IF NOT EXISTS idx_relations_type ON kg_relations(relation_type)`);
  database.exec(`CREATE INDEX IF NOT EXISTS idx_observations_entity ON kg_observations(entity_name)`);
  database.exec(`CREATE INDEX IF NOT EXISTS idx_decisions_type ON kg_decisions(decision_type)`);
  database.exec(`CREATE INDEX IF NOT EXISTS idx_learnings_type ON kg_learnings(learning_type)`);

  // FTS for search
  database.exec(`
    CREATE VIRTUAL TABLE IF NOT EXISTS kg_fts USING fts5(
      entity_name,
      entity_type,
      content_type,
      content_text,
      content='',
      tokenize='porter'
    )
  `);
}

/**
 * Get the database connection, initializing if necessary.
 * This is the primary way other modules should access the database.
 */
export function getDb(): Database.Database {
  return initDb();
}

/**
 * Clear all detections from the database.
 */
export function clearDb(): void {
  const database = initDb();
  database.exec('DELETE FROM detections');
}

/**
 * Force recreation of the database.
 * Useful when schema changes require a fresh start.
 */
export function recreateDb(): void {
  if (db) {
    db.close();
    db = null;
  }
  if (existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
  }
}

/**
 * Check if the database file exists.
 */
export function dbExists(): boolean {
  return existsSync(DB_PATH);
}

/**
 * Close the database connection.
 */
export function closeDb(): void {
  if (db) {
    db.close();
    db = null;
  }
}
