/**
 * Knowledge Graph Database Operations
 * 
 * Manages the knowledge graph for tribal knowledge storage.
 * Entities, relations, observations, decisions, and learnings
 * capture WHY connections were made and decisions were reached.
 */

import type Database from 'better-sqlite3';
import { getDb } from './connection.js';
import type {
  KnowledgeEntity,
  KnowledgeRelation,
  KnowledgeObservation,
  KnowledgeDecision,
  KnowledgeLearning,
  KnowledgeQueryOptions,
} from '../types/knowledge.js';

// ============================================================================
// Schema Creation
// ============================================================================

/**
 * Initialize all knowledge graph tables.
 * Called on first access to ensure tables exist.
 */
export function createKnowledgeSchema(db: Database.Database): void {
  createKnowledgeTables(db);
  createKnowledgeFts(db);
  createKnowledgeTriggers(db);
  createKnowledgeIndexes(db);
}

function createKnowledgeTables(db: Database.Database): void {
  // Entities - discrete concepts in the security domain
  db.exec(`
    CREATE TABLE IF NOT EXISTS kg_entities (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      entity_type TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Relations - typed connections between entities with reasoning
  db.exec(`
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

  // Observations - facts about entities
  db.exec(`
    CREATE TABLE IF NOT EXISTS kg_observations (
      id TEXT PRIMARY KEY,
      entity_name TEXT NOT NULL,
      observation TEXT NOT NULL,
      source TEXT,
      confidence REAL DEFAULT 1.0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Decisions - recorded analytical decisions with reasoning (tribal knowledge)
  db.exec(`
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

  // Learnings - reusable patterns and insights
  db.exec(`
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
}

function createKnowledgeFts(db: Database.Database): void {
  // FTS for observations - search facts
  db.exec(`
    CREATE VIRTUAL TABLE IF NOT EXISTS kg_observations_fts USING fts5(
      id,
      entity_name,
      observation,
      source,
      content='kg_observations',
      content_rowid='rowid'
    )
  `);

  // FTS for decisions - search tribal knowledge
  db.exec(`
    CREATE VIRTUAL TABLE IF NOT EXISTS kg_decisions_fts USING fts5(
      id,
      decision_type,
      context,
      decision,
      reasoning,
      entities_involved,
      outcome,
      content='kg_decisions',
      content_rowid='rowid'
    )
  `);

  // FTS for learnings - search insights
  db.exec(`
    CREATE VIRTUAL TABLE IF NOT EXISTS kg_learnings_fts USING fts5(
      id,
      learning_type,
      title,
      insight,
      evidence,
      applications,
      content='kg_learnings',
      content_rowid='rowid'
    )
  `);

  // FTS for entities - search by name
  db.exec(`
    CREATE VIRTUAL TABLE IF NOT EXISTS kg_entities_fts USING fts5(
      id,
      name,
      entity_type,
      content='kg_entities',
      content_rowid='rowid'
    )
  `);

  // FTS for relations - search reasoning
  db.exec(`
    CREATE VIRTUAL TABLE IF NOT EXISTS kg_relations_fts USING fts5(
      id,
      from_entity,
      to_entity,
      relation_type,
      reasoning,
      content='kg_relations',
      content_rowid='rowid'
    )
  `);
}

function createKnowledgeTriggers(db: Database.Database): void {
  // Observations FTS triggers
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS kg_observations_ai AFTER INSERT ON kg_observations BEGIN
      INSERT INTO kg_observations_fts(rowid, id, entity_name, observation, source)
      VALUES (NEW.rowid, NEW.id, NEW.entity_name, NEW.observation, NEW.source);
    END
  `);
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS kg_observations_ad AFTER DELETE ON kg_observations BEGIN
      INSERT INTO kg_observations_fts(kg_observations_fts, rowid, id, entity_name, observation, source)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.entity_name, OLD.observation, OLD.source);
    END
  `);

  // Decisions FTS triggers
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS kg_decisions_ai AFTER INSERT ON kg_decisions BEGIN
      INSERT INTO kg_decisions_fts(rowid, id, decision_type, context, decision, reasoning, entities_involved, outcome)
      VALUES (NEW.rowid, NEW.id, NEW.decision_type, NEW.context, NEW.decision, NEW.reasoning, NEW.entities_involved, NEW.outcome);
    END
  `);
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS kg_decisions_ad AFTER DELETE ON kg_decisions BEGIN
      INSERT INTO kg_decisions_fts(kg_decisions_fts, rowid, id, decision_type, context, decision, reasoning, entities_involved, outcome)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.decision_type, OLD.context, OLD.decision, OLD.reasoning, OLD.entities_involved, OLD.outcome);
    END
  `);

  // Learnings FTS triggers
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS kg_learnings_ai AFTER INSERT ON kg_learnings BEGIN
      INSERT INTO kg_learnings_fts(rowid, id, learning_type, title, insight, evidence, applications)
      VALUES (NEW.rowid, NEW.id, NEW.learning_type, NEW.title, NEW.insight, NEW.evidence, NEW.applications);
    END
  `);
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS kg_learnings_ad AFTER DELETE ON kg_learnings BEGIN
      INSERT INTO kg_learnings_fts(kg_learnings_fts, rowid, id, learning_type, title, insight, evidence, applications)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.learning_type, OLD.title, OLD.insight, OLD.evidence, OLD.applications);
    END
  `);

  // Entities FTS triggers
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS kg_entities_ai AFTER INSERT ON kg_entities BEGIN
      INSERT INTO kg_entities_fts(rowid, id, name, entity_type)
      VALUES (NEW.rowid, NEW.id, NEW.name, NEW.entity_type);
    END
  `);
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS kg_entities_ad AFTER DELETE ON kg_entities BEGIN
      INSERT INTO kg_entities_fts(kg_entities_fts, rowid, id, name, entity_type)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.entity_type);
    END
  `);

  // Relations FTS triggers
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS kg_relations_ai AFTER INSERT ON kg_relations BEGIN
      INSERT INTO kg_relations_fts(rowid, id, from_entity, to_entity, relation_type, reasoning)
      VALUES (NEW.rowid, NEW.id, NEW.from_entity, NEW.to_entity, NEW.relation_type, NEW.reasoning);
    END
  `);
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS kg_relations_ad AFTER DELETE ON kg_relations BEGIN
      INSERT INTO kg_relations_fts(kg_relations_fts, rowid, id, from_entity, to_entity, relation_type, reasoning)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.from_entity, OLD.to_entity, OLD.relation_type, OLD.reasoning);
    END
  `);
}

function createKnowledgeIndexes(db: Database.Database): void {
  // Entity indexes
  db.exec(`CREATE INDEX IF NOT EXISTS idx_kg_entity_type ON kg_entities(entity_type)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_kg_entity_name ON kg_entities(name)`);

  // Relation indexes
  db.exec(`CREATE INDEX IF NOT EXISTS idx_kg_rel_from ON kg_relations(from_entity)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_kg_rel_to ON kg_relations(to_entity)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_kg_rel_type ON kg_relations(relation_type)`);

  // Observation indexes
  db.exec(`CREATE INDEX IF NOT EXISTS idx_kg_obs_entity ON kg_observations(entity_name)`);

  // Decision indexes
  db.exec(`CREATE INDEX IF NOT EXISTS idx_kg_dec_type ON kg_decisions(decision_type)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_kg_dec_session ON kg_decisions(session_id)`);

  // Learning indexes
  db.exec(`CREATE INDEX IF NOT EXISTS idx_kg_learn_type ON kg_learnings(learning_type)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_kg_learn_applied ON kg_learnings(times_applied DESC)`);
}

// ============================================================================
// Entity Operations
// ============================================================================

let schemaInitialized = false;

function ensureSchema(): void {
  if (!schemaInitialized) {
    // Check if tables already exist (created by connection.ts)
    const db = getDb();
    const tableExists = db.prepare(`
      SELECT name FROM sqlite_master WHERE type='table' AND name='kg_entities'
    `).get();
    
    if (!tableExists) {
      createKnowledgeSchema(db);
    }
    schemaInitialized = true;
  }
}

/**
 * Create a new knowledge entity
 */
export function createEntity(
  name: string,
  entityType: string,
  id?: string
): KnowledgeEntity {
  ensureSchema();
  const db = getDb();
  const entityId = id || crypto.randomUUID();
  const now = new Date().toISOString();

  const stmt = db.prepare(`
    INSERT INTO kg_entities (id, name, entity_type, created_at)
    VALUES (?, ?, ?, ?)
  `);
  stmt.run(entityId, name, entityType, now);

  return { id: entityId, name, entity_type: entityType, created_at: now };
}

/**
 * Get an entity by name or ID
 */
export function getEntity(nameOrId: string): KnowledgeEntity | null {
  ensureSchema();
  const db = getDb();
  const row = db.prepare(`
    SELECT * FROM kg_entities WHERE name = ? OR id = ?
  `).get(nameOrId, nameOrId) as KnowledgeEntity | undefined;
  return row || null;
}

/**
 * Delete an entity and all its relations and observations
 */
export function deleteEntity(nameOrId: string): { deleted: boolean; relations_removed: number; observations_removed: number } {
  ensureSchema();
  const db = getDb();
  const entity = getEntity(nameOrId);
  if (!entity) {
    return { deleted: false, relations_removed: 0, observations_removed: 0 };
  }

  // Delete relations involving this entity
  const relResult = db.prepare(`
    DELETE FROM kg_relations WHERE from_entity = ? OR to_entity = ?
  `).run(entity.name, entity.name);

  // Delete observations about this entity
  const obsResult = db.prepare(`
    DELETE FROM kg_observations WHERE entity_name = ?
  `).run(entity.name);

  // Delete the entity
  db.prepare(`DELETE FROM kg_entities WHERE id = ?`).run(entity.id);

  return {
    deleted: true,
    relations_removed: relResult.changes,
    observations_removed: obsResult.changes,
  };
}

/**
 * List all entities, optionally filtered by type
 */
export function listEntities(entityType?: string, limit = 100): KnowledgeEntity[] {
  ensureSchema();
  const db = getDb();
  if (entityType) {
    return db.prepare(`
      SELECT * FROM kg_entities WHERE entity_type = ? ORDER BY created_at DESC LIMIT ?
    `).all(entityType, limit) as KnowledgeEntity[];
  }
  return db.prepare(`
    SELECT * FROM kg_entities ORDER BY created_at DESC LIMIT ?
  `).all(limit) as KnowledgeEntity[];
}

// ============================================================================
// Relation Operations
// ============================================================================

/**
 * Create a relation between two entities
 */
export function createRelation(
  fromEntity: string,
  toEntity: string,
  relationType: string,
  reasoning?: string,
  confidence = 1.0,
  id?: string
): KnowledgeRelation {
  ensureSchema();
  const db = getDb();
  const relationId = id || crypto.randomUUID();
  const now = new Date().toISOString();

  const stmt = db.prepare(`
    INSERT INTO kg_relations (id, from_entity, to_entity, relation_type, reasoning, confidence, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(relationId, fromEntity, toEntity, relationType, reasoning || null, confidence, now);

  return {
    id: relationId,
    from_entity: fromEntity,
    to_entity: toEntity,
    relation_type: relationType,
    reasoning,
    confidence,
    created_at: now,
  };
}

/**
 * Get relations for an entity (both incoming and outgoing)
 */
export function getRelationsForEntity(entityName: string): {
  outgoing: KnowledgeRelation[];
  incoming: KnowledgeRelation[];
} {
  ensureSchema();
  const db = getDb();
  const outgoing = db.prepare(`
    SELECT * FROM kg_relations WHERE from_entity = ?
  `).all(entityName) as KnowledgeRelation[];
  const incoming = db.prepare(`
    SELECT * FROM kg_relations WHERE to_entity = ?
  `).all(entityName) as KnowledgeRelation[];
  return { outgoing, incoming };
}

/**
 * Get all relations, optionally filtered by type
 */
export function listRelations(relationType?: string, limit = 100): KnowledgeRelation[] {
  ensureSchema();
  const db = getDb();
  if (relationType) {
    return db.prepare(`
      SELECT * FROM kg_relations WHERE relation_type = ? ORDER BY created_at DESC LIMIT ?
    `).all(relationType, limit) as KnowledgeRelation[];
  }
  return db.prepare(`
    SELECT * FROM kg_relations ORDER BY created_at DESC LIMIT ?
  `).all(limit) as KnowledgeRelation[];
}

// ============================================================================
// Observation Operations
// ============================================================================

/**
 * Add an observation to an entity
 */
export function addObservation(
  entityName: string,
  observation: string,
  source?: string,
  confidence = 1.0,
  id?: string
): KnowledgeObservation {
  ensureSchema();
  const db = getDb();
  const obsId = id || crypto.randomUUID();
  const now = new Date().toISOString();

  const stmt = db.prepare(`
    INSERT INTO kg_observations (id, entity_name, observation, source, confidence, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  stmt.run(obsId, entityName, observation, source || null, confidence, now);

  return {
    id: obsId,
    entity_name: entityName,
    observation,
    source,
    confidence,
    created_at: now,
  };
}

/**
 * Get observations for an entity
 */
export function getObservationsForEntity(entityName: string): KnowledgeObservation[] {
  ensureSchema();
  const db = getDb();
  return db.prepare(`
    SELECT * FROM kg_observations WHERE entity_name = ? ORDER BY created_at DESC
  `).all(entityName) as KnowledgeObservation[];
}

/**
 * Delete an observation by ID
 */
export function deleteObservation(obsId: string): boolean {
  ensureSchema();
  const db = getDb();
  const result = db.prepare(`DELETE FROM kg_observations WHERE id = ?`).run(obsId);
  return result.changes > 0;
}

// ============================================================================
// Decision Operations (Tribal Knowledge)
// ============================================================================

/**
 * Log a decision with full context and reasoning
 */
export function logDecision(
  decisionType: string,
  context: string,
  decision: string,
  reasoning: string,
  entitiesInvolved: string[] = [],
  outcome?: string,
  sessionId?: string,
  id?: string
): KnowledgeDecision {
  ensureSchema();
  const db = getDb();
  const decisionId = id || crypto.randomUUID();
  const now = new Date().toISOString();

  const stmt = db.prepare(`
    INSERT INTO kg_decisions (id, decision_type, context, decision, reasoning, entities_involved, outcome, session_id, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    decisionId,
    decisionType,
    context,
    decision,
    reasoning,
    JSON.stringify(entitiesInvolved),
    outcome || null,
    sessionId || null,
    now
  );

  return {
    id: decisionId,
    decision_type: decisionType,
    context,
    decision,
    reasoning,
    entities_involved: entitiesInvolved,
    outcome,
    session_id: sessionId,
    created_at: now,
  };
}

/**
 * Get decisions relevant to a context (uses FTS)
 */
export function getRelevantDecisions(
  contextQuery: string,
  options: KnowledgeQueryOptions = {}
): KnowledgeDecision[] {
  ensureSchema();
  const db = getDb();
  const limit = options.limit || 20;

  // Use FTS to find relevant decisions
  const rows = db.prepare(`
    SELECT d.* FROM kg_decisions d
    JOIN kg_decisions_fts fts ON d.rowid = fts.rowid
    WHERE kg_decisions_fts MATCH ?
    ${options.decision_type ? 'AND d.decision_type = ?' : ''}
    ${options.session_id ? 'AND d.session_id = ?' : ''}
    ORDER BY rank
    LIMIT ?
  `).all(
    contextQuery,
    ...(options.decision_type ? [options.decision_type] : []),
    ...(options.session_id ? [options.session_id] : []),
    limit
  ) as Array<KnowledgeDecision & { entities_involved: string }>;

  return rows.map(row => ({
    ...row,
    entities_involved: row.entities_involved ? JSON.parse(row.entities_involved) : [],
  }));
}

/**
 * List decisions by type
 */
export function listDecisions(decisionType?: string, limit = 50): KnowledgeDecision[] {
  ensureSchema();
  const db = getDb();
  let rows: Array<KnowledgeDecision & { entities_involved: string }>;

  if (decisionType) {
    rows = db.prepare(`
      SELECT * FROM kg_decisions WHERE decision_type = ? ORDER BY created_at DESC LIMIT ?
    `).all(decisionType, limit) as Array<KnowledgeDecision & { entities_involved: string }>;
  } else {
    rows = db.prepare(`
      SELECT * FROM kg_decisions ORDER BY created_at DESC LIMIT ?
    `).all(limit) as Array<KnowledgeDecision & { entities_involved: string }>;
  }

  return rows.map(row => ({
    ...row,
    entities_involved: row.entities_involved ? JSON.parse(row.entities_involved) : [],
  }));
}

// ============================================================================
// Learning Operations
// ============================================================================

/**
 * Add a learning (pattern/insight)
 */
export function addLearning(
  learningType: string,
  title: string,
  insight: string,
  evidence?: string,
  applications?: string,
  id?: string
): KnowledgeLearning {
  ensureSchema();
  const db = getDb();
  const learningId = id || crypto.randomUUID();
  const now = new Date().toISOString();

  const stmt = db.prepare(`
    INSERT INTO kg_learnings (id, learning_type, title, insight, evidence, applications, times_applied, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 0, ?)
  `);
  stmt.run(learningId, learningType, title, insight, evidence || null, applications || null, now);

  return {
    id: learningId,
    learning_type: learningType,
    title,
    insight,
    evidence,
    applications,
    times_applied: 0,
    created_at: now,
  };
}

/**
 * Get learnings relevant to a task (uses FTS)
 */
export function getRelevantLearnings(
  taskQuery: string,
  options: KnowledgeQueryOptions = {}
): KnowledgeLearning[] {
  ensureSchema();
  const db = getDb();
  const limit = options.limit || 10;

  const rows = db.prepare(`
    SELECT l.* FROM kg_learnings l
    JOIN kg_learnings_fts fts ON l.rowid = fts.rowid
    WHERE kg_learnings_fts MATCH ?
    ${options.learning_type ? 'AND l.learning_type = ?' : ''}
    ORDER BY l.times_applied DESC, rank
    LIMIT ?
  `).all(
    taskQuery,
    ...(options.learning_type ? [options.learning_type] : []),
    limit
  ) as KnowledgeLearning[];

  return rows;
}

/**
 * Increment the times_applied counter for a learning
 */
export function applyLearning(learningId: string): boolean {
  ensureSchema();
  const db = getDb();
  const now = new Date().toISOString();
  const result = db.prepare(`
    UPDATE kg_learnings SET times_applied = times_applied + 1, last_applied = ? WHERE id = ?
  `).run(now, learningId);
  return result.changes > 0;
}

/**
 * List learnings by type or get most-applied
 */
export function listLearnings(learningType?: string, limit = 20): KnowledgeLearning[] {
  ensureSchema();
  const db = getDb();
  if (learningType) {
    return db.prepare(`
      SELECT * FROM kg_learnings WHERE learning_type = ? ORDER BY times_applied DESC, created_at DESC LIMIT ?
    `).all(learningType, limit) as KnowledgeLearning[];
  }
  return db.prepare(`
    SELECT * FROM kg_learnings ORDER BY times_applied DESC, created_at DESC LIMIT ?
  `).all(limit) as KnowledgeLearning[];
}

// ============================================================================
// Graph Operations
// ============================================================================

/**
 * Get the entire knowledge graph or a filtered subgraph
 */
export function readGraph(options: KnowledgeQueryOptions = {}): {
  entities: KnowledgeEntity[];
  relations: KnowledgeRelation[];
  observations: KnowledgeObservation[];
  stats: { entities: number; relations: number; observations: number };
} {
  ensureSchema();
  const db = getDb();
  const limit = options.limit || 500;

  let entities: KnowledgeEntity[];
  let relations: KnowledgeRelation[];
  let observations: KnowledgeObservation[];

  if (options.entity_type) {
    entities = db.prepare(`
      SELECT * FROM kg_entities WHERE entity_type = ? LIMIT ?
    `).all(options.entity_type, limit) as KnowledgeEntity[];

    // Get entity names for filtering
    const entityNames = entities.map(e => e.name);
    if (entityNames.length > 0) {
      const placeholders = entityNames.map(() => '?').join(',');
      relations = db.prepare(`
        SELECT * FROM kg_relations 
        WHERE from_entity IN (${placeholders}) OR to_entity IN (${placeholders})
        LIMIT ?
      `).all(...entityNames, ...entityNames, limit) as KnowledgeRelation[];
      observations = db.prepare(`
        SELECT * FROM kg_observations WHERE entity_name IN (${placeholders}) LIMIT ?
      `).all(...entityNames, limit) as KnowledgeObservation[];
    } else {
      relations = [];
      observations = [];
    }
  } else {
    entities = db.prepare(`SELECT * FROM kg_entities LIMIT ?`).all(limit) as KnowledgeEntity[];
    relations = db.prepare(`SELECT * FROM kg_relations LIMIT ?`).all(limit) as KnowledgeRelation[];
    observations = db.prepare(`SELECT * FROM kg_observations LIMIT ?`).all(limit) as KnowledgeObservation[];
  }

  return {
    entities,
    relations,
    observations,
    stats: {
      entities: entities.length,
      relations: relations.length,
      observations: observations.length,
    },
  };
}

/**
 * Get complete information about a specific entity
 */
export function openEntity(nameOrId: string): {
  entity: KnowledgeEntity | null;
  relations: { outgoing: KnowledgeRelation[]; incoming: KnowledgeRelation[] };
  observations: KnowledgeObservation[];
} | null {
  ensureSchema();
  const entity = getEntity(nameOrId);
  if (!entity) {
    return null;
  }

  return {
    entity,
    relations: getRelationsForEntity(entity.name),
    observations: getObservationsForEntity(entity.name),
  };
}

// ============================================================================
// Search Operations
// ============================================================================

export interface SearchResult {
  type: 'entity' | 'relation' | 'observation' | 'decision' | 'learning';
  id: string;
  name?: string;
  content: string;
  score?: number;
}

/**
 * Search across all knowledge types
 */
export function searchKnowledge(query: string, limit = 30): SearchResult[] {
  ensureSchema();
  const db = getDb();
  const results: SearchResult[] = [];
  const perTypeLimit = Math.ceil(limit / 5);

  // Search entities
  try {
    const entityRows = db.prepare(`
      SELECT e.*, rank FROM kg_entities e
      JOIN kg_entities_fts fts ON e.rowid = fts.rowid
      WHERE kg_entities_fts MATCH ?
      ORDER BY rank LIMIT ?
    `).all(query, perTypeLimit) as Array<KnowledgeEntity & { rank: number }>;
    results.push(...entityRows.map(r => ({
      type: 'entity' as const,
      id: r.id,
      name: r.name,
      content: `[${r.entity_type}] ${r.name}`,
      score: r.rank,
    })));
  } catch {
    // FTS query might fail for invalid syntax
  }

  // Search relations
  try {
    const relationRows = db.prepare(`
      SELECT r.*, rank FROM kg_relations r
      JOIN kg_relations_fts fts ON r.rowid = fts.rowid
      WHERE kg_relations_fts MATCH ?
      ORDER BY rank LIMIT ?
    `).all(query, perTypeLimit) as Array<KnowledgeRelation & { rank: number }>;
    results.push(...relationRows.map(r => ({
      type: 'relation' as const,
      id: r.id,
      content: `${r.from_entity} --[${r.relation_type}]--> ${r.to_entity}: ${r.reasoning || 'no reasoning'}`,
      score: r.rank,
    })));
  } catch {
    // FTS query might fail
  }

  // Search observations
  try {
    const obsRows = db.prepare(`
      SELECT o.*, rank FROM kg_observations o
      JOIN kg_observations_fts fts ON o.rowid = fts.rowid
      WHERE kg_observations_fts MATCH ?
      ORDER BY rank LIMIT ?
    `).all(query, perTypeLimit) as Array<KnowledgeObservation & { rank: number }>;
    results.push(...obsRows.map(r => ({
      type: 'observation' as const,
      id: r.id,
      name: r.entity_name,
      content: r.observation,
      score: r.rank,
    })));
  } catch {
    // FTS query might fail
  }

  // Search decisions
  try {
    const decRows = db.prepare(`
      SELECT d.*, rank FROM kg_decisions d
      JOIN kg_decisions_fts fts ON d.rowid = fts.rowid
      WHERE kg_decisions_fts MATCH ?
      ORDER BY rank LIMIT ?
    `).all(query, perTypeLimit) as Array<KnowledgeDecision & { rank: number }>;
    results.push(...decRows.map(r => ({
      type: 'decision' as const,
      id: r.id,
      name: r.decision_type,
      content: `${r.decision}: ${r.reasoning}`,
      score: r.rank,
    })));
  } catch {
    // FTS query might fail
  }

  // Search learnings
  try {
    const learnRows = db.prepare(`
      SELECT l.*, rank FROM kg_learnings l
      JOIN kg_learnings_fts fts ON l.rowid = fts.rowid
      WHERE kg_learnings_fts MATCH ?
      ORDER BY rank LIMIT ?
    `).all(query, perTypeLimit) as Array<KnowledgeLearning & { rank: number }>;
    results.push(...learnRows.map(r => ({
      type: 'learning' as const,
      id: r.id,
      name: r.title,
      content: r.insight,
      score: r.rank,
    })));
  } catch {
    // FTS query might fail
  }

  // Sort by score and limit
  results.sort((a, b) => (a.score || 0) - (b.score || 0));
  return results.slice(0, limit);
}

/**
 * Get knowledge graph statistics
 */
export function getKnowledgeStats(): {
  entities: number;
  relations: number;
  observations: number;
  decisions: number;
  learnings: number;
  entity_types: Array<{ type: string; count: number }>;
  relation_types: Array<{ type: string; count: number }>;
  decision_types: Array<{ type: string; count: number }>;
  learning_types: Array<{ type: string; count: number }>;
} {
  ensureSchema();
  const db = getDb();

  const entityCount = (db.prepare(`SELECT COUNT(*) as count FROM kg_entities`).get() as { count: number }).count;
  const relationCount = (db.prepare(`SELECT COUNT(*) as count FROM kg_relations`).get() as { count: number }).count;
  const observationCount = (db.prepare(`SELECT COUNT(*) as count FROM kg_observations`).get() as { count: number }).count;
  const decisionCount = (db.prepare(`SELECT COUNT(*) as count FROM kg_decisions`).get() as { count: number }).count;
  const learningCount = (db.prepare(`SELECT COUNT(*) as count FROM kg_learnings`).get() as { count: number }).count;

  const entityTypes = db.prepare(`
    SELECT entity_type as type, COUNT(*) as count FROM kg_entities GROUP BY entity_type ORDER BY count DESC
  `).all() as Array<{ type: string; count: number }>;

  const relationTypes = db.prepare(`
    SELECT relation_type as type, COUNT(*) as count FROM kg_relations GROUP BY relation_type ORDER BY count DESC
  `).all() as Array<{ type: string; count: number }>;

  const decisionTypes = db.prepare(`
    SELECT decision_type as type, COUNT(*) as count FROM kg_decisions GROUP BY decision_type ORDER BY count DESC
  `).all() as Array<{ type: string; count: number }>;

  const learningTypes = db.prepare(`
    SELECT learning_type as type, COUNT(*) as count FROM kg_learnings GROUP BY learning_type ORDER BY count DESC
  `).all() as Array<{ type: string; count: number }>;

  return {
    entities: entityCount,
    relations: relationCount,
    observations: observationCount,
    decisions: decisionCount,
    learnings: learningCount,
    entity_types: entityTypes,
    relation_types: relationTypes,
    decision_types: decisionTypes,
    learning_types: learningTypes,
  };
}
