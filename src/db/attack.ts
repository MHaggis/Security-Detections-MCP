/**
 * ATT&CK Data Access Layer
 *
 * Query functions for MITRE ATT&CK STIX-sourced data:
 * threat actors, software, technique coverage, and actor-based gap analysis.
 */

import { getDb } from './connection.js';
import { safeJsonParse } from '../utils/helpers.js';

// =============================================================================
// TYPES
// =============================================================================

export interface AttackActor {
  actor_id: string;
  name: string;
  aliases: string[];
  description: string | null;
  external_references: unknown[];
  created: string | null;
  modified: string | null;
}

export interface AttackTechnique {
  technique_id: string;
  name: string;
  description: string | null;
  platforms: string[];
  data_sources: string[];
  is_subtechnique: boolean;
  parent_technique_id: string | null;
  url: string | null;
}

export interface AttackSoftware {
  software_id: string;
  name: string;
  software_type: string;
  description: string | null;
  platforms: string[];
  aliases: string[];
}

export interface ActorTechnique {
  technique_id: string;
  technique_name: string;
  description: string | null;
  detection_count: number;
  tactics: string[];
}

export interface ActorCoverageResult {
  actor: AttackActor;
  total_techniques: number;
  covered_count: number;
  gap_count: number;
  coverage_percentage: number;
  covered_techniques: ActorTechnique[];
  gap_techniques: ActorTechnique[];
  by_tactic: Record<string, { total: number; covered: number; percentage: number }>;
}

export interface ActorListItem {
  actor_id: string;
  name: string;
  aliases: string[];
  technique_count: number;
}

// =============================================================================
// HELPERS
// =============================================================================

function rowToActor(row: Record<string, unknown>): AttackActor {
  return {
    actor_id: row.actor_id as string,
    name: row.name as string,
    aliases: safeJsonParse<string[]>(row.aliases as string, []),
    description: (row.description as string) || null,
    external_references: safeJsonParse<unknown[]>(row.external_references as string, []),
    created: (row.created as string) || null,
    modified: (row.modified as string) || null,
  };
}

function rowToTechnique(row: Record<string, unknown>): AttackTechnique {
  return {
    technique_id: row.technique_id as string,
    name: row.name as string,
    description: (row.description as string) || null,
    platforms: safeJsonParse<string[]>(row.platforms as string, []),
    data_sources: safeJsonParse<string[]>(row.data_sources as string, []),
    is_subtechnique: (row.is_subtechnique as number) === 1,
    parent_technique_id: (row.parent_technique_id as string) || null,
    url: (row.url as string) || null,
  };
}

function rowToSoftware(row: Record<string, unknown>): AttackSoftware {
  return {
    software_id: row.software_id as string,
    name: row.name as string,
    software_type: (row.software_type as string) || 'unknown',
    description: (row.description as string) || null,
    platforms: safeJsonParse<string[]>(row.platforms as string, []),
    aliases: safeJsonParse<string[]>(row.aliases as string, []),
  };
}

// =============================================================================
// QUERY FUNCTIONS
// =============================================================================

/**
 * Check if STIX data has been loaded into the database.
 */
export function isStixLoaded(): boolean {
  try {
    const row = getDb().prepare('SELECT COUNT(*) as count FROM attack_actors').get() as { count: number };
    return row.count > 0;
  } catch {
    return false;
  }
}

/**
 * Find a threat actor by name or alias (case-insensitive).
 */
export function getActorByName(name: string): AttackActor | null {
  const database = getDb();

  // Try exact name match first
  let row = database.prepare(
    'SELECT * FROM attack_actors WHERE name = ? COLLATE NOCASE'
  ).get(name) as Record<string, unknown> | undefined;

  if (row) return rowToActor(row);

  // Try alias match
  row = database.prepare(
    "SELECT * FROM attack_actors WHERE aliases LIKE ? COLLATE NOCASE"
  ).get(`%"${name}"%`) as Record<string, unknown> | undefined;

  if (row) return rowToActor(row);

  // Try partial name match
  row = database.prepare(
    'SELECT * FROM attack_actors WHERE name LIKE ? COLLATE NOCASE'
  ).get(`%${name}%`) as Record<string, unknown> | undefined;

  return row ? rowToActor(row) : null;
}

/**
 * List all threat actors, optionally filtered by search term.
 */
export function listActors(search?: string, limit: number = 100): ActorListItem[] {
  const database = getDb();

  let query: string;
  let params: unknown[];

  if (search) {
    query = `
      SELECT a.*, COUNT(at.technique_id) as technique_count
      FROM attack_actors a
      LEFT JOIN actor_techniques at ON a.actor_id = at.actor_id
      WHERE a.name LIKE ? COLLATE NOCASE OR a.aliases LIKE ? COLLATE NOCASE
      GROUP BY a.actor_id
      ORDER BY technique_count DESC
      LIMIT ?
    `;
    params = [`%${search}%`, `%${search}%`, limit];
  } else {
    query = `
      SELECT a.*, COUNT(at.technique_id) as technique_count
      FROM attack_actors a
      LEFT JOIN actor_techniques at ON a.actor_id = at.actor_id
      GROUP BY a.actor_id
      ORDER BY technique_count DESC
      LIMIT ?
    `;
    params = [limit];
  }

  const rows = database.prepare(query).all(...params) as Array<Record<string, unknown>>;
  return rows.map(row => ({
    actor_id: row.actor_id as string,
    name: row.name as string,
    aliases: safeJsonParse<string[]>(row.aliases as string, []),
    technique_count: (row.technique_count as number) || 0,
  }));
}

/**
 * Get all techniques used by a specific actor, with detection coverage info.
 */
export function getActorTechniques(actorId: string): ActorTechnique[] {
  const database = getDb();

  const rows = database.prepare(`
    SELECT
      at.technique_id,
      COALESCE(atk.name, at.technique_id) as technique_name,
      at.description,
      COUNT(dt.detection_id) as detection_count
    FROM actor_techniques at
    LEFT JOIN attack_techniques atk ON at.technique_id = atk.technique_id
    LEFT JOIN detection_techniques dt ON at.technique_id = dt.technique_id
    WHERE at.actor_id = ?
    GROUP BY at.technique_id
    ORDER BY detection_count DESC
  `).all(actorId) as Array<Record<string, unknown>>;

  // Get tactics for each technique
  return rows.map(row => {
    const techId = row.technique_id as string;
    const tacticRows = database.prepare(
      'SELECT tactic_name FROM technique_tactics WHERE technique_id = ?'
    ).all(techId) as Array<{ tactic_name: string }>;

    return {
      technique_id: techId,
      technique_name: row.technique_name as string,
      description: (row.description as string) || null,
      detection_count: (row.detection_count as number) || 0,
      tactics: tacticRows.map(r => r.tactic_name),
    };
  });
}

/**
 * Get full detection coverage analysis for a threat actor.
 */
export function getActorCoverage(actorId: string, sourceType?: string): ActorCoverageResult {
  const database = getDb();

  // Get the actor
  const actorRow = database.prepare(
    'SELECT * FROM attack_actors WHERE actor_id = ?'
  ).get(actorId) as Record<string, unknown>;

  if (!actorRow) {
    throw new Error(`Actor not found: ${actorId}`);
  }

  const actor = rowToActor(actorRow);

  // Get all techniques for this actor with detection counts
  let detectionCountQuery: string;
  let queryParams: unknown[];

  if (sourceType) {
    detectionCountQuery = `
      SELECT
        at.technique_id,
        COALESCE(atk.name, at.technique_id) as technique_name,
        at.description,
        COUNT(d.id) as detection_count
      FROM actor_techniques at
      LEFT JOIN attack_techniques atk ON at.technique_id = atk.technique_id
      LEFT JOIN detection_techniques dt ON at.technique_id = dt.technique_id
      LEFT JOIN detections d ON dt.detection_id = d.id AND dt.source_type = d.source_type AND d.source_type = ?
      WHERE at.actor_id = ?
      GROUP BY at.technique_id
      ORDER BY detection_count DESC
    `;
    queryParams = [sourceType, actorId];
  } else {
    detectionCountQuery = `
      SELECT
        at.technique_id,
        COALESCE(atk.name, at.technique_id) as technique_name,
        at.description,
        COUNT(dt.detection_id) as detection_count
      FROM actor_techniques at
      LEFT JOIN attack_techniques atk ON at.technique_id = atk.technique_id
      LEFT JOIN detection_techniques dt ON at.technique_id = dt.technique_id
      WHERE at.actor_id = ?
      GROUP BY at.technique_id
      ORDER BY detection_count DESC
    `;
    queryParams = [actorId];
  }

  const rows = database.prepare(detectionCountQuery).all(...queryParams) as Array<Record<string, unknown>>;

  const covered: ActorTechnique[] = [];
  const gaps: ActorTechnique[] = [];
  const byTactic: Record<string, { total: number; covered: number; percentage: number }> = {};

  for (const row of rows) {
    const techId = row.technique_id as string;
    const detectionCount = (row.detection_count as number) || 0;

    // Get tactics for this technique
    const tacticRows = database.prepare(
      'SELECT tactic_name FROM technique_tactics WHERE technique_id = ?'
    ).all(techId) as Array<{ tactic_name: string }>;
    const tactics = tacticRows.map(r => r.tactic_name);

    const entry: ActorTechnique = {
      technique_id: techId,
      technique_name: row.technique_name as string,
      description: (row.description as string) || null,
      detection_count: detectionCount,
      tactics,
    };

    if (detectionCount > 0) {
      covered.push(entry);
    } else {
      gaps.push(entry);
    }

    // Aggregate by tactic
    for (const tactic of tactics) {
      if (!byTactic[tactic]) {
        byTactic[tactic] = { total: 0, covered: 0, percentage: 0 };
      }
      byTactic[tactic].total++;
      if (detectionCount > 0) {
        byTactic[tactic].covered++;
      }
    }
  }

  // Calculate percentages
  for (const tactic of Object.keys(byTactic)) {
    byTactic[tactic].percentage = byTactic[tactic].total > 0
      ? Math.round((byTactic[tactic].covered / byTactic[tactic].total) * 100)
      : 0;
  }

  const totalTechniques = rows.length;
  const coveragePercentage = totalTechniques > 0
    ? Math.round((covered.length / totalTechniques) * 100)
    : 0;

  return {
    actor,
    total_techniques: totalTechniques,
    covered_count: covered.length,
    gap_count: gaps.length,
    coverage_percentage: coveragePercentage,
    covered_techniques: covered,
    gap_techniques: gaps,
    by_tactic: byTactic,
  };
}

/**
 * Get all software used by a specific actor.
 */
export function getSoftwareForActor(actorId: string): AttackSoftware[] {
  const database = getDb();

  // STIX models actor→software as "uses" relationships too,
  // but we only stored actor→technique and software→technique.
  // So we find software that shares techniques with this actor.
  const rows = database.prepare(`
    SELECT DISTINCT s.*
    FROM attack_software s
    JOIN software_techniques st ON s.software_id = st.software_id
    WHERE st.technique_id IN (
      SELECT technique_id FROM actor_techniques WHERE actor_id = ?
    )
    ORDER BY s.name
  `).all(actorId) as Array<Record<string, unknown>>;

  return rows.map(rowToSoftware);
}

/**
 * Get all threat actors that use a specific technique.
 */
export function getTechniqueActors(techniqueId: string): AttackActor[] {
  const database = getDb();

  const rows = database.prepare(`
    SELECT a.*
    FROM attack_actors a
    JOIN actor_techniques at ON a.actor_id = at.actor_id
    WHERE at.technique_id = ?
    ORDER BY a.name
  `).all(techniqueId) as Array<Record<string, unknown>>;

  return rows.map(rowToActor);
}

/**
 * Get a technique from the ATT&CK catalog.
 */
export function getAttackTechnique(techniqueId: string): AttackTechnique | null {
  const database = getDb();

  const row = database.prepare(
    'SELECT * FROM attack_techniques WHERE technique_id = ?'
  ).get(techniqueId) as Record<string, unknown> | undefined;

  return row ? rowToTechnique(row) : null;
}

/**
 * Get total counts for ATT&CK data.
 */
export function getAttackStats(): {
  techniques: number;
  actors: number;
  software: number;
  actor_technique_links: number;
  software_technique_links: number;
} {
  const database = getDb();

  try {
    const techniques = (database.prepare('SELECT COUNT(*) as c FROM attack_techniques').get() as { c: number }).c;
    const actors = (database.prepare('SELECT COUNT(*) as c FROM attack_actors').get() as { c: number }).c;
    const software = (database.prepare('SELECT COUNT(*) as c FROM attack_software').get() as { c: number }).c;
    const actorLinks = (database.prepare('SELECT COUNT(*) as c FROM actor_techniques').get() as { c: number }).c;
    const swLinks = (database.prepare('SELECT COUNT(*) as c FROM software_techniques').get() as { c: number }).c;

    return {
      techniques,
      actors,
      software,
      actor_technique_links: actorLinks,
      software_technique_links: swLinks,
    };
  } catch {
    return { techniques: 0, actors: 0, software: 0, actor_technique_links: 0, software_technique_links: 0 };
  }
}
