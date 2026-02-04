/**
 * Stories Database Module
 * 
 * CRUD operations for analytic stories (Splunk ESCU stories).
 */

import type { AnalyticStory } from '../types.js';
import { getDb } from './connection.js';

// =============================================================================
// INTERNAL HELPERS
// =============================================================================

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

// =============================================================================
// CRUD OPERATIONS
// =============================================================================

/**
 * Insert or replace a story in the database.
 */
export function insertStory(story: AnalyticStory): void {
  const database = getDb();
  
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

/**
 * Get a story by its name.
 */
export function getStoryByName(name: string): AnalyticStory | null {
  const database = getDb();
  
  const stmt = database.prepare('SELECT * FROM stories WHERE name = ?');
  const row = stmt.get(name) as Record<string, unknown> | undefined;
  
  return row ? rowToStory(row) : null;
}

/**
 * Get a story by its ID.
 */
export function getStoryById(id: string): AnalyticStory | null {
  const database = getDb();
  
  const stmt = database.prepare('SELECT * FROM stories WHERE id = ?');
  const row = stmt.get(id) as Record<string, unknown> | undefined;
  
  return row ? rowToStory(row) : null;
}

/**
 * Get the total count of stories.
 */
export function getStoryCount(): number {
  const database = getDb();
  try {
    return (database.prepare('SELECT COUNT(*) as count FROM stories').get() as { count: number }).count;
  } catch {
    return 0;
  }
}

// =============================================================================
// SEARCH AND LIST OPERATIONS
// =============================================================================

/**
 * Full-text search across stories.
 */
export function searchStories(query: string, limit: number = 20): AnalyticStory[] {
  const database = getDb();
  
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

/**
 * List stories with pagination.
 */
export function listStories(limit: number = 100, offset: number = 0): AnalyticStory[] {
  const database = getDb();
  
  try {
    const stmt = database.prepare('SELECT * FROM stories ORDER BY name LIMIT ? OFFSET ?');
    const rows = stmt.all(limit, offset) as Record<string, unknown>[];
    return rows.map(rowToStory);
  } catch {
    return [];
  }
}

/**
 * List stories filtered by category.
 */
export function listStoriesByCategory(category: string, limit: number = 100, offset: number = 0): AnalyticStory[] {
  const database = getDb();
  
  try {
    const stmt = database.prepare('SELECT * FROM stories WHERE category = ? ORDER BY name LIMIT ? OFFSET ?');
    const rows = stmt.all(category, limit, offset) as Record<string, unknown>[];
    return rows.map(rowToStory);
  } catch {
    return [];
  }
}
