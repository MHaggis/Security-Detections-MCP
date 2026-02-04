/**
 * Cache Database Module
 * 
 * Saved queries and results caching functionality.
 */

import { getDb } from './connection.js';
import { createSavedQueriesTable } from './schema.js';

// Track if saved queries table has been initialized
let savedQueriesTableInitialized = false;

/**
 * Ensure the saved queries table exists.
 */
function ensureSavedQueriesTable(): void {
  if (savedQueriesTableInitialized) return;
  
  const database = getDb();
  createSavedQueriesTable(database);
  savedQueriesTableInitialized = true;
}

/**
 * Initialize the saved queries table.
 * Called automatically when needed.
 */
export function initSavedQueriesTable(): void {
  ensureSavedQueriesTable();
}

/**
 * Save a query result to the cache.
 * 
 * @param name - Unique name for the saved query
 * @param queryType - Type of query (e.g., 'search', 'coverage', 'gaps')
 * @param queryParams - Parameters used for the query
 * @param result - The result to cache
 * @param ttlMinutes - Optional time-to-live in minutes
 * @returns The generated ID for the saved query
 */
export function saveQueryResult(
  name: string,
  queryType: string,
  queryParams: Record<string, unknown>,
  result: unknown,
  ttlMinutes?: number
): string {
  ensureSavedQueriesTable();
  
  const database = getDb();
  
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

/**
 * Get a saved query result by name.
 * Returns null if not found or expired.
 * 
 * @param name - Name of the saved query
 * @returns The cached result or null
 */
export function getSavedQuery(name: string): unknown | null {
  ensureSavedQueriesTable();
  
  const database = getDb();
  
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

/**
 * List all saved queries, optionally filtered by type.
 * 
 * @param queryType - Optional filter by query type
 * @returns Array of saved query metadata
 */
export function listSavedQueries(queryType?: string): Array<{ id: string; name: string; query_type: string; created_at: string }> {
  ensureSavedQueriesTable();
  
  const database = getDb();
  
  let sql = 'SELECT id, name, query_type, created_at FROM saved_queries';
  const params: string[] = [];
  
  if (queryType) {
    sql += ' WHERE query_type = ?';
    params.push(queryType);
  }
  
  sql += ' ORDER BY created_at DESC LIMIT 50';
  
  return database.prepare(sql).all(...params) as Array<{ id: string; name: string; query_type: string; created_at: string }>;
}

/**
 * Delete a saved query by name.
 * 
 * @param name - Name of the saved query to delete
 * @returns True if a query was deleted, false otherwise
 */
export function deleteSavedQuery(name: string): boolean {
  ensureSavedQueriesTable();
  
  const database = getDb();
  
  const result = database.prepare('DELETE FROM saved_queries WHERE name = ?').run(name);
  return result.changes > 0;
}

/**
 * Delete all expired saved queries.
 * 
 * @returns Number of queries deleted
 */
export function cleanupExpiredQueries(): number {
  ensureSavedQueriesTable();
  
  const database = getDb();
  
  const result = database.prepare(`
    DELETE FROM saved_queries 
    WHERE expires_at IS NOT NULL AND expires_at < datetime('now')
  `).run();
  
  return result.changes;
}

/**
 * Get a saved query result by ID.
 * 
 * @param id - ID of the saved query
 * @returns The cached result or null
 */
export function getSavedQueryById(id: string): unknown | null {
  ensureSavedQueriesTable();
  
  const database = getDb();
  
  const stmt = database.prepare(`
    SELECT result_json, expires_at FROM saved_queries 
    WHERE id = ?
  `);
  
  const row = stmt.get(id) as { result_json: string; expires_at: string | null } | undefined;
  
  if (!row) return null;
  
  // Check expiry
  if (row.expires_at && new Date(row.expires_at) < new Date()) {
    return null;
  }
  
  return JSON.parse(row.result_json);
}
