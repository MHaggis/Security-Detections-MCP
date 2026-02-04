/**
 * Dynamic Table Database Operations
 * 
 * Provides database operations for runtime-created tables that allow the LLM
 * to store and retrieve custom data structures persistently.
 */

import { getDb } from './connection.js';
import type {
  DynamicTable,
  DynamicRow,
  DynamicQueryResult,
  DynamicQueryOptions,
  DynamicColumnSchema,
} from '../types/dynamic.js';
import { randomUUID } from 'crypto';

// =============================================================================
// Schema Creation
// =============================================================================

/**
 * Initialize the dynamic tables schema.
 * Creates the metadata tables if they don't exist.
 */
export function initDynamicSchema(): void {
  const db = getDb();
  
  // Table to track all dynamic tables and their schemas
  db.exec(`
    CREATE TABLE IF NOT EXISTS dynamic_tables (
      name TEXT PRIMARY KEY,
      schema TEXT NOT NULL,
      created_by TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      description TEXT,
      row_count INTEGER DEFAULT 0
    )
  `);
  
  // Table to store actual data (JSON-based storage)
  db.exec(`
    CREATE TABLE IF NOT EXISTS dynamic_data (
      table_name TEXT NOT NULL,
      row_id TEXT NOT NULL,
      data TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (table_name, row_id)
    )
  `);
  
  // Index for faster queries on table_name
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_dynamic_data_table 
    ON dynamic_data(table_name)
  `);
  
  // Auto-create pre-built analysis tables
  initPrebuiltTables();
}

/**
 * Pre-built table schemas for common analysis workflows.
 */
const PREBUILT_TABLES: Array<{
  name: string;
  description: string;
  schema: DynamicColumnSchema[];
}> = [
  {
    name: 'gap_analyses',
    description: 'Store gap analysis results including technique coverage, missing detections, and recommendations',
    schema: [
      { name: 'id', type: 'TEXT', primary_key: true },
      { name: 'name', type: 'TEXT' },
      { name: 'threat_profile', type: 'TEXT' },
      { name: 'total_techniques', type: 'INTEGER' },
      { name: 'covered_techniques', type: 'INTEGER' },
      { name: 'coverage_percentage', type: 'REAL' },
      { name: 'gaps', type: 'TEXT' }, // JSON array of technique IDs
      { name: 'recommendations', type: 'TEXT' }, // JSON array
      { name: 'created_at', type: 'TEXT' },
    ],
  },
  {
    name: 'source_comparisons',
    description: 'Store detection source comparison results (Sigma vs Splunk vs Elastic)',
    schema: [
      { name: 'id', type: 'TEXT', primary_key: true },
      { name: 'name', type: 'TEXT' },
      { name: 'sources_compared', type: 'TEXT' }, // JSON array
      { name: 'technique_id', type: 'TEXT' },
      { name: 'common_detections', type: 'INTEGER' },
      { name: 'source_specific', type: 'TEXT' }, // JSON object
      { name: 'analysis_notes', type: 'TEXT' },
      { name: 'created_at', type: 'TEXT' },
    ],
  },
  {
    name: 'threat_actor_profiles',
    description: 'Store threat actor research including TTPs, campaigns, and detection mappings',
    schema: [
      { name: 'id', type: 'TEXT', primary_key: true },
      { name: 'actor_name', type: 'TEXT' },
      { name: 'aliases', type: 'TEXT' }, // JSON array
      { name: 'mitre_group_id', type: 'TEXT' },
      { name: 'primary_ttps', type: 'TEXT' }, // JSON array of technique IDs
      { name: 'campaigns', type: 'TEXT' }, // JSON array
      { name: 'detection_coverage', type: 'REAL' },
      { name: 'detection_ids', type: 'TEXT' }, // JSON array of detection IDs
      { name: 'notes', type: 'TEXT' },
      { name: 'created_at', type: 'TEXT' },
    ],
  },
  {
    name: 'detection_recommendations',
    description: 'Store detection recommendations and their implementation status',
    schema: [
      { name: 'id', type: 'TEXT', primary_key: true },
      { name: 'technique_id', type: 'TEXT' },
      { name: 'technique_name', type: 'TEXT' },
      { name: 'priority', type: 'TEXT' }, // high, medium, low
      { name: 'recommendation_type', type: 'TEXT' }, // new_detection, enhancement, data_source
      { name: 'description', type: 'TEXT' },
      { name: 'implementation_notes', type: 'TEXT' },
      { name: 'status', type: 'TEXT' }, // pending, in_progress, completed, rejected
      { name: 'related_gap_analysis_id', type: 'TEXT' },
      { name: 'created_at', type: 'TEXT' },
    ],
  },
];

/**
 * Initialize pre-built tables for common analysis patterns.
 */
function initPrebuiltTables(): void {
  for (const table of PREBUILT_TABLES) {
    // Check if table already exists
    const existing = getTableMetadata(table.name);
    if (!existing) {
      createDynamicTable(table.name, table.schema, table.description, 'system');
    }
  }
}

// =============================================================================
// Table Management
// =============================================================================

/**
 * Create a new dynamic table.
 */
export function createDynamicTable(
  name: string,
  schema: DynamicColumnSchema[],
  description: string,
  createdBy?: string
): { success: boolean; error?: string } {
  const db = getDb();
  
  // Validate table name (alphanumeric and underscores only)
  if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(name)) {
    return {
      success: false,
      error: 'Table name must start with a letter and contain only letters, numbers, and underscores',
    };
  }
  
  // Check if table already exists
  const existing = getTableMetadata(name);
  if (existing) {
    return { success: false, error: `Table '${name}' already exists` };
  }
  
  // Insert table metadata
  const stmt = db.prepare(`
    INSERT INTO dynamic_tables (name, schema, description, created_by, created_at, row_count)
    VALUES (?, ?, ?, ?, datetime('now'), 0)
  `);
  
  stmt.run(name, JSON.stringify(schema), description, createdBy || 'llm');
  
  return { success: true };
}

/**
 * Get metadata for a dynamic table.
 */
export function getTableMetadata(name: string): DynamicTable | null {
  const db = getDb();
  
  const row = db.prepare(`
    SELECT name, schema, description, created_at, row_count
    FROM dynamic_tables
    WHERE name = ?
  `).get(name) as { name: string; schema: string; description: string; created_at: string; row_count: number } | undefined;
  
  if (!row) return null;
  
  return {
    name: row.name,
    full_name: `dynamic_${row.name}`,
    description: row.description,
    columns: JSON.parse(row.schema) as DynamicColumnSchema[],
    row_count: row.row_count,
    created_at: row.created_at,
    modified_at: row.created_at, // We could track this separately
  };
}

/**
 * List all dynamic tables.
 */
export function listDynamicTables(): DynamicTable[] {
  const db = getDb();
  
  const rows = db.prepare(`
    SELECT name, schema, description, created_at, row_count
    FROM dynamic_tables
    ORDER BY created_at DESC
  `).all() as Array<{ name: string; schema: string; description: string; created_at: string; row_count: number }>;
  
  return rows.map(row => ({
    name: row.name,
    full_name: `dynamic_${row.name}`,
    description: row.description,
    columns: JSON.parse(row.schema) as DynamicColumnSchema[],
    row_count: row.row_count,
    created_at: row.created_at,
    modified_at: row.created_at,
  }));
}

/**
 * Drop a dynamic table and all its data.
 */
export function dropDynamicTable(name: string): { success: boolean; error?: string; rows_deleted?: number } {
  const db = getDb();
  
  // Check if table exists
  const existing = getTableMetadata(name);
  if (!existing) {
    return { success: false, error: `Table '${name}' does not exist` };
  }
  
  // Delete all data first
  const deleteData = db.prepare('DELETE FROM dynamic_data WHERE table_name = ?');
  const dataResult = deleteData.run(name);
  
  // Delete table metadata
  const deleteMeta = db.prepare('DELETE FROM dynamic_tables WHERE name = ?');
  deleteMeta.run(name);
  
  return { success: true, rows_deleted: dataResult.changes };
}

// =============================================================================
// Data Operations
// =============================================================================

/**
 * Insert a row into a dynamic table.
 */
export function insertDynamicRow(
  tableName: string,
  data: Record<string, unknown>,
  rowId?: string
): { success: boolean; row_id?: string; error?: string } {
  const db = getDb();
  
  // Check if table exists
  const table = getTableMetadata(tableName);
  if (!table) {
    return { success: false, error: `Table '${tableName}' does not exist` };
  }
  
  // Validate data against schema (basic validation)
  const validationError = validateDataAgainstSchema(data, table.columns);
  if (validationError) {
    return { success: false, error: validationError };
  }
  
  // Generate row ID if not provided
  const id = rowId || randomUUID();
  
  // Insert the row
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO dynamic_data (table_name, row_id, data, created_at)
    VALUES (?, ?, ?, datetime('now'))
  `);
  
  stmt.run(tableName, id, JSON.stringify(data));
  
  // Update row count
  updateRowCount(tableName);
  
  return { success: true, row_id: id };
}

/**
 * Insert multiple rows into a dynamic table.
 */
export function insertDynamicRows(
  tableName: string,
  rows: Array<{ data: Record<string, unknown>; row_id?: string }>
): { success: boolean; inserted: number; errors: string[] } {
  const db = getDb();
  const errors: string[] = [];
  let inserted = 0;
  
  // Check if table exists
  const table = getTableMetadata(tableName);
  if (!table) {
    return { success: false, inserted: 0, errors: [`Table '${tableName}' does not exist`] };
  }
  
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO dynamic_data (table_name, row_id, data, created_at)
    VALUES (?, ?, ?, datetime('now'))
  `);
  
  const insertMany = db.transaction((rows: Array<{ data: Record<string, unknown>; row_id?: string }>) => {
    for (const row of rows) {
      const validationError = validateDataAgainstSchema(row.data, table.columns);
      if (validationError) {
        errors.push(`Row ${row.row_id || 'unknown'}: ${validationError}`);
        continue;
      }
      
      const id = row.row_id || randomUUID();
      stmt.run(tableName, id, JSON.stringify(row.data));
      inserted++;
    }
  });
  
  insertMany(rows);
  
  // Update row count
  updateRowCount(tableName);
  
  return { success: errors.length === 0, inserted, errors };
}

/**
 * Query rows from a dynamic table.
 */
export function queryDynamicTable(
  tableName: string,
  options: DynamicQueryOptions = {}
): DynamicQueryResult | { error: string } {
  const db = getDb();
  
  // Check if table exists
  const table = getTableMetadata(tableName);
  if (!table) {
    return { error: `Table '${tableName}' does not exist` };
  }
  
  // Build WHERE clause
  const whereClauses: string[] = ['table_name = ?'];
  const params: unknown[] = [tableName];
  
  if (options.where) {
    for (const [field, value] of Object.entries(options.where)) {
      if (typeof value === 'string' && value.includes('%')) {
        // LIKE query
        whereClauses.push(`json_extract(data, '$.${field}') LIKE ?`);
        params.push(value);
      } else {
        // Exact match
        whereClauses.push(`json_extract(data, '$.${field}') = ?`);
        params.push(value);
      }
    }
  }
  
  if (options.where_raw) {
    whereClauses.push(`(${options.where_raw})`);
  }
  
  const whereClause = whereClauses.join(' AND ');
  
  // Get total count first
  const countStmt = db.prepare(`
    SELECT COUNT(*) as count FROM dynamic_data WHERE ${whereClause}
  `);
  const countResult = countStmt.get(...params) as { count: number };
  
  // Build ORDER BY
  let orderBy = 'created_at DESC';
  if (options.order_by && options.order_by.length > 0) {
    orderBy = options.order_by
      .map(o => `json_extract(data, '$.${o.column}') ${o.direction}`)
      .join(', ');
  }
  
  // Build LIMIT and OFFSET
  const limit = options.limit || 100;
  const offset = options.offset || 0;
  
  // Execute query
  const queryStmt = db.prepare(`
    SELECT row_id, data, created_at 
    FROM dynamic_data 
    WHERE ${whereClause}
    ORDER BY ${orderBy}
    LIMIT ? OFFSET ?
  `);
  
  const rows = queryStmt.all(...params, limit, offset) as Array<{
    row_id: string;
    data: string;
    created_at: string;
  }>;
  
  // Parse and filter columns if specified
  const parsedRows: DynamicRow[] = rows.map(row => {
    const data = JSON.parse(row.data) as DynamicRow;
    data._id = row.row_id as unknown as number; // Store row_id as _id
    
    if (options.select && options.select.length > 0) {
      const filtered: DynamicRow = { _id: data._id };
      for (const col of options.select) {
        if (col in data) {
          filtered[col] = data[col];
        }
      }
      return filtered;
    }
    
    return data;
  });
  
  return {
    table_name: tableName,
    rows: parsedRows,
    total_count: countResult.count,
    columns: table.columns.map(c => c.name),
  };
}

/**
 * Delete rows from a dynamic table.
 */
export function deleteDynamicRows(
  tableName: string,
  rowIds: string[]
): { success: boolean; deleted: number; error?: string } {
  const db = getDb();
  
  // Check if table exists
  const table = getTableMetadata(tableName);
  if (!table) {
    return { success: false, deleted: 0, error: `Table '${tableName}' does not exist` };
  }
  
  if (rowIds.length === 0) {
    return { success: true, deleted: 0 };
  }
  
  const placeholders = rowIds.map(() => '?').join(', ');
  const stmt = db.prepare(`
    DELETE FROM dynamic_data 
    WHERE table_name = ? AND row_id IN (${placeholders})
  `);
  
  const result = stmt.run(tableName, ...rowIds);
  
  // Update row count
  updateRowCount(tableName);
  
  return { success: true, deleted: result.changes };
}

/**
 * Get a single row by ID.
 */
export function getDynamicRow(
  tableName: string,
  rowId: string
): DynamicRow | { error: string } {
  const db = getDb();
  
  // Check if table exists
  const table = getTableMetadata(tableName);
  if (!table) {
    return { error: `Table '${tableName}' does not exist` };
  }
  
  const row = db.prepare(`
    SELECT row_id, data, created_at
    FROM dynamic_data
    WHERE table_name = ? AND row_id = ?
  `).get(tableName, rowId) as { row_id: string; data: string; created_at: string } | undefined;
  
  if (!row) {
    return { error: `Row '${rowId}' not found in table '${tableName}'` };
  }
  
  const data = JSON.parse(row.data) as DynamicRow;
  data._id = row.row_id as unknown as number;
  
  return data;
}

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Validate data against a table schema (basic validation).
 */
function validateDataAgainstSchema(
  data: Record<string, unknown>,
  schema: DynamicColumnSchema[]
): string | null {
  for (const column of schema) {
    const value = data[column.name];
    
    // Check required (non-nullable) fields
    if (!column.nullable && column.default_value === undefined) {
      if (value === undefined || value === null) {
        // Primary keys can be auto-generated
        if (!column.primary_key) {
          return `Missing required field: ${column.name}`;
        }
      }
    }
    
    // Type validation (basic)
    if (value !== undefined && value !== null) {
      const valueType = typeof value;
      switch (column.type) {
        case 'INTEGER':
          if (valueType !== 'number' || !Number.isInteger(value)) {
            // Allow string integers
            if (valueType !== 'string' || isNaN(parseInt(value as string, 10))) {
              return `Field '${column.name}' must be an integer`;
            }
          }
          break;
        case 'REAL':
          if (valueType !== 'number') {
            // Allow string numbers
            if (valueType !== 'string' || isNaN(parseFloat(value as string))) {
              return `Field '${column.name}' must be a number`;
            }
          }
          break;
        case 'TEXT':
          // TEXT can accept any type (will be stringified)
          break;
        case 'BLOB':
          // BLOB can accept any type
          break;
      }
    }
  }
  
  return null;
}

/**
 * Update the row count for a table.
 */
function updateRowCount(tableName: string): void {
  const db = getDb();
  
  const countResult = db.prepare(`
    SELECT COUNT(*) as count FROM dynamic_data WHERE table_name = ?
  `).get(tableName) as { count: number };
  
  db.prepare(`
    UPDATE dynamic_tables SET row_count = ? WHERE name = ?
  `).run(countResult.count, tableName);
}

// =============================================================================
// Exports
// =============================================================================

export {
  PREBUILT_TABLES,
};
