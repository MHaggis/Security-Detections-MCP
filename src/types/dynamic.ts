/**
 * Dynamic Table Types
 * Types for runtime-created tables that extend the schema dynamically
 * Enables user-defined data structures for custom analysis workflows
 */

/**
 * Schema definition for a dynamic table column
 */
export interface DynamicColumnSchema {
  /** Column name */
  name: string;
  /** SQLite data type: TEXT, INTEGER, REAL, BLOB */
  type: 'TEXT' | 'INTEGER' | 'REAL' | 'BLOB';
  /** Whether this column can contain NULL values */
  nullable?: boolean;
  /** Default value for the column */
  default_value?: string | number | null;
  /** Whether this column is part of the primary key */
  primary_key?: boolean;
  /** Whether values must be unique */
  unique?: boolean;
}

/**
 * Definition for creating a new dynamic table
 */
export interface DynamicTableDefinition {
  /** Name of the table (will be prefixed with dynamic_) */
  table_name: string;
  /** Human-readable description of the table's purpose */
  description: string;
  /** Column definitions */
  columns: DynamicColumnSchema[];
  /** Optional indexes to create for performance */
  indexes?: DynamicIndexDefinition[];
}

/**
 * Index definition for a dynamic table
 */
export interface DynamicIndexDefinition {
  /** Index name */
  name: string;
  /** Column names to include in the index */
  columns: string[];
  /** Whether the index enforces uniqueness */
  unique?: boolean;
}

/**
 * Metadata about an existing dynamic table
 */
export interface DynamicTable {
  /** Table name (without dynamic_ prefix) */
  name: string;
  /** Full table name in SQLite */
  full_name: string;
  /** Table description */
  description: string;
  /** Column schemas */
  columns: DynamicColumnSchema[];
  /** Number of rows in the table */
  row_count: number;
  /** ISO timestamp when table was created */
  created_at: string;
  /** ISO timestamp when table was last modified */
  modified_at: string;
}

/**
 * A row in a dynamic table - flexible key-value structure
 */
export interface DynamicRow {
  /** Auto-generated row ID */
  _id?: number;
  /** Flexible fields based on table schema */
  [key: string]: unknown;
}

/**
 * Result of a dynamic table query
 */
export interface DynamicQueryResult {
  /** Table that was queried */
  table_name: string;
  /** Rows returned */
  rows: DynamicRow[];
  /** Total count matching the query (before LIMIT) */
  total_count: number;
  /** Columns in the result set */
  columns: string[];
}

/**
 * Options for querying a dynamic table
 */
export interface DynamicQueryOptions {
  /** Columns to select (default: all) */
  select?: string[];
  /** WHERE conditions as key-value pairs (AND logic) */
  where?: Record<string, unknown>;
  /** Raw WHERE clause for complex conditions */
  where_raw?: string;
  /** ORDER BY columns */
  order_by?: { column: string; direction: 'ASC' | 'DESC' }[];
  /** Maximum rows to return */
  limit?: number;
  /** Number of rows to skip */
  offset?: number;
}

/**
 * Options for inserting into a dynamic table
 */
export interface DynamicInsertOptions {
  /** Whether to replace on conflict (UPSERT behavior) */
  replace_on_conflict?: boolean;
  /** Return the inserted row(s) */
  return_inserted?: boolean;
}
