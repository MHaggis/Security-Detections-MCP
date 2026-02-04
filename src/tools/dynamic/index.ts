/**
 * Dynamic Table MCP Tools
 * 
 * Tools that enable the LLM to create and manage custom tables at runtime,
 * providing persistent storage for analysis results, research findings,
 * and custom data structures.
 */

import { defineTool, ToolDefinition } from '../registry.js';
import {
  initDynamicSchema,
  createDynamicTable,
  getTableMetadata,
  listDynamicTables,
  dropDynamicTable,
  insertDynamicRow,
  queryDynamicTable,
  PREBUILT_TABLES,
} from '../../db/dynamic.js';
import type { DynamicColumnSchema, DynamicQueryOptions } from '../../types/dynamic.js';

// Initialize dynamic schema on module load
initDynamicSchema();

// =============================================================================
// create_table - Create a new dynamic table
// =============================================================================

const createTableTool = defineTool({
  name: 'create_table',
  description: `Create a new custom table to store analysis data. Use this to persist findings, research results, or any structured data you want to retrieve later.

Pre-built tables available: gap_analyses, source_comparisons, threat_actor_profiles, detection_recommendations`,
  inputSchema: {
    type: 'object',
    properties: {
      name: {
        type: 'string',
        description: 'Table name (alphanumeric and underscores, must start with letter). Examples: my_analysis, cve_research, custom_mappings',
      },
      description: {
        type: 'string',
        description: 'Human-readable description of what this table stores',
      },
      columns: {
        type: 'array',
        description: 'Column definitions for the table schema',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Column name' },
            type: { 
              type: 'string', 
              enum: ['TEXT', 'INTEGER', 'REAL', 'BLOB'],
              description: 'SQLite data type' 
            },
            nullable: { type: 'boolean', description: 'Allow NULL values (default: true)' },
            primary_key: { type: 'boolean', description: 'Is this the primary key?' },
            unique: { type: 'boolean', description: 'Must values be unique?' },
          },
          required: ['name', 'type'],
        },
      },
    },
    required: ['name', 'description', 'columns'],
  },
  handler: async (args) => {
    const name = args?.name as string;
    const description = args?.description as string;
    const columns = args?.columns as DynamicColumnSchema[];

    if (!name || !description || !columns || columns.length === 0) {
      return {
        error: true,
        code: 'MISSING_REQUIRED_ARG',
        message: 'name, description, and columns are all required',
      };
    }

    const result = createDynamicTable(name, columns, description);

    if (!result.success) {
      return {
        error: true,
        code: 'CREATE_FAILED',
        message: result.error,
      };
    }

    return {
      success: true,
      table_name: name,
      description,
      columns: columns.map(c => c.name),
      message: `Table '${name}' created successfully. Use insert_row to add data.`,
    };
  },
});

// =============================================================================
// insert_row - Insert data into a dynamic table
// =============================================================================

const insertRowTool = defineTool({
  name: 'insert_row',
  description: 'Insert a row of data into a dynamic table. Data is validated against the table schema.',
  inputSchema: {
    type: 'object',
    properties: {
      table_name: {
        type: 'string',
        description: 'Name of the table to insert into',
      },
      data: {
        type: 'object',
        description: 'Key-value pairs matching the table schema. Use JSON for complex values (arrays, nested objects).',
      },
      row_id: {
        type: 'string',
        description: 'Optional: Custom row ID. If not provided, a UUID is generated.',
      },
    },
    required: ['table_name', 'data'],
  },
  handler: async (args) => {
    const tableName = args?.table_name as string;
    const data = args?.data as Record<string, unknown>;
    const rowId = args?.row_id as string | undefined;

    if (!tableName || !data) {
      return {
        error: true,
        code: 'MISSING_REQUIRED_ARG',
        message: 'table_name and data are required',
      };
    }

    const result = insertDynamicRow(tableName, data, rowId);

    if (!result.success) {
      return {
        error: true,
        code: 'INSERT_FAILED',
        message: result.error,
      };
    }

    return {
      success: true,
      table_name: tableName,
      row_id: result.row_id,
      message: `Row inserted successfully into '${tableName}'`,
    };
  },
});

// =============================================================================
// query_table - Query dynamic table with filters
// =============================================================================

const queryTableTool = defineTool({
  name: 'query_table',
  description: `Query data from a dynamic table with optional filtering, sorting, and pagination.

Filter examples:
- Exact match: {"status": "completed"}
- LIKE match: {"name": "%ransomware%"}
- Multiple conditions: {"status": "pending", "priority": "high"}`,
  inputSchema: {
    type: 'object',
    properties: {
      table_name: {
        type: 'string',
        description: 'Name of the table to query',
      },
      where: {
        type: 'object',
        description: 'Filter conditions as key-value pairs. Use % for LIKE patterns.',
      },
      select: {
        type: 'array',
        items: { type: 'string' },
        description: 'Columns to return (default: all)',
      },
      order_by: {
        type: 'array',
        description: 'Sort order',
        items: {
          type: 'object',
          properties: {
            column: { type: 'string' },
            direction: { type: 'string', enum: ['ASC', 'DESC'] },
          },
        },
      },
      limit: {
        type: 'number',
        description: 'Maximum rows to return (default: 100)',
      },
      offset: {
        type: 'number',
        description: 'Number of rows to skip (for pagination)',
      },
    },
    required: ['table_name'],
  },
  handler: async (args) => {
    const tableName = args?.table_name as string;

    if (!tableName) {
      return {
        error: true,
        code: 'MISSING_REQUIRED_ARG',
        message: 'table_name is required',
      };
    }

    const options: DynamicQueryOptions = {
      where: args?.where as Record<string, unknown> | undefined,
      select: args?.select as string[] | undefined,
      order_by: args?.order_by as Array<{ column: string; direction: 'ASC' | 'DESC' }> | undefined,
      limit: args?.limit as number | undefined,
      offset: args?.offset as number | undefined,
    };

    const result = queryDynamicTable(tableName, options);

    if ('error' in result) {
      return {
        error: true,
        code: 'QUERY_FAILED',
        message: result.error,
      };
    }

    return {
      table_name: result.table_name,
      total_count: result.total_count,
      returned_count: result.rows.length,
      columns: result.columns,
      rows: result.rows,
    };
  },
});

// =============================================================================
// list_tables - List all dynamic tables
// =============================================================================

const listTablesTool = defineTool({
  name: 'list_tables',
  description: 'List all dynamic tables created by the LLM, including pre-built analysis tables and their statistics.',
  inputSchema: {
    type: 'object',
    properties: {
      include_prebuilt: {
        type: 'boolean',
        description: 'Include pre-built analysis tables in the list (default: true)',
      },
    },
  },
  handler: async (args) => {
    const includePrebuilt = args?.include_prebuilt !== false;
    
    const tables = listDynamicTables();
    const prebuiltNames = PREBUILT_TABLES.map(t => t.name);
    
    const result = includePrebuilt 
      ? tables 
      : tables.filter(t => !prebuiltNames.includes(t.name));

    const summary = {
      total_tables: result.length,
      prebuilt_tables: result.filter(t => prebuiltNames.includes(t.name)).length,
      custom_tables: result.filter(t => !prebuiltNames.includes(t.name)).length,
      total_rows: result.reduce((sum, t) => sum + t.row_count, 0),
    };

    return {
      summary,
      tables: result.map(t => ({
        name: t.name,
        description: t.description,
        row_count: t.row_count,
        columns: t.columns.map(c => c.name),
        is_prebuilt: prebuiltNames.includes(t.name),
        created_at: t.created_at,
      })),
      prebuilt_table_names: prebuiltNames,
    };
  },
});

// =============================================================================
// drop_table - Remove a dynamic table
// =============================================================================

const dropTableTool = defineTool({
  name: 'drop_table',
  description: 'Remove a dynamic table and all its data. Use with caution - this is irreversible.',
  inputSchema: {
    type: 'object',
    properties: {
      table_name: {
        type: 'string',
        description: 'Name of the table to drop',
      },
      confirm: {
        type: 'boolean',
        description: 'Must be true to confirm deletion',
      },
    },
    required: ['table_name', 'confirm'],
  },
  handler: async (args) => {
    const tableName = args?.table_name as string;
    const confirm = args?.confirm as boolean;

    if (!tableName) {
      return {
        error: true,
        code: 'MISSING_REQUIRED_ARG',
        message: 'table_name is required',
      };
    }

    if (!confirm) {
      return {
        error: true,
        code: 'CONFIRMATION_REQUIRED',
        message: 'Set confirm: true to confirm you want to delete this table and all its data',
      };
    }

    // Warn about pre-built tables
    const prebuiltNames = PREBUILT_TABLES.map(t => t.name);
    if (prebuiltNames.includes(tableName)) {
      // Allow dropping but warn - it will be recreated on next init
      console.warn(`[dynamic] Dropping pre-built table '${tableName}' - will be recreated on next startup`);
    }

    const result = dropDynamicTable(tableName);

    if (!result.success) {
      return {
        error: true,
        code: 'DROP_FAILED',
        message: result.error,
      };
    }

    return {
      success: true,
      table_name: tableName,
      rows_deleted: result.rows_deleted,
      message: `Table '${tableName}' and ${result.rows_deleted} rows deleted`,
      note: prebuiltNames.includes(tableName) 
        ? 'This pre-built table will be recreated (empty) on next server restart'
        : undefined,
    };
  },
});

// =============================================================================
// describe_table - Get schema and stats for a table
// =============================================================================

const describeTableTool = defineTool({
  name: 'describe_table',
  description: 'Get detailed schema information and statistics for a dynamic table.',
  inputSchema: {
    type: 'object',
    properties: {
      table_name: {
        type: 'string',
        description: 'Name of the table to describe',
      },
    },
    required: ['table_name'],
  },
  handler: async (args) => {
    const tableName = args?.table_name as string;

    if (!tableName) {
      return {
        error: true,
        code: 'MISSING_REQUIRED_ARG',
        message: 'table_name is required',
      };
    }

    const table = getTableMetadata(tableName);

    if (!table) {
      // Check if it's a valid pre-built table name that hasn't been created yet
      const prebuilt = PREBUILT_TABLES.find(t => t.name === tableName);
      if (prebuilt) {
        return {
          error: true,
          code: 'TABLE_NOT_INITIALIZED',
          message: `Pre-built table '${tableName}' exists but hasn't been initialized. Run list_tables to initialize all pre-built tables.`,
          prebuilt_schema: prebuilt,
        };
      }

      return {
        error: true,
        code: 'TABLE_NOT_FOUND',
        message: `Table '${tableName}' does not exist`,
        available_tables: listDynamicTables().map(t => t.name),
      };
    }

    const prebuiltNames = PREBUILT_TABLES.map(t => t.name);

    return {
      name: table.name,
      full_name: table.full_name,
      description: table.description,
      is_prebuilt: prebuiltNames.includes(table.name),
      row_count: table.row_count,
      created_at: table.created_at,
      columns: table.columns.map(col => ({
        name: col.name,
        type: col.type,
        nullable: col.nullable !== false,
        primary_key: col.primary_key || false,
        unique: col.unique || false,
        default_value: col.default_value,
      })),
      example_insert: generateExampleInsert(table.name, table.columns),
    };
  },
});

/**
 * Generate an example insert_row call for documentation.
 */
function generateExampleInsert(tableName: string, columns: DynamicColumnSchema[]): object {
  const exampleData: Record<string, unknown> = {};
  
  for (const col of columns) {
    if (col.primary_key) continue; // Skip auto-generated IDs
    
    switch (col.type) {
      case 'TEXT':
        exampleData[col.name] = col.name.includes('json') || col.name.includes('array') 
          ? '["example1", "example2"]'
          : `example_${col.name}`;
        break;
      case 'INTEGER':
        exampleData[col.name] = 42;
        break;
      case 'REAL':
        exampleData[col.name] = 0.85;
        break;
      default:
        exampleData[col.name] = `example_${col.name}`;
    }
  }
  
  return {
    tool: 'insert_row',
    args: {
      table_name: tableName,
      data: exampleData,
    },
  };
}

// =============================================================================
// Export all dynamic table tools
// =============================================================================

export const dynamicTools: ToolDefinition[] = [
  createTableTool,
  insertRowTool,
  queryTableTool,
  listTablesTool,
  dropTableTool,
  describeTableTool,
];

// Export individual tools for granular imports
export {
  createTableTool,
  insertRowTool,
  queryTableTool,
  listTablesTool,
  dropTableTool,
  describeTableTool,
};
