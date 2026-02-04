// src/tools/meta/index.ts
// Meta-Tools: Self-extending tool system for query templates and reusable shortcuts

import { defineTool, ToolDefinition } from '../registry.js';
import { getDb } from '../../db/connection.js';

// =============================================================================
// Schema Initialization - Create query_templates table if not exists
// =============================================================================

/**
 * Initialize the query_templates table for storing reusable templates.
 * Called automatically when any meta tool is used.
 */
function ensureTemplateSchema(): void {
  const db = getDb();
  db.exec(`
    CREATE TABLE IF NOT EXISTS query_templates (
      name TEXT PRIMARY KEY,
      description TEXT,
      template TEXT NOT NULL,
      parameters TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      use_count INTEGER DEFAULT 0
    )
  `);
}

// =============================================================================
// Template Utilities
// =============================================================================

/**
 * Extract {{param}} placeholders from a template string.
 * @param template - The template string with {{param}} placeholders
 * @returns Array of unique parameter names
 */
function extractParameters(template: string): string[] {
  const regex = /\{\{(\w+)\}\}/g;
  const params = new Set<string>();
  let match;
  while ((match = regex.exec(template)) !== null) {
    params.add(match[1]);
  }
  return Array.from(params);
}

/**
 * Substitute parameters into a template string.
 * @param template - The template string with {{param}} placeholders
 * @param params - Object mapping parameter names to values
 * @returns The template with all placeholders replaced
 */
function substituteParameters(template: string, params: Record<string, string | number>): string {
  let result = template;
  for (const [key, value] of Object.entries(params)) {
    const regex = new RegExp(`\\{\\{${key}\\}\\}`, 'g');
    result = result.replace(regex, String(value));
  }
  return result;
}

/**
 * Validate that all required parameters are provided.
 * @param templateParams - Parameters defined in the template
 * @param providedParams - Parameters provided by the user
 * @returns Object with missing and extra parameters
 */
function validateParameters(
  templateParams: string[],
  providedParams: Record<string, unknown>
): { missing: string[]; extra: string[] } {
  const providedKeys = Object.keys(providedParams);
  const missing = templateParams.filter(p => !providedKeys.includes(p));
  const extra = providedKeys.filter(p => !templateParams.includes(p));
  return { missing, extra };
}

// =============================================================================
// Template Storage Types
// =============================================================================

interface StoredTemplate {
  name: string;
  description: string | null;
  template: string;
  parameters: string | null; // JSON array
  created_at: string;
  use_count: number;
}

// =============================================================================
// save_template - Save a reusable query template
// =============================================================================

const saveTemplateTool = defineTool({
  name: 'save_template',
  description: 'Save a reusable query template with {{placeholders}}. Templates can contain SQL queries or tool-chain definitions for future execution.',
  inputSchema: {
    type: 'object',
    properties: {
      name: {
        type: 'string',
        description: 'Unique name for the template (e.g., "ransomware_gaps", "technique_coverage")',
      },
      template: {
        type: 'string',
        description: 'The query template with {{param}} placeholders (e.g., "SELECT * FROM detections WHERE mitre_ids LIKE \'%{{technique}}%\'")',
      },
      description: {
        type: 'string',
        description: 'Human-readable description of what this template does',
      },
    },
    required: ['name', 'template'],
  },
  handler: async (args) => {
    const name = args?.name as string;
    const template = args?.template as string;
    const description = (args?.description as string) || null;

    if (!name || !template) {
      return {
        error: true,
        code: 'MISSING_REQUIRED_ARG',
        message: 'name and template are required',
      };
    }

    // Validate template name (alphanumeric, underscores, hyphens only)
    if (!/^[\w-]+$/.test(name)) {
      return {
        error: true,
        code: 'INVALID_NAME',
        message: 'Template name must contain only letters, numbers, underscores, and hyphens',
      };
    }

    ensureTemplateSchema();
    const db = getDb();

    // Extract parameters from template
    const parameters = extractParameters(template);

    // Check if template already exists
    const existing = db.prepare('SELECT name FROM query_templates WHERE name = ?').get(name);

    if (existing) {
      // Update existing template
      db.prepare(`
        UPDATE query_templates 
        SET template = ?, description = ?, parameters = ?
        WHERE name = ?
      `).run(template, description, JSON.stringify(parameters), name);

      return {
        saved: true,
        name,
        action: 'updated',
        parameters,
        description,
        message: `Template "${name}" updated successfully`,
      };
    }

    // Insert new template
    db.prepare(`
      INSERT INTO query_templates (name, description, template, parameters)
      VALUES (?, ?, ?, ?)
    `).run(name, description, template, JSON.stringify(parameters));

    return {
      saved: true,
      name,
      action: 'created',
      parameters,
      description,
      message: `Template "${name}" saved successfully`,
      example_usage: parameters.length > 0
        ? `run_template(name="${name}", params={${parameters.map(p => `"${p}": "value"`).join(', ')}})`
        : `run_template(name="${name}")`,
    };
  },
});

// =============================================================================
// run_template - Execute a template with provided parameters
// =============================================================================

const runTemplateTool = defineTool({
  name: 'run_template',
  description: 'Execute a saved query template with the provided parameters. Returns the query results.',
  inputSchema: {
    type: 'object',
    properties: {
      name: {
        type: 'string',
        description: 'Name of the saved template to execute',
      },
      params: {
        type: 'object',
        description: 'Parameter values to substitute into the template (e.g., {"technique": "T1486", "source": "splunk_escu"})',
      },
    },
    required: ['name'],
  },
  handler: async (args) => {
    const name = args?.name as string;
    const params = (args?.params as Record<string, string | number>) || {};

    if (!name) {
      return {
        error: true,
        code: 'MISSING_REQUIRED_ARG',
        message: 'name is required',
      };
    }

    ensureTemplateSchema();
    const db = getDb();

    // Fetch template
    const row = db.prepare('SELECT * FROM query_templates WHERE name = ?').get(name) as StoredTemplate | undefined;

    if (!row) {
      // List available templates to help
      const available = db.prepare('SELECT name FROM query_templates ORDER BY use_count DESC LIMIT 10').all() as { name: string }[];
      return {
        error: true,
        code: 'TEMPLATE_NOT_FOUND',
        message: `Template "${name}" not found`,
        available_templates: available.map(t => t.name),
      };
    }

    // Parse stored parameters
    const templateParams: string[] = row.parameters ? JSON.parse(row.parameters) : [];

    // Validate parameters
    const { missing, extra } = validateParameters(templateParams, params);

    if (missing.length > 0) {
      return {
        error: true,
        code: 'MISSING_PARAMETERS',
        message: `Missing required parameters: ${missing.join(', ')}`,
        template_name: name,
        required_parameters: templateParams,
        provided_parameters: Object.keys(params),
        missing_parameters: missing,
      };
    }

    // Warn about extra parameters (but don't fail)
    const warnings: string[] = [];
    if (extra.length > 0) {
      warnings.push(`Extra parameters ignored: ${extra.join(', ')}`);
    }

    // Substitute parameters into template
    const query = substituteParameters(row.template, params);

    // Increment use count
    db.prepare('UPDATE query_templates SET use_count = use_count + 1 WHERE name = ?').run(name);

    // Determine if this is a SQL template or tool-chain template
    const isSqlTemplate = query.trim().toUpperCase().startsWith('SELECT') ||
                          query.trim().toUpperCase().startsWith('WITH');

    if (isSqlTemplate) {
      // Execute SQL query
      try {
        const results = db.prepare(query).all();
        return {
          template_name: name,
          executed_query: query,
          result_count: results.length,
          results,
          warnings: warnings.length > 0 ? warnings : undefined,
        };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          error: true,
          code: 'QUERY_EXECUTION_ERROR',
          message: `Failed to execute query: ${message}`,
          template_name: name,
          executed_query: query,
        };
      }
    } else {
      // Return the rendered template for tool-chain or custom execution
      return {
        template_name: name,
        template_type: 'non-sql',
        rendered_template: query,
        parameters_used: params,
        warnings: warnings.length > 0 ? warnings : undefined,
        note: 'This template is not a SQL query. Use the rendered_template value as needed.',
      };
    }
  },
});

// =============================================================================
// list_templates - List all saved query templates
// =============================================================================

const listTemplatesTool = defineTool({
  name: 'list_templates',
  description: 'List all saved query templates with their names, descriptions, and usage statistics.',
  inputSchema: {
    type: 'object',
    properties: {
      sort_by: {
        type: 'string',
        enum: ['name', 'created_at', 'use_count'],
        description: 'Field to sort by (default: use_count)',
      },
      limit: {
        type: 'number',
        description: 'Maximum number of templates to return (default: 50)',
      },
    },
  },
  handler: async (args) => {
    const sortBy = (args?.sort_by as string) || 'use_count';
    const limit = (args?.limit as number) || 50;

    ensureTemplateSchema();
    const db = getDb();

    // Validate sort field to prevent SQL injection
    const validSortFields = ['name', 'created_at', 'use_count'];
    const sortField = validSortFields.includes(sortBy) ? sortBy : 'use_count';
    const sortOrder = sortField === 'use_count' ? 'DESC' : 'ASC';

    const templates = db.prepare(`
      SELECT name, description, parameters, created_at, use_count
      FROM query_templates
      ORDER BY ${sortField} ${sortOrder}
      LIMIT ?
    `).all(limit) as StoredTemplate[];

    const formattedTemplates = templates.map(t => ({
      name: t.name,
      description: t.description,
      parameters: t.parameters ? JSON.parse(t.parameters) : [],
      created_at: t.created_at,
      use_count: t.use_count,
    }));

    // Get total count
    const countResult = db.prepare('SELECT COUNT(*) as total FROM query_templates').get() as { total: number };

    return {
      total: countResult.total,
      showing: formattedTemplates.length,
      sorted_by: sortField,
      templates: formattedTemplates,
    };
  },
});

// =============================================================================
// get_template - Get a template's full details
// =============================================================================

const getTemplateTool = defineTool({
  name: 'get_template',
  description: 'Get the full details of a saved query template including the template string and parameters.',
  inputSchema: {
    type: 'object',
    properties: {
      name: {
        type: 'string',
        description: 'Name of the template to retrieve',
      },
    },
    required: ['name'],
  },
  handler: async (args) => {
    const name = args?.name as string;

    if (!name) {
      return {
        error: true,
        code: 'MISSING_REQUIRED_ARG',
        message: 'name is required',
      };
    }

    ensureTemplateSchema();
    const db = getDb();

    const row = db.prepare('SELECT * FROM query_templates WHERE name = ?').get(name) as StoredTemplate | undefined;

    if (!row) {
      return {
        error: true,
        code: 'TEMPLATE_NOT_FOUND',
        message: `Template "${name}" not found`,
      };
    }

    const parameters = row.parameters ? JSON.parse(row.parameters) : [];

    return {
      found: true,
      name: row.name,
      description: row.description,
      template: row.template,
      parameters,
      created_at: row.created_at,
      use_count: row.use_count,
      example_usage: parameters.length > 0
        ? `run_template(name="${row.name}", params={${parameters.map((p: string) => `"${p}": "value"`).join(', ')}})`
        : `run_template(name="${row.name}")`,
    };
  },
});

// =============================================================================
// delete_template - Remove a template
// =============================================================================

const deleteTemplateTool = defineTool({
  name: 'delete_template',
  description: 'Delete a saved query template by name.',
  inputSchema: {
    type: 'object',
    properties: {
      name: {
        type: 'string',
        description: 'Name of the template to delete',
      },
    },
    required: ['name'],
  },
  handler: async (args) => {
    const name = args?.name as string;

    if (!name) {
      return {
        error: true,
        code: 'MISSING_REQUIRED_ARG',
        message: 'name is required',
      };
    }

    ensureTemplateSchema();
    const db = getDb();

    // Check if template exists
    const existing = db.prepare('SELECT use_count FROM query_templates WHERE name = ?').get(name) as { use_count: number } | undefined;

    if (!existing) {
      return {
        error: true,
        code: 'TEMPLATE_NOT_FOUND',
        message: `Template "${name}" not found`,
      };
    }

    // Delete template
    db.prepare('DELETE FROM query_templates WHERE name = ?').run(name);

    return {
      deleted: true,
      name,
      previous_use_count: existing.use_count,
      message: `Template "${name}" deleted successfully`,
    };
  },
});

// =============================================================================
// Export all meta tools
// =============================================================================

export const metaTools: ToolDefinition[] = [
  saveTemplateTool,
  runTemplateTool,
  listTemplatesTool,
  getTemplateTool,
  deleteTemplateTool,
];

// Export individual tools for granular imports
export {
  saveTemplateTool,
  runTemplateTool,
  listTemplatesTool,
  getTemplateTool,
  deleteTemplateTool,
};

// Export utilities for use by other modules
export { extractParameters, substituteParameters, ensureTemplateSchema };
