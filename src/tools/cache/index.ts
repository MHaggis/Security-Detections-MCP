// src/tools/cache/index.ts
// Cache and Saved Query Tools - Query result caching and index management

import { defineTool, ToolDefinition } from '../registry.js';
import {
  saveQueryResult,
  getSavedQuery,
  listSavedQueries,
  getStats,
  getDbPath,
  recreateDb,
} from '../../db/index.js';
import { indexDetections } from '../../indexer.js';
import { getServerInstance, notifyResourceChange } from '../../server.js';

// =============================================================================
// Configuration - Get paths from environment
// =============================================================================

function parsePaths(envVar: string | undefined): string[] {
  if (!envVar) return [];
  return envVar.split(',').map(p => p.trim()).filter(p => p.length > 0);
}

const SIGMA_PATHS = parsePaths(process.env.SIGMA_PATHS);
const SPLUNK_PATHS = parsePaths(process.env.SPLUNK_PATHS);
const ELASTIC_PATHS = parsePaths(process.env.ELASTIC_PATHS);
const STORY_PATHS = parsePaths(process.env.STORY_PATHS);
const KQL_PATHS = parsePaths(process.env.KQL_PATHS);

// =============================================================================
// Saved Query Tools
// =============================================================================

const saveQueryTool = defineTool({
  name: 'save_query',
  description: 'Save a query result for quick retrieval later. Useful for caching frequently needed data.',
  inputSchema: {
    type: 'object',
    properties: {
      name: {
        type: 'string',
        description: 'Name for the saved query (e.g., "powershell_splunk_detections")',
      },
      query_type: {
        type: 'string',
        description: 'Type of query (e.g., "detection_list", "comparison", "coverage")',
      },
      data: {
        type: 'object',
        description: 'The data to save (any JSON object)',
      },
      ttl_minutes: {
        type: 'number',
        description: 'Time-to-live in minutes (optional, default: no expiry)',
      },
    },
    required: ['name', 'query_type', 'data'],
  },
  handler: async (args) => {
    const name = args?.name as string;
    const queryType = args?.query_type as string;
    const data = args?.data as Record<string, unknown>;
    const ttlMinutes = args?.ttl_minutes as number | undefined;

    if (!name || !queryType || !data) {
      return {
        error: true,
        code: 'MISSING_REQUIRED_ARG',
        message: 'name, query_type, and data are all required',
      };
    }

    const id = saveQueryResult(name, queryType, { name, queryType }, data, ttlMinutes);

    return {
      saved: true,
      id,
      name,
      query_type: queryType,
      expires: ttlMinutes ? `in ${ttlMinutes} minutes` : 'never',
    };
  },
});

const getSavedQueryTool = defineTool({
  name: 'get_saved_query',
  description: 'Retrieve a previously saved query result by name.',
  inputSchema: {
    type: 'object',
    properties: {
      name: {
        type: 'string',
        description: 'Name of the saved query',
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

    const result = getSavedQuery(name);

    if (!result) {
      return {
        found: false,
        name,
        message: 'No saved query found with this name (may have expired)',
      };
    }

    return {
      found: true,
      name,
      data: result,
    };
  },
});

const listSavedQueriesTool = defineTool({
  name: 'list_saved_queries',
  description: 'List all saved queries, optionally filtered by type.',
  inputSchema: {
    type: 'object',
    properties: {
      query_type: {
        type: 'string',
        description: 'Optional: filter by query type',
      },
    },
  },
  handler: async (args) => {
    const queryType = args?.query_type as string | undefined;
    const queries = listSavedQueries(queryType);

    return {
      count: queries.length,
      filter: queryType || 'all',
      queries,
    };
  },
});

// =============================================================================
// Index Management Tool
// =============================================================================

/**
 * Rebuild index tool with elicitation support for confirmation.
 * Uses getServerInstance() to access the MCP server for elicitation.
 */
const rebuildIndexTool = defineTool({
  name: 'rebuild_index',
  description: 'Force re-index all detections and stories from configured paths. WARNING: This is a destructive operation that deletes the current index.',
  inputSchema: {
    type: 'object',
    properties: {
      confirm: {
        type: 'boolean',
        description: 'Set to true to confirm you want to rebuild (required for safety)',
        default: false,
      },
      skip_elicitation: {
        type: 'boolean', 
        description: 'Skip the elicitation confirmation prompt (for programmatic use)',
        default: false,
      },
    },
  },
  handler: async (args) => {
    const confirmArg = args?.confirm as boolean;
    const skipElicitation = args?.skip_elicitation as boolean;
    
    if (SIGMA_PATHS.length === 0 && SPLUNK_PATHS.length === 0 && ELASTIC_PATHS.length === 0 && KQL_PATHS.length === 0) {
      return {
        error: true,
        message: 'No paths configured. Set SIGMA_PATHS, SPLUNK_PATHS, ELASTIC_PATHS, and/or KQL_PATHS environment variables.',
      };
    }

    const currentStats = getStats();
    
    // Try elicitation first if not skipped and confirm not already provided
    if (!skipElicitation && !confirmArg) {
      const server = getServerInstance();
      if (server) {
        try {
          // Attempt elicitation - will throw if not supported
          const elicitResult = await (server as unknown as { 
            request: (req: { method: string; params: unknown }) => Promise<{ action: string; content?: { confirm?: boolean } }> 
          }).request({
            method: 'elicitation/create',
            params: {
              mode: 'form',
              message: `⚠️ DESTRUCTIVE OPERATION\n\nThis will DELETE and rebuild the entire detection index.\n\nCurrent index: ${currentStats.total} detections\n\nAre you sure you want to proceed?`,
              requestedSchema: {
                type: 'object',
                properties: {
                  confirm: {
                    type: 'boolean',
                    title: 'Yes, rebuild the index',
                    description: 'Check this box to confirm you want to delete and rebuild the entire index',
                    default: false,
                  },
                },
                required: ['confirm'],
              },
            },
          });

          // Check if user confirmed via elicitation
          if (elicitResult.action !== 'accept' || !elicitResult.content?.confirm) {
            return {
              cancelled: true,
              message: 'Index rebuild cancelled by user.',
              tip: 'To bypass elicitation, call with confirm: true',
            };
          }
        } catch (e) {
          // Elicitation not supported - fall back to requiring confirm parameter
          console.error('[security-detections-mcp] Elicitation not supported by client, falling back to confirm parameter');
          
          if (!confirmArg) {
            return {
              error: true,
              requires_confirmation: true,
              message: 'This is a destructive operation. The client does not support elicitation prompts.',
              current_index_size: currentStats.total,
              to_proceed: 'Call rebuild_index with confirm: true to proceed',
              warning: 'This will DELETE all indexed detections and rebuild from configured paths',
            };
          }
        }
      } else if (!confirmArg) {
        // No server instance available
        return {
          error: true,
          requires_confirmation: true,
          message: 'This is a destructive operation.',
          current_index_size: currentStats.total,
          to_proceed: 'Call rebuild_index with confirm: true to proceed',
        };
      }
    }

    // At this point, either elicitation confirmed, or confirm: true was passed
    console.error('[security-detections-mcp] Rebuilding index...');
    
    // Recreate DB to apply schema changes
    recreateDb();

    const result = indexDetections(SIGMA_PATHS, SPLUNK_PATHS, STORY_PATHS, ELASTIC_PATHS, KQL_PATHS);
    
    // Notify subscribers that resources have changed
    try {
      await notifyResourceChange('detection://stats');
      await notifyResourceChange('detection://coverage');
    } catch (e) {
      // Notifications are best-effort
    }
    
    return {
      message: 'Index rebuilt successfully',
      ...result,
      stories_note: STORY_PATHS.length === 0 ? 'No STORY_PATHS configured - stories not indexed' : undefined,
      elastic_note: ELASTIC_PATHS.length === 0 ? 'No ELASTIC_PATHS configured - Elastic rules not indexed' : undefined,
      kql_note: KQL_PATHS.length === 0 ? 'No KQL_PATHS configured - KQL queries not indexed' : undefined,
      db_path: getDbPath(),
    };
  },
});

// =============================================================================
// Export all cache tools
// =============================================================================

export const cacheTools: ToolDefinition[] = [
  saveQueryTool,
  getSavedQueryTool,
  listSavedQueriesTool,
  rebuildIndexTool,
];

// Export individual tools for granular imports
export { saveQueryTool, getSavedQueryTool, listSavedQueriesTool, rebuildIndexTool };
