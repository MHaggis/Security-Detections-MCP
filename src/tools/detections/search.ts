// Search and retrieval tools for detections
import { defineTool } from '../registry.js';
import {
  searchDetections,
  getDetectionById,
  listDetections,
  getRawYaml,
  validateTechniqueId,
} from '../../db/index.js';

export const searchTools = [
  defineTool({
    name: 'search',
    description: 'Full-text search across all detection fields (name, description, query, MITRE IDs, tags, CVEs, analytic stories, process names, file paths, registry paths)',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search query (FTS5 syntax supported: use quotes for exact phrases, OR for alternatives)',
          examples: ['powershell base64', 'CVE-2024-*', '"DLL sideloading"', 'ransomware OR encryption'],
        },
        limit: {
          type: 'number',
          description: 'Max results to return',
          default: 50,
          minimum: 1,
          maximum: 500,
        },
        source_type: {
          type: 'string',
          enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
          description: 'Filter results by detection source type',
        },
      },
      required: ['query'],
    },
    handler: async (args) => {
      const query = args.query as string;
      const limit = (args.limit as number) || 50;
      const sourceFilter = args.source_type as string | undefined;

      if (!query) {
        return {
          error: true,
          code: 'MISSING_REQUIRED_ARG',
          message: 'query is required',
          examples: ['powershell base64', 'CVE-2024', 'ransomware encryption'],
          hint: 'FTS5 syntax supported for advanced queries',
        };
      }

      let results = searchDetections(query, 200);
      
      if (sourceFilter) {
        results = results.filter(r => r.source_type === sourceFilter);
      }
      results = results.slice(0, limit);

      if (results.length === 0) {
        return {
          results: [],
          suggestions: {
            try_broader: 'Try a simpler query or single keyword',
            try_tools: ['list_by_mitre_tactic', 'list_by_severity', 'list_by_source'],
            tip: 'Use quotes for exact phrases, OR for alternatives',
          },
        };
      }

      return { count: results.length, detections: results };
    },
  }),

  defineTool({
    name: 'get_by_id',
    description: 'Get a single detection by its ID',
    inputSchema: {
      type: 'object',
      properties: {
        id: {
          type: 'string',
          description: 'Detection ID (UUID for Sigma, or Splunk detection ID)',
        },
      },
      required: ['id'],
    },
    handler: async (args) => {
      const id = args.id as string;

      if (!id) {
        return {
          error: true,
          code: 'MISSING_REQUIRED_ARG',
          message: 'id is required',
          hint: 'Use search or list tools to find detection IDs first',
        };
      }

      const detection = getDetectionById(id);
      if (!detection) {
        return {
          error: true,
          code: 'NOT_FOUND',
          message: `Detection not found: ${id}`,
          suggestions: {
            try_search: 'Use search("keyword") to find detections',
            try_list: 'Use list_all or list_by_source to browse',
            tip: 'Sigma IDs are UUIDs, Splunk IDs are slug-format',
          },
        };
      }

      return detection;
    },
  }),

  defineTool({
    name: 'get_raw_yaml',
    description: 'Get the original YAML content for a detection',
    inputSchema: {
      type: 'object',
      properties: {
        id: {
          type: 'string',
          description: 'Detection ID',
        },
      },
      required: ['id'],
    },
    handler: async (args) => {
      const id = args.id as string;

      if (!id) {
        return { error: true, message: 'id is required' };
      }

      const yaml = getRawYaml(id);
      if (!yaml) {
        return { error: true, message: `Detection not found: ${id}` };
      }

      return { id, yaml };
    },
  }),

  defineTool({
    name: 'list_all',
    description: 'List all detections with pagination. Use for browsing the detection index.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: {
          type: 'number',
          description: 'Max results to return',
          default: 100,
          minimum: 1,
          maximum: 1000,
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (for paging through results)',
          default: 0,
          minimum: 0,
        },
      },
    },
    handler: async (args) => {
      const limit = (args.limit as number) || 100;
      const offset = (args.offset as number) || 0;

      const results = listDetections(limit, offset);
      return { count: results.length, offset, limit, detections: results };
    },
  }),
];
