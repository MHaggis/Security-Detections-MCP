export interface ToolDefinition {
  type: 'function';
  function: {
    name: string;
    description: string;
    parameters: {
      type: 'object';
      properties: Record<string, { type: string; description: string; enum?: string[] }>;
      required: string[];
    };
  };
}

export const AI_TOOLS: ToolDefinition[] = [
  {
    type: 'function',
    function: {
      name: 'search_detections',
      description: 'Search for security detections by keyword, technique ID, or description. Returns matching detection rules.',
      parameters: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Search query (keywords, technique IDs, CVEs, process names)' },
          source: { type: 'string', description: 'Filter by source', enum: ['sigma', 'splunk_escu', 'elastic', 'kql', 'sublime', 'crowdstrike_cql'] },
          severity: { type: 'string', description: 'Filter by severity', enum: ['critical', 'high', 'medium', 'low'] },
          limit: { type: 'string', description: 'Max results (default 10)' },
        },
        required: ['query'],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'get_technique_coverage',
      description: 'Get detection coverage for a specific MITRE ATT&CK technique. Shows which sources have detections.',
      parameters: {
        type: 'object',
        properties: {
          technique_id: { type: 'string', description: 'MITRE ATT&CK technique ID (e.g., T1059.001)' },
        },
        required: ['technique_id'],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'get_actor_coverage',
      description: 'Analyze detection coverage against a MITRE ATT&CK threat actor/APT group. Shows covered and uncovered techniques.',
      parameters: {
        type: 'object',
        properties: {
          actor_name: { type: 'string', description: 'Threat actor name (e.g., APT29, Lazarus Group, FIN7)' },
        },
        required: ['actor_name'],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'get_tactic_summary',
      description: 'Get a summary of detection coverage across all MITRE ATT&CK tactics.',
      parameters: {
        type: 'object',
        properties: {},
        required: [],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'list_actors',
      description: 'List known MITRE ATT&CK threat actors. Can search by name.',
      parameters: {
        type: 'object',
        properties: {
          search: { type: 'string', description: 'Search query to filter actors by name' },
          limit: { type: 'string', description: 'Max results (default 20)' },
        },
        required: [],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'compare_sources',
      description: 'Compare detection coverage between different sources for a given technique or tactic.',
      parameters: {
        type: 'object',
        properties: {
          technique_id: { type: 'string', description: 'MITRE ATT&CK technique ID to compare coverage for' },
        },
        required: ['technique_id'],
      },
    },
  },
];
