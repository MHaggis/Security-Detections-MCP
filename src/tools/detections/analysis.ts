// Coverage analysis tools for detections
import { defineTool } from '../registry.js';
import {
  getStats,
  getTechniqueIds,
  analyzeCoverage,
  identifyGaps,
  suggestDetections,
  validateTechniqueId,
} from '../../db/index.js';

const THREAT_PROFILE_VALUES = ['ransomware', 'apt', 'initial-access', 'persistence', 'credential-access', 'defense-evasion'];

export const analysisTools = [
  defineTool({
    name: 'get_stats',
    description: 'Get statistics about the indexed detections and stories',
    inputSchema: {
      type: 'object',
      properties: {},
    },
    handler: async () => {
      const stats = getStats();
      return stats;
    },
  }),

  defineTool({
    name: 'get_technique_ids',
    description: 'Get ONLY unique MITRE technique IDs (lightweight - no full detection data). Use this for Navigator layer generation or coverage analysis.',
    inputSchema: {
      type: 'object',
      properties: {
        source_type: {
          type: 'string',
          enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
          description: 'Filter by source type',
        },
        tactic: {
          type: 'string',
          enum: [
            'reconnaissance', 'resource-development', 'initial-access', 'execution',
            'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
            'discovery', 'lateral-movement', 'collection', 'command-and-control',
            'exfiltration', 'impact',
          ],
          description: 'Filter by MITRE tactic',
        },
        severity: {
          type: 'string',
          enum: ['informational', 'low', 'medium', 'high', 'critical'],
          description: 'Filter by severity',
        },
      },
    },
    handler: async (args) => {
      const sourceType = args.source_type as 'sigma' | 'splunk_escu' | 'elastic' | 'kql' | undefined;
      const tactic = args.tactic as string | undefined;
      const severity = args.severity as string | undefined;

      const techniqueIds = getTechniqueIds({
        source_type: sourceType,
        tactic,
        severity,
      });

      return {
        count: techniqueIds.length,
        technique_ids: techniqueIds,
      };
    },
  }),

  defineTool({
    name: 'analyze_coverage',
    description: 'Get coverage analysis with stats by tactic, top covered techniques, and weak spots. Returns summary data, not raw detections. Use this instead of listing detections and processing manually.',
    inputSchema: {
      type: 'object',
      properties: {
        source_type: {
          type: 'string',
          enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
          description: 'Filter by source type (optional - analyzes all if not specified)',
        },
      },
    },
    handler: async (args) => {
      const sourceType = args.source_type as 'sigma' | 'splunk_escu' | 'elastic' | 'kql' | undefined;
      const report = analyzeCoverage(sourceType);
      return report;
    },
  }),

  defineTool({
    name: 'identify_gaps',
    description: 'Identify detection gaps based on a threat profile (ransomware, apt, initial-access, persistence, credential-access, defense-evasion). Returns prioritized gaps with recommendations.',
    inputSchema: {
      type: 'object',
      properties: {
        threat_profile: {
          type: 'string',
          enum: THREAT_PROFILE_VALUES,
          description: 'Threat profile to analyze gaps against',
        },
        source_type: {
          type: 'string',
          enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
          description: 'Filter by source type (optional)',
        },
      },
      required: ['threat_profile'],
    },
    handler: async (args) => {
      const threatProfile = args.threat_profile as string;
      const sourceType = args.source_type as 'sigma' | 'splunk_escu' | 'elastic' | 'kql' | undefined;

      if (!threatProfile) {
        return {
          error: true,
          code: 'MISSING_REQUIRED_ARG',
          message: 'threat_profile is required',
          valid_values: THREAT_PROFILE_VALUES,
          hint: 'Each profile contains commonly used techniques for that threat type',
        };
      }

      const gaps = identifyGaps(threatProfile, sourceType);
      return gaps;
    },
  }),

  defineTool({
    name: 'suggest_detections',
    description: 'Get detection suggestions for a specific technique. Returns existing detections, required data sources, and detection ideas.',
    inputSchema: {
      type: 'object',
      properties: {
        technique_id: {
          type: 'string',
          description: 'MITRE technique ID (e.g., T1059.001, T1547.001)',
        },
        source_type: {
          type: 'string',
          enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
          description: 'Filter by source type (optional)',
        },
      },
      required: ['technique_id'],
    },
    handler: async (args) => {
      const techniqueId = args.technique_id as string;
      const sourceType = args.source_type as 'sigma' | 'splunk_escu' | 'elastic' | 'kql' | undefined;

      if (!techniqueId) {
        return {
          error: true,
          code: 'MISSING_REQUIRED_ARG',
          message: 'technique_id is required',
          examples: ['T1059.001', 'T1547.001', 'T1003.001'],
          hint: 'Use format T####.### (e.g., T1059.001 for PowerShell)',
        };
      }

      // Validate technique ID format
      const validation = validateTechniqueId(techniqueId);
      if (!validation.valid) {
        return {
          error: true,
          code: 'INVALID_TECHNIQUE_ID',
          message: validation.error,
          suggestion: validation.suggestion,
          similar: validation.similar,
        };
      }

      const suggestions = suggestDetections(techniqueId, sourceType);
      return suggestions;
    },
  }),
];
