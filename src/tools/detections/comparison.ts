// Comparison and lightweight tools for detections
import { defineTool } from '../registry.js';
import {
  searchDetections,
  searchDetectionList,
  compareDetectionsBySource,
  countDetectionsBySource,
  getDetectionNamesByPattern,
  listByMitre,
  analyzeCoverage,
  identifyGaps,
} from '../../db/index.js';

const THREAT_PROFILE_VALUES = ['ransomware', 'apt', 'initial-access', 'persistence', 'credential-access', 'defense-evasion'];

export const comparisonTools = [
  defineTool({
    name: 'get_detection_list',
    description: 'Get a lightweight list of detection names and IDs matching a search query. Returns ONLY name, id, source, mitre_ids - no queries or raw yaml. Use this when you need a simple list.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search query (e.g., "powershell", "credential", "T1059")',
        },
        source_type: {
          type: 'string',
          enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
          description: 'Optional: filter by source type',
        },
        limit: {
          type: 'number',
          description: 'Max results (default 100)',
        },
      },
      required: ['query'],
    },
    handler: async (args) => {
      const query = args.query as string;
      const sourceType = args.source_type as 'sigma' | 'splunk_escu' | 'elastic' | 'kql' | undefined;
      const limit = (args.limit as number) || 100;

      if (!query) {
        return {
          error: true,
          code: 'MISSING_REQUIRED_ARG',
          message: 'query is required',
          examples: ['powershell', 'credential', 'T1059.001'],
        };
      }

      let results = searchDetectionList(query, limit * 2);

      if (sourceType) {
        results = results.filter(r => r.source_type === sourceType);
      }

      results = results.slice(0, limit);

      return {
        query,
        source_filter: sourceType || 'all',
        count: results.length,
        detections: results.map(r => ({
          name: r.name,
          id: r.id,
          source: r.source_type,
          mitre: r.mitre_ids,
        })),
      };
    },
  }),

  defineTool({
    name: 'compare_sources',
    description: 'Compare detection coverage between sources (Sigma vs Splunk vs Elastic vs KQL) for a topic. Returns a clean breakdown with counts and names per source.',
    inputSchema: {
      type: 'object',
      properties: {
        topic: {
          type: 'string',
          description: 'Topic to compare (e.g., "powershell", "credential dumping", "ransomware")',
        },
        limit_per_source: {
          type: 'number',
          description: 'Max detections to show per source (default 50)',
        },
      },
      required: ['topic'],
    },
    handler: async (args) => {
      const topic = args.topic as string;
      const limitPerSource = (args.limit_per_source as number) || 50;

      if (!topic) {
        return {
          error: true,
          code: 'MISSING_REQUIRED_ARG',
          message: 'topic is required',
          examples: ['powershell', 'credential dumping', 'ransomware'],
        };
      }

      const comparison = compareDetectionsBySource(topic, limitPerSource);

      // Format as clean comparison
      const formatted = {
        topic: comparison.topic,
        total_found: comparison.total_found,
        source_counts: comparison.summary.source_counts,
        by_source: {} as Record<string, Array<{ name: string; id: string; mitre: string[] }>>,
        tactic_breakdown: comparison.by_tactic,
      };

      for (const [source, items] of Object.entries(comparison.by_source)) {
        if (items.length > 0) {
          formatted.by_source[source] = items.map(i => ({
            name: i.name,
            id: i.id,
            mitre: i.mitre_ids,
          }));
        }
      }

      return formatted;
    },
  }),

  defineTool({
    name: 'count_by_source',
    description: 'Get quick counts of detections by source for a topic. Returns just the numbers, no detection details.',
    inputSchema: {
      type: 'object',
      properties: {
        topic: {
          type: 'string',
          description: 'Topic to count (e.g., "powershell", "lateral movement")',
        },
      },
      required: ['topic'],
    },
    handler: async (args) => {
      const topic = args.topic as string;

      if (!topic) {
        return {
          error: true,
          code: 'MISSING_REQUIRED_ARG',
          message: 'topic is required',
        };
      }

      const counts = countDetectionsBySource(topic);
      const total = Object.values(counts).reduce((a, b) => a + b, 0);

      return {
        topic,
        total,
        by_source: counts,
      };
    },
  }),

  defineTool({
    name: 'list_by_name_pattern',
    description: 'List detections whose NAME matches a pattern, grouped by source. Returns just name + ID pairs.',
    inputSchema: {
      type: 'object',
      properties: {
        pattern: {
          type: 'string',
          description: 'Pattern to match in detection names (e.g., "PowerShell", "WMI", "Registry")',
        },
        source_type: {
          type: 'string',
          enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
          description: 'Optional: filter to specific source',
        },
      },
      required: ['pattern'],
    },
    handler: async (args) => {
      const pattern = args.pattern as string;
      const sourceType = args.source_type as 'sigma' | 'splunk_escu' | 'elastic' | 'kql' | undefined;

      if (!pattern) {
        return {
          error: true,
          code: 'MISSING_REQUIRED_ARG',
          message: 'pattern is required',
          examples: ['PowerShell', 'WMI', 'Registry'],
        };
      }

      const results = getDetectionNamesByPattern(pattern, sourceType);
      const total = results.reduce((sum, r) => sum + r.detections.length, 0);

      return {
        pattern,
        source_filter: sourceType || 'all',
        total,
        results,
      };
    },
  }),

  defineTool({
    name: 'smart_compare',
    description: 'Compare detections across sources, tactics, or techniques for a given topic. Returns breakdown by source, tactic, and severity.',
    inputSchema: {
      type: 'object',
      properties: {
        topic: {
          type: 'string',
          description: 'Topic to compare (e.g., "powershell", "credential dumping", "T1059", "ransomware")',
        },
      },
      required: ['topic'],
    },
    handler: async (args) => {
      const topic = args.topic as string;

      if (!topic) {
        return {
          error: true,
          code: 'MISSING_REQUIRED_ARG',
          message: 'topic is required',
          examples: ['powershell', 'credential dumping', 'T1059.001', 'ransomware'],
        };
      }

      // Search to see what we have for this topic
      const allResults = searchDetections(topic, 500);

      if (allResults.length === 0) {
        return {
          topic,
          found: 0,
          suggestion: 'No detections found. Try a broader search term.',
        };
      }

      // Analyze what we found - group by source AND tactic
      const bySource: Record<string, number> = {};
      const byTactic: Record<string, number> = {};
      const bySeverity: Record<string, number> = {};

      for (const r of allResults) {
        bySource[r.source_type] = (bySource[r.source_type] || 0) + 1;
        if (r.severity) bySeverity[r.severity] = (bySeverity[r.severity] || 0) + 1;
        for (const tactic of (r.mitre_tactics || [])) {
          byTactic[tactic] = (byTactic[tactic] || 0) + 1;
        }
      }

      return {
        topic,
        total: allResults.length,
        by_source: bySource,
        by_tactic: byTactic,
        by_severity: bySeverity,
      };
    },
  }),

  defineTool({
    name: 'get_coverage_summary',
    description: 'Get a lightweight coverage summary (~200 bytes) with tactic percentages. Use this for quick overviews instead of full analyze_coverage.',
    inputSchema: {
      type: 'object',
      properties: {
        source_type: {
          type: 'string',
          enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
          description: 'Filter by source type (optional)',
        },
      },
    },
    handler: async (args) => {
      const sourceType = args.source_type as 'sigma' | 'splunk_escu' | 'elastic' | 'kql' | undefined;
      const report = analyzeCoverage(sourceType);

      // Return minimal data - just percentages
      return {
        techniques: report.summary.total_techniques,
        detections: report.summary.total_detections,
        by_tactic: Object.fromEntries(
          Object.entries(report.summary.coverage_by_tactic).map(
            ([tactic, data]) => [tactic, `${data.percent}%`]
          )
        ),
      };
    },
  }),

  defineTool({
    name: 'get_top_gaps',
    description: 'Get just the top 5 gaps (~300 bytes) for a threat profile. Use this for quick gap checks.',
    inputSchema: {
      type: 'object',
      properties: {
        threat_profile: {
          type: 'string',
          enum: THREAT_PROFILE_VALUES,
          description: 'Threat profile to check',
        },
      },
      required: ['threat_profile'],
    },
    handler: async (args) => {
      const threatProfile = args.threat_profile as string;

      if (!threatProfile) {
        return {
          error: true,
          code: 'MISSING_REQUIRED_ARG',
          message: 'threat_profile is required',
          valid_values: THREAT_PROFILE_VALUES,
        };
      }

      const gaps = identifyGaps(threatProfile);

      // Return minimal data - just top 5 technique IDs
      return {
        profile: threatProfile,
        gaps: gaps.critical_gaps.slice(0, 5).map(g => g.technique),
        total: gaps.total_gaps,
      };
    },
  }),

  defineTool({
    name: 'get_technique_count',
    description: 'Get just the detection count for a technique (~50 bytes). Use this for quick coverage checks.',
    inputSchema: {
      type: 'object',
      properties: {
        technique_id: {
          type: 'string',
          description: 'MITRE technique ID (e.g., T1059.001)',
        },
      },
      required: ['technique_id'],
    },
    handler: async (args) => {
      const techniqueId = args.technique_id as string;

      if (!techniqueId) {
        return {
          error: true,
          code: 'MISSING_REQUIRED_ARG',
          message: 'technique_id is required',
          examples: ['T1059.001', 'T1547.001'],
        };
      }

      const detections = listByMitre(techniqueId, 1000, 0);

      return {
        technique: techniqueId,
        count: detections.length,
      };
    },
  }),
];
