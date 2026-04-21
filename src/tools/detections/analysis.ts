// Coverage analysis tools for detections
import { defineTool } from '../registry.js';
import {
  getStats,
  getTechniqueIds,
  analyzeCoverage,
  identifyGaps,
  suggestDetections,
  validateTechniqueId,
  generateNavigatorLayer,
  listByMitre,
  getDb,
} from '../../db/index.js';
import { PROCEDURE_REFERENCE, type TechniqueProcedure } from '../../db/procedure-reference.js';

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
          enum: ['sigma', 'splunk_escu', 'elastic', 'kql', 'sublime', 'crowdstrike_cql', 'jamf_protect'],
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
      const sourceType = args.source_type as 'sigma' | 'splunk_escu' | 'elastic' | 'kql' | 'sublime' | 'crowdstrike_cql' | 'jamf_protect' | undefined;
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
          enum: ['sigma', 'splunk_escu', 'elastic', 'kql', 'sublime', 'crowdstrike_cql', 'jamf_protect'],
          description: 'Filter by source type (optional - analyzes all if not specified)',
        },
      },
    },
    handler: async (args) => {
      const sourceType = args.source_type as 'sigma' | 'splunk_escu' | 'elastic' | 'kql' | 'sublime' | 'crowdstrike_cql' | 'jamf_protect' | undefined;
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
          enum: ['sigma', 'splunk_escu', 'elastic', 'kql', 'sublime', 'crowdstrike_cql', 'jamf_protect'],
          description: 'Filter by source type (optional)',
        },
      },
      required: ['threat_profile'],
    },
    handler: async (args) => {
      const threatProfile = args.threat_profile as string;
      const sourceType = args.source_type as 'sigma' | 'splunk_escu' | 'elastic' | 'kql' | 'sublime' | 'crowdstrike_cql' | 'jamf_protect' | undefined;

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
          enum: ['sigma', 'splunk_escu', 'elastic', 'kql', 'sublime', 'crowdstrike_cql', 'jamf_protect'],
          description: 'Filter by source type (optional)',
        },
      },
      required: ['technique_id'],
    },
    handler: async (args) => {
      const techniqueId = args.technique_id as string;
      const sourceType = args.source_type as 'sigma' | 'splunk_escu' | 'elastic' | 'kql' | 'sublime' | 'crowdstrike_cql' | 'jamf_protect' | undefined;

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

  // ═══════════════════════════════════════════════════════════════════════
  // NAVIGATOR LAYER GENERATION
  // ═══════════════════════════════════════════════════════════════════════

  defineTool({
    name: 'generate_navigator_layer',
    description: 'Generate a MITRE ATT&CK Navigator layer JSON from detection coverage. Returns valid Navigator JSON ready for import at https://mitre-attack.github.io/attack-navigator/. Filter by source, tactic, or severity.',
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'Layer name (e.g., "Sigma Coverage Q1 2026")',
        },
        description: {
          type: 'string',
          description: 'Optional layer description',
        },
        source_type: {
          type: 'string',
          enum: ['sigma', 'splunk_escu', 'elastic', 'kql', 'sublime', 'crowdstrike_cql', 'jamf_protect'],
          description: 'Filter to specific source type (optional — includes all if omitted)',
        },
        tactic: {
          type: 'string',
          enum: [
            'reconnaissance', 'resource-development', 'initial-access', 'execution',
            'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
            'discovery', 'lateral-movement', 'collection', 'command-and-control',
            'exfiltration', 'impact',
          ],
          description: 'Filter by MITRE tactic (optional)',
        },
        severity: {
          type: 'string',
          enum: ['informational', 'low', 'medium', 'high', 'critical'],
          description: 'Filter by minimum severity (optional)',
        },
      },
      required: ['name'],
    },
    handler: async (args) => {
      const name = args.name as string;
      if (!name) {
        return { error: true, code: 'MISSING_REQUIRED_ARG', message: 'name is required' };
      }

      const layer = generateNavigatorLayer({
        name,
        description: args.description as string | undefined,
        source_type: args.source_type as 'sigma' | 'splunk_escu' | 'elastic' | 'kql' | 'sublime' | 'crowdstrike_cql' | 'jamf_protect' | undefined,
        tactic: args.tactic as string | undefined,
        severity: args.severity as string | undefined,
      });

      return layer;
    },
  }),

  // ═══════════════════════════════════════════════════════════════════════
  // PROCEDURE-LEVEL COVERAGE ANALYSIS
  // ═══════════════════════════════════════════════════════════════════════

  defineTool({
    name: 'analyze_procedure_coverage',
    description: 'Analyze procedure-level coverage for a MITRE technique. Goes beyond "we cover T1059.001" to show WHICH specific behaviors/procedures your detections actually catch (e.g., encoded commands, download cradles, AMSI bypass). Shows covered and uncovered procedures with detection names.',
    inputSchema: {
      type: 'object',
      properties: {
        technique_id: {
          type: 'string',
          description: 'MITRE technique ID (e.g., T1059.001, T1003.001)',
        },
        source_type: {
          type: 'string',
          enum: ['sigma', 'splunk_escu', 'elastic', 'kql', 'sublime', 'crowdstrike_cql', 'jamf_protect'],
          description: 'Filter to specific source (optional — analyzes all if omitted)',
        },
        include_query_snippets: {
          type: 'boolean',
          description: 'Include relevant query snippets showing what each detection checks (default: false)',
        },
      },
      required: ['technique_id'],
    },
    handler: async (args) => {
      const techniqueId = args.technique_id as string;
      if (!techniqueId) {
        return { error: true, code: 'MISSING_REQUIRED_ARG', message: 'technique_id is required', examples: ['T1059.001', 'T1003.001', 'T1547.001'] };
      }

      const validation = validateTechniqueId(techniqueId);
      if (!validation.valid) {
        return { error: true, code: 'INVALID_TECHNIQUE_ID', message: validation.error, suggestion: validation.suggestion, similar: validation.similar };
      }

      const sourceType = args.source_type as 'sigma' | 'splunk_escu' | 'elastic' | 'kql' | 'sublime' | 'crowdstrike_cql' | 'jamf_protect' | undefined;
      const includeSnippets = args.include_query_snippets === true;

      return analyzeProcedureCoverageForTechnique(techniqueId, sourceType, includeSnippets);
    },
  }),

  defineTool({
    name: 'compare_procedure_coverage',
    description: 'Compare procedure-level detection coverage across sources for a technique. Shows which source catches which specific behaviors — two orgs can both tag T1059.001 but detect completely different procedures. Returns a matrix of source × procedure.',
    inputSchema: {
      type: 'object',
      properties: {
        technique_id: {
          type: 'string',
          description: 'MITRE technique ID to compare across sources',
        },
        sources: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['sigma', 'splunk_escu', 'elastic', 'kql', 'sublime', 'crowdstrike_cql', 'jamf_protect'],
          },
          description: 'Sources to compare (default: all available)',
        },
      },
      required: ['technique_id'],
    },
    handler: async (args) => {
      const techniqueId = args.technique_id as string;
      if (!techniqueId) {
        return { error: true, code: 'MISSING_REQUIRED_ARG', message: 'technique_id is required' };
      }

      const validation = validateTechniqueId(techniqueId);
      if (!validation.valid) {
        return { error: true, code: 'INVALID_TECHNIQUE_ID', message: validation.error, suggestion: validation.suggestion, similar: validation.similar };
      }

      const sources = args.sources as string[] | undefined;
      return compareProcedureCoverage(techniqueId, sources);
    },
  }),
];

// ═══════════════════════════════════════════════════════════════════════════
// PROCEDURE ANALYSIS HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Get procedures for a technique. Checks DB first (auto-extracted + hand-curated),
 * falls back to the static PROCEDURE_REFERENCE file.
 */
function getProcedures(techniqueId: string): TechniqueProcedure[] | null {
  try {
    const db = getDb();
    const rows = db.prepare(
      `SELECT id, name, category, description, indicators FROM procedure_reference
       WHERE technique_id = ? ORDER BY source DESC, confidence DESC`
    ).all(techniqueId) as Array<{ id: string; name: string; category: string; description: string; indicators: string }>;

    if (rows.length > 0) {
      return rows.map(row => ({
        id: row.id,
        name: row.name,
        category: row.category,
        description: row.description,
        indicators: JSON.parse(row.indicators || '{}'),
      }));
    }
  } catch {
    // Table may not exist yet — fall through to static
  }

  return PROCEDURE_REFERENCE[techniqueId] || null;
}

interface DetectionProcedureMatch {
  detection_name: string;
  source_type: string;
  procedures_matched: string[];
  query_snippet?: string;
}

function matchDetectionToProcedures(
  detection: { name: string; description: string; query: string; source_type: string; process_names: string[]; file_paths: string[]; registry_paths: string[] },
  procedures: TechniqueProcedure[],
  includeSnippets: boolean,
): DetectionProcedureMatch {
  const matched: string[] = [];
  const searchText = [
    detection.description || '',
    detection.query || '',
    detection.name || '',
  ].join(' ').toLowerCase();

  const processNamesLower = (detection.process_names || []).map(p => p.toLowerCase());
  const filePathsLower = (detection.file_paths || []).map(f => f.toLowerCase());
  const registryPathsLower = (detection.registry_paths || []).map(r => r.toLowerCase());

  for (const proc of procedures) {
    let score = 0;

    // Check process name matches
    if (proc.indicators.process_names) {
      for (const pn of proc.indicators.process_names) {
        if (processNamesLower.some(dp => dp.includes(pn.toLowerCase()))) { score += 2; break; }
        if (searchText.includes(pn.toLowerCase())) { score += 1; break; }
      }
    }

    // Check command pattern matches
    if (proc.indicators.command_patterns) {
      for (const cp of proc.indicators.command_patterns) {
        if (searchText.includes(cp.toLowerCase())) { score += 2; break; }
      }
    }

    // Check description keyword matches
    if (proc.indicators.description_keywords) {
      let kwMatches = 0;
      for (const kw of proc.indicators.description_keywords) {
        if (searchText.includes(kw.toLowerCase())) { kwMatches++; }
      }
      if (kwMatches >= 2) score += 3;
      else if (kwMatches >= 1) score += 1;
    }

    // Check registry path matches
    if (proc.indicators.registry_paths) {
      for (const rp of proc.indicators.registry_paths) {
        if (registryPathsLower.some(dr => dr.includes(rp.toLowerCase()))) { score += 2; break; }
        if (searchText.includes(rp.toLowerCase())) { score += 1; break; }
      }
    }

    // Check file path matches
    if (proc.indicators.file_paths) {
      for (const fp of proc.indicators.file_paths) {
        if (filePathsLower.some(df => df.includes(fp.toLowerCase()))) { score += 2; break; }
        if (searchText.includes(fp.toLowerCase())) { score += 1; break; }
      }
    }

    // Check event ID matches
    if (proc.indicators.event_ids) {
      for (const eid of proc.indicators.event_ids) {
        if (searchText.includes(`eventid ${eid}`) || searchText.includes(`event_id: ${eid}`) || searchText.includes(`eventcode=${eid}`) || searchText.includes(`"${eid}"`)) {
          score += 2; break;
        }
      }
    }

    // Check field pattern matches
    if (proc.indicators.field_patterns) {
      for (const fp of proc.indicators.field_patterns) {
        if (searchText.includes(fp.toLowerCase())) { score += 1; break; }
      }
    }

    // Threshold: need at least 3 points to count as a match
    if (score >= 3) {
      matched.push(proc.id);
    }
  }

  const result: DetectionProcedureMatch = {
    detection_name: detection.name,
    source_type: detection.source_type,
    procedures_matched: matched,
  };

  if (includeSnippets && detection.query) {
    result.query_snippet = detection.query.substring(0, 200) + (detection.query.length > 200 ? '...' : '');
  }

  return result;
}

function analyzeProcedureCoverageForTechnique(
  techniqueId: string,
  sourceType?: string,
  includeSnippets: boolean = false,
) {
  const procedures = getProcedures(techniqueId);
  const detections = listByMitre(techniqueId, 500);
  const filtered = sourceType ? detections.filter(d => d.source_type === sourceType) : detections;

  if (filtered.length === 0) {
    return {
      technique_id: techniqueId,
      total_detections: 0,
      has_procedure_reference: !!procedures,
      message: sourceType
        ? `No detections found for ${techniqueId} from source ${sourceType}`
        : `No detections found for ${techniqueId}`,
    };
  }

  // If no procedure reference, do best-effort extraction
  if (!procedures) {
    const sources: Record<string, string[]> = {};
    const allProcessNames = new Set<string>();
    for (const d of filtered) {
      const src = d.source_type;
      if (!sources[src]) sources[src] = [];
      sources[src].push(d.name);
      for (const pn of d.process_names || []) allProcessNames.add(pn);
    }

    return {
      technique_id: techniqueId,
      total_detections: filtered.length,
      has_procedure_reference: false,
      message: `No procedure reference data for ${techniqueId}. Showing detection inventory. Procedures are auto-extracted at index time for techniques with 2+ detections.`,
      detections_by_source: sources,
      process_names_observed: Array.from(allProcessNames),
    };
  }

  // Match each detection against procedures
  const detectionMatches = filtered.map(d => matchDetectionToProcedures(d, procedures, includeSnippets));

  // Aggregate: which procedures are covered?
  const procedureCoverage: Record<string, { detection_count: number; sources: Set<string>; detections: string[] }> = {};
  for (const proc of procedures) {
    procedureCoverage[proc.id] = { detection_count: 0, sources: new Set(), detections: [] };
  }
  for (const dm of detectionMatches) {
    for (const procId of dm.procedures_matched) {
      const pc = procedureCoverage[procId];
      if (pc) {
        pc.detection_count++;
        pc.sources.add(dm.source_type);
        if (pc.detections.length < 5) pc.detections.push(dm.detection_name);
      }
    }
  }

  const covered = [];
  const uncovered = [];

  for (const proc of procedures) {
    const pc = procedureCoverage[proc.id];
    if (pc.detection_count > 0) {
      covered.push({
        procedure: proc.name,
        id: proc.id,
        category: proc.category,
        detection_count: pc.detection_count,
        sources: Array.from(pc.sources),
        detections: pc.detections,
      });
    } else {
      uncovered.push({
        procedure: proc.name,
        id: proc.id,
        category: proc.category,
        description: proc.description,
        recommendation: `Add detection for: ${proc.description}`,
      });
    }
  }

  // Coverage depth
  const coveredCount = covered.length;
  const totalProcs = procedures.length;
  let coverage_depth: string;
  const coverageRatio = coveredCount / totalProcs;
  if (coverageRatio >= 0.8 && coveredCount >= 5) coverage_depth = 'deep';
  else if (coverageRatio >= 0.5 && coveredCount >= 3) coverage_depth = 'moderate';
  else if (coveredCount >= 1) coverage_depth = 'shallow';
  else coverage_depth = 'none';

  // Unmatched detections (detections that didn't match any procedure)
  const unmatchedCount = detectionMatches.filter(dm => dm.procedures_matched.length === 0).length;

  return {
    technique_id: techniqueId,
    total_detections: filtered.length,
    coverage_depth,
    procedures_covered: coveredCount,
    procedures_total: totalProcs,
    coverage_percent: Math.round((coveredCount / totalProcs) * 100),
    covered,
    uncovered,
    unmatched_detections: unmatchedCount,
    unmatched_note: unmatchedCount > 0
      ? `${unmatchedCount} detection(s) didn't match any known procedure. They may cover behaviors not yet in the reference data.`
      : undefined,
  };
}

function compareProcedureCoverage(techniqueId: string, sources?: string[]) {
  const procedures = getProcedures(techniqueId);
  const detections = listByMitre(techniqueId, 500);

  if (!procedures) {
    return {
      technique_id: techniqueId,
      has_procedure_reference: false,
      message: `No procedure reference data for ${techniqueId}. Procedures are auto-extracted at index time for techniques with 2+ detections.`,
    };
  }

  // Determine available sources
  const availableSources = new Set<string>(detections.map(d => d.source_type));
  const sourcesToCompare = sources
    ? sources.filter(s => availableSources.has(s))
    : Array.from(availableSources);

  if (sourcesToCompare.length === 0) {
    return {
      technique_id: techniqueId,
      message: 'No detections found for the requested sources',
      available_sources: Array.from(availableSources),
    };
  }

  // Build matrix: procedure × source
  const matrix: Record<string, Record<string, { covered: boolean; count: number; detections: string[] }>> = {};
  for (const proc of procedures) {
    matrix[proc.id] = {};
    for (const src of sourcesToCompare) {
      matrix[proc.id][src] = { covered: false, count: 0, detections: [] };
    }
  }

  // Fill matrix
  for (const src of sourcesToCompare) {
    const srcDetections = detections.filter(d => d.source_type === src);
    const matches = srcDetections.map(d => matchDetectionToProcedures(d, procedures, false));

    for (const dm of matches) {
      for (const procId of dm.procedures_matched) {
        if (matrix[procId]?.[src]) {
          matrix[procId][src].covered = true;
          matrix[procId][src].count++;
          if (matrix[procId][src].detections.length < 3) {
            matrix[procId][src].detections.push(dm.detection_name);
          }
        }
      }
    }
  }

  // Build readable comparison
  const comparison = procedures.map(proc => {
    const row: Record<string, unknown> = { procedure: proc.name, id: proc.id, category: proc.category };
    let coveredByCount = 0;
    const coveredBy: string[] = [];

    for (const src of sourcesToCompare) {
      const cell = matrix[proc.id][src];
      row[src] = cell.covered ? `${cell.count} detection(s)` : '—';
      if (cell.covered) {
        coveredByCount++;
        coveredBy.push(src);
      }
    }

    row.covered_by_sources = coveredByCount;
    row.redundancy = coveredByCount > 1 ? 'redundant' : coveredByCount === 1 ? 'single-source' : 'gap';
    return row;
  });

  // Summary
  const totalProcs = procedures.length;
  const fullyCovered = comparison.filter(r => r.redundancy === 'redundant').length;
  const singleSource = comparison.filter(r => r.redundancy === 'single-source').length;
  const gaps = comparison.filter(r => r.redundancy === 'gap').length;

  // Per-source score
  const sourceScores: Record<string, { procedures_covered: number; total: number; percent: number }> = {};
  for (const src of sourcesToCompare) {
    const covered = comparison.filter(r => {
      const val = r[src] as string;
      return val !== '—';
    }).length;
    sourceScores[src] = { procedures_covered: covered, total: totalProcs, percent: Math.round((covered / totalProcs) * 100) };
  }

  return {
    technique_id: techniqueId,
    sources_compared: sourcesToCompare,
    procedures_total: totalProcs,
    summary: {
      multi_source_coverage: fullyCovered,
      single_source_only: singleSource,
      uncovered_gaps: gaps,
    },
    source_scores: sourceScores,
    matrix: comparison,
  };
}
