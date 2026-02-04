/**
 * Autonomous Analysis Tools
 * 
 * Tools that leverage MCP sampling (when available) to perform
 * autonomous analysis tasks, store findings, and build knowledge.
 * 
 * These tools combine multiple operations:
 * - Run analysis (coverage, gaps, comparisons)
 * - Request LLM reasoning via sampling (when supported)
 * - Store results in dynamic tables
 * - Log decisions and reasoning in knowledge graph
 * - Build entity relationships for threat actors
 * 
 * Note: Sampling requires client support. If not available, tools
 * fall back to direct analysis without LLM-enhanced reasoning.
 */

import { defineTool } from '../registry.js';
import {
  analyzeCoverage,
  identifyGaps,
  searchDetections,
  compareDetectionsBySource,
  getStats,
  listBySource,
  listByMitreTactic,
  type GapAnalysis,
  type CoverageReport,
} from '../../db/index.js';
import {
  initDynamicSchema,
  insertDynamicRow,
  queryDynamicTable,
} from '../../db/dynamic.js';
import {
  createEntity,
  createRelation,
  addObservation,
  logDecision,
  getEntity,
} from '../../db/knowledge.js';
import { randomUUID } from 'crypto';
import { requestAnalysis, getSamplingStatus } from '../../handlers/sampling.js';

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Format current timestamp for storage
 */
function now(): string {
  return new Date().toISOString();
}

/**
 * Safe division to avoid divide-by-zero
 */
function safeDivide(numerator: number, denominator: number, defaultValue = 0): number {
  if (denominator === 0) return defaultValue;
  return numerator / denominator;
}

/**
 * Ensure dynamic tables are initialized
 */
function ensureDynamicSchema(): void {
  try {
    initDynamicSchema();
  } catch {
    // Already initialized
  }
}

// ============================================================================
// Tool 1: auto_analyze_coverage
// ============================================================================

export const autoAnalyzeCoverage = defineTool({
  name: 'auto_analyze_coverage',
  description: `Automatically analyze detection coverage, identify gaps across threat profiles, and store findings for future reference.

This tool:
1. Runs coverage analysis across all detections
2. Identifies gaps for specified threat profiles (ransomware, apt, etc.)
3. Stores results in the gap_analyses dynamic table
4. Logs decisions about significant findings in the knowledge graph

Use this for comprehensive, stored analysis that persists across sessions.`,
  inputSchema: {
    type: 'object',
    properties: {
      threat_profiles: {
        type: 'array',
        items: { type: 'string' },
        description: 'Threat profiles to analyze. Options: ransomware, apt, initial-access, persistence, credential-access, defense-evasion. Default: ["ransomware", "apt"]',
      },
      store_results: {
        type: 'boolean',
        description: 'Store results in dynamic tables for persistence (default: true)',
      },
      analysis_name: {
        type: 'string',
        description: 'Optional name for this analysis run (defaults to timestamp-based name)',
      },
      session_id: {
        type: 'string',
        description: 'Optional session ID to group related analyses',
      },
    },
  },
  handler: async (args) => {
    const threatProfiles = (args.threat_profiles as string[]) || ['ransomware', 'apt'];
    const storeResults = args.store_results !== false;
    const analysisName = (args.analysis_name as string) || `Coverage Analysis ${now()}`;
    const sessionId = args.session_id as string | undefined;

    // Initialize dynamic schema if storing results
    if (storeResults) {
      ensureDynamicSchema();
    }

    // Run overall coverage analysis
    const coverage = analyzeCoverage() as CoverageReport;
    const stats = getStats();

    // Analyze each threat profile
    const profileResults: Array<{
      profile: string;
      gaps: GapAnalysis;
      stored_id?: string;
    }> = [];

    for (const profile of threatProfiles) {
      const gaps = identifyGaps(profile) as GapAnalysis;

      let storedId: string | undefined;
      if (storeResults) {
        // Store in gap_analyses table
        storedId = randomUUID();
        const insertResult = insertDynamicRow('gap_analyses', {
          id: storedId,
          name: `${analysisName} - ${profile}`,
          threat_profile: profile,
          total_techniques: gaps.critical_gaps.length + gaps.covered.length,
          covered_techniques: gaps.covered.length,
          coverage_percentage: safeDivide(gaps.covered.length, gaps.critical_gaps.length + gaps.covered.length) * 100,
          gaps: JSON.stringify(gaps.critical_gaps.map(g => g.technique)),
          recommendations: JSON.stringify(gaps.recommendations),
          created_at: now(),
        });

        if (!insertResult.success) {
          console.warn(`Failed to store gap analysis for ${profile}: ${insertResult.error}`);
        }
      }

      profileResults.push({
        profile,
        gaps,
        stored_id: storedId,
      });

      // Log decision for significant gaps
      if (gaps.critical_gaps.length > 0) {
        const topGaps = gaps.critical_gaps.slice(0, 5);
        logDecision(
          'gap_identified',
          `Analyzing ${profile} threat profile coverage`,
          `Found ${gaps.critical_gaps.length} critical gaps in ${profile} coverage`,
          `Top gaps identified: ${topGaps.map(g => `${g.technique} (${g.priority})`).join(', ')}. ` +
          `Covered ${gaps.covered.length} techniques. Recommendations: ${gaps.recommendations.slice(0, 2).join('; ')}`,
          [profile, ...topGaps.map(g => g.technique)],
          `Stored analysis with ID ${storedId}`,
          sessionId
        );
      }
    }

    // Summarize findings
    const totalGaps = profileResults.reduce((sum, r) => sum + r.gaps.critical_gaps.length, 0);
    const totalCovered = profileResults.reduce((sum, r) => sum + r.gaps.covered.length, 0);

    return {
      status: 'completed',
      analysis_name: analysisName,
      summary: {
        profiles_analyzed: threatProfiles.length,
        total_detections: stats.total,
        total_gaps_found: totalGaps,
        total_techniques_covered: totalCovered,
        coverage_by_tactic: coverage.summary.coverage_by_tactic,
      },
      profile_results: profileResults.map(r => ({
        profile: r.profile,
        gaps_count: r.gaps.critical_gaps.length,
        covered_count: r.gaps.covered.length,
        top_critical_gaps: r.gaps.critical_gaps.slice(0, 5),
        recommendations: r.gaps.recommendations.slice(0, 3),
        stored_id: r.stored_id,
      })),
      weak_coverage_areas: coverage.weak_coverage.slice(0, 10),
      results_stored: storeResults,
      note: storeResults
        ? 'Results stored in gap_analyses table and decisions logged to knowledge graph'
        : 'Results not stored (store_results=false)',
    };
  },
});

// ============================================================================
// Tool 2: auto_gap_report
// ============================================================================

export const autoGapReport = defineTool({
  name: 'auto_gap_report',
  description: `Generate a comprehensive gap report comparing detection coverage across sources (Sigma, Splunk ESCU, Elastic, KQL) and threat profiles.

This tool:
1. Analyzes all threat profiles for gaps
2. Compares detection coverage across different sources
3. Creates prioritized recommendations based on severity and coverage
4. Stores the complete report in dynamic tables

Use this for executive-level reporting on detection posture.`,
  inputSchema: {
    type: 'object',
    properties: {
      report_name: {
        type: 'string',
        description: 'Name for this report (defaults to timestamp-based name)',
      },
      compare_sources: {
        type: 'boolean',
        description: 'Include source comparison analysis (default: true)',
      },
      include_recommendations: {
        type: 'boolean',
        description: 'Generate prioritized recommendations (default: true)',
      },
      priority_tactics: {
        type: 'array',
        items: { type: 'string' },
        description: 'Tactics to prioritize in recommendations. Options: execution, persistence, credential-access, defense-evasion, lateral-movement, exfiltration, impact',
      },
      session_id: {
        type: 'string',
        description: 'Optional session ID to group related reports',
      },
    },
  },
  handler: async (args) => {
    const reportName = (args.report_name as string) || `Gap Report ${now()}`;
    const compareSources = args.compare_sources !== false;
    const includeRecommendations = args.include_recommendations !== false;
    const priorityTactics = (args.priority_tactics as string[]) || ['execution', 'credential-access', 'defense-evasion'];
    const sessionId = args.session_id as string | undefined;

    ensureDynamicSchema();

    const stats = getStats();
    const coverage = analyzeCoverage() as CoverageReport;

    // Analyze all threat profiles
    const allProfiles = ['ransomware', 'apt', 'initial-access', 'persistence', 'credential-access', 'defense-evasion'];
    const profileGaps: Record<string, GapAnalysis> = {};

    for (const profile of allProfiles) {
      profileGaps[profile] = identifyGaps(profile) as GapAnalysis;
    }

    // Source comparison if requested
    let sourceComparison: Record<string, unknown> | undefined;
    if (compareSources) {
      // Compare detections across sources for high-priority techniques
      const highPriorityTechniques = ['T1059.001', 'T1003.001', 'T1547.001', 'T1486', 'T1078'];
      const sourceStats: Record<string, number> = {};

      for (const source of ['sigma', 'splunk_escu', 'elastic', 'kql'] as const) {
        const detections = listBySource(source, 9999);
        sourceStats[source] = detections.length;
      }

      sourceComparison = {
        source_counts: sourceStats,
        priority_technique_coverage: highPriorityTechniques.map(tech => {
          const comparison = compareDetectionsBySource(tech);
          return {
            technique: tech,
            total: comparison.total_found,
            by_source: comparison.summary.source_counts,
          };
        }),
      };
    }

    // Generate prioritized recommendations
    const recommendations: Array<{
      technique: string;
      priority: 'critical' | 'high' | 'medium';
      reason: string;
      affected_profiles: string[];
      recommendation: string;
    }> = [];

    if (includeRecommendations) {
      // Collect all critical gaps
      const techniqueGapCount: Record<string, { count: number; profiles: string[] }> = {};

      for (const [profile, gaps] of Object.entries(profileGaps)) {
        for (const gap of gaps.critical_gaps) {
          if (!techniqueGapCount[gap.technique]) {
            techniqueGapCount[gap.technique] = { count: 0, profiles: [] };
          }
          techniqueGapCount[gap.technique].count++;
          techniqueGapCount[gap.technique].profiles.push(profile);
        }
      }

      // Sort by frequency and create recommendations
      const sortedGaps = Object.entries(techniqueGapCount)
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 15);

      for (const [technique, data] of sortedGaps) {
        const priority = data.count >= 4 ? 'critical' : data.count >= 2 ? 'high' : 'medium';
        recommendations.push({
          technique,
          priority,
          reason: `Missing from ${data.count} threat profiles`,
          affected_profiles: data.profiles,
          recommendation: `Create detection for ${technique} - impacts ${data.profiles.join(', ')} coverage`,
        });
      }

      // Store recommendations in dynamic table
      for (const rec of recommendations.slice(0, 10)) {
        const recId = randomUUID();
        insertDynamicRow('detection_recommendations', {
          id: recId,
          technique_id: rec.technique,
          technique_name: rec.technique, // Could be enhanced with technique name lookup
          priority: rec.priority,
          recommendation_type: 'new_detection',
          description: rec.recommendation,
          implementation_notes: `Affects profiles: ${rec.affected_profiles.join(', ')}`,
          status: 'pending',
          related_gap_analysis_id: reportName,
          created_at: now(),
        });
      }
    }

    // Log decision about the report
    logDecision(
      'coverage_mapped',
      `Generating comprehensive gap report: ${reportName}`,
      `Completed analysis of ${allProfiles.length} threat profiles across ${stats.total} detections`,
      `Found ${recommendations.length} prioritized recommendations. ` +
      `Weakest coverage in: ${coverage.weak_coverage.slice(0, 3).map(w => w.technique).join(', ')}. ` +
      `Top priority: ${recommendations.slice(0, 3).map(r => r.technique).join(', ')}`,
      [...allProfiles, ...recommendations.slice(0, 5).map(r => r.technique)],
      `Report generated with ${recommendations.length} recommendations`,
      sessionId
    );

    // Build summary
    const summaryByProfile = Object.entries(profileGaps).map(([profile, gaps]) => ({
      profile,
      total_techniques: gaps.critical_gaps.length + gaps.covered.length,
      covered: gaps.covered.length,
      gaps: gaps.critical_gaps.length,
      coverage_percent: Math.round(safeDivide(gaps.covered.length, gaps.critical_gaps.length + gaps.covered.length) * 100),
    }));

    return {
      status: 'completed',
      report_name: reportName,
      generated_at: now(),
      summary: {
        total_detections: stats.total,
        profiles_analyzed: allProfiles.length,
        total_recommendations: recommendations.length,
        coverage_by_tactic: coverage.summary.coverage_by_tactic,
      },
      profile_coverage: summaryByProfile,
      source_comparison: sourceComparison,
      prioritized_recommendations: recommendations,
      weak_coverage_techniques: coverage.weak_coverage.slice(0, 10),
      strong_coverage_techniques: coverage.top_covered.slice(0, 5),
      note: 'Results stored in detection_recommendations table. Recommendations sorted by cross-profile impact.',
    };
  },
});

// ============================================================================
// Tool 3: auto_compare_sources
// ============================================================================

export const autoCompareSources = defineTool({
  name: 'auto_compare_sources',
  description: `Autonomously compare detection coverage across different sources (Sigma, Splunk ESCU, Elastic, KQL) with detailed reasoning and analysis.

This tool:
1. Compares detection counts and coverage across all available sources
2. Analyzes technique-level coverage differences between sources
3. Identifies which source has best coverage for specific tactics/techniques
4. Provides reasoned recommendations for source selection
5. Stores comparison results and logs decision reasoning

Use this to understand the strengths/weaknesses of different detection sources and make informed decisions about which to use.`,
  inputSchema: {
    type: 'object',
    properties: {
      techniques_to_compare: {
        type: 'array',
        items: { type: 'string' },
        description: 'Specific MITRE technique IDs to compare (e.g., ["T1059.001", "T1003.001"]). If not provided, uses high-priority techniques.',
      },
      focus_tactic: {
        type: 'string',
        enum: ['execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact'],
        description: 'Focus comparison on a specific MITRE ATT&CK tactic',
      },
      include_quality_analysis: {
        type: 'boolean',
        description: 'Include analysis of detection quality indicators (default: true)',
      },
      session_id: {
        type: 'string',
        description: 'Optional session ID to group related comparisons',
      },
    },
  },
  handler: async (args) => {
    const techniquesToCompare = (args.techniques_to_compare as string[]) || [
      'T1059.001', // PowerShell
      'T1003.001', // LSASS Memory
      'T1547.001', // Registry Run Keys
      'T1486',     // Data Encrypted for Impact
      'T1078',     // Valid Accounts
      'T1055',     // Process Injection
      'T1021.001', // Remote Desktop Protocol
      'T1070.001', // Clear Windows Event Logs
      'T1036.003', // Rename System Utilities
      'T1027',     // Obfuscated Files
    ];
    const focusTactic = args.focus_tactic as string | undefined;
    const includeQualityAnalysis = args.include_quality_analysis !== false;
    const sessionId = args.session_id as string | undefined;

    ensureDynamicSchema();

    const sources = ['sigma', 'splunk_escu', 'elastic', 'kql'] as const;
    
    // Get overall stats by source
    const sourceStats: Record<string, { total: number; coverage: CoverageReport }> = {};
    for (const source of sources) {
      const detections = listBySource(source, 9999);
      const coverage = analyzeCoverage(source) as CoverageReport;
      sourceStats[source] = {
        total: detections.length,
        coverage,
      };
    }

    // Compare technique-by-technique coverage
    const techniqueComparisons: Array<{
      technique: string;
      total_detections: number;
      by_source: Record<string, number>;
      best_source: string;
      coverage_gap_sources: string[];
      reasoning: string;
    }> = [];

    for (const technique of techniquesToCompare) {
      const comparison = compareDetectionsBySource(technique);
      const sourceCounts = comparison.summary.source_counts as Record<string, number>;
      
      // Find best source for this technique
      let bestSource = 'none';
      let maxCount = 0;
      const gapSources: string[] = [];
      
      for (const source of sources) {
        const count = sourceCounts[source] || 0;
        if (count > maxCount) {
          maxCount = count;
          bestSource = source;
        }
        if (count === 0) {
          gapSources.push(source);
        }
      }

      // Generate reasoning
      let reasoning = '';
      if (maxCount === 0) {
        reasoning = `No detections found for ${technique} in any source - critical gap`;
      } else if (gapSources.length > 0) {
        reasoning = `${bestSource} leads with ${maxCount} detections. Missing from: ${gapSources.join(', ')}`;
      } else {
        const sortedSources = Object.entries(sourceCounts)
          .filter(([, count]) => count > 0)
          .sort((a, b) => b[1] - a[1]);
        reasoning = `Coverage across all sources. ${sortedSources.map(([s, c]) => `${s}(${c})`).join(' > ')}`;
      }

      techniqueComparisons.push({
        technique,
        total_detections: comparison.total_found,
        by_source: sourceCounts,
        best_source: bestSource,
        coverage_gap_sources: gapSources,
        reasoning,
      });
    }

    // Analyze tactic-level coverage if focused
    let tacticAnalysis: Record<string, unknown> | undefined;
    if (focusTactic) {
      const tacticComparison: Record<string, { count: number; techniques: string[] }> = {};
      for (const source of sources) {
        // Get all detections for this source, then filter by tactic
        const allDetections = listByMitreTactic(focusTactic, 500);
        const detections = allDetections.filter(d => d.source_type === source);
        const techniques = new Set<string>();
        for (const d of detections) {
          for (const t of d.mitre_ids || []) {
            techniques.add(t);
          }
        }
        tacticComparison[source] = {
          count: detections.length,
          techniques: Array.from(techniques),
        };
      }
      tacticAnalysis = {
        tactic: focusTactic,
        comparison: tacticComparison,
        best_source: Object.entries(tacticComparison)
          .sort((a, b) => b[1].count - a[1].count)[0]?.[0] || 'none',
      };
    }

    // Quality indicators analysis
    let qualityAnalysis: Record<string, unknown> | undefined;
    if (includeQualityAnalysis) {
      const qualityMetrics: Record<string, {
        avg_techniques_per_detection: number;
        high_severity_ratio: number;
        unique_techniques: number;
      }> = {};

      for (const source of sources) {
        const coverage = sourceStats[source].coverage;
        const total = sourceStats[source].total;
        
        // Calculate unique techniques covered
        const uniqueTechs = new Set<string>();
        for (const tc of coverage.top_covered || []) {
          uniqueTechs.add(tc.technique);
        }
        for (const wc of coverage.weak_coverage || []) {
          uniqueTechs.add(wc.technique);
        }

        qualityMetrics[source] = {
          avg_techniques_per_detection: total > 0 ? uniqueTechs.size / total : 0,
          high_severity_ratio: coverage.summary.total_detections > 0 
            ? (coverage.top_covered.length / coverage.summary.total_detections) 
            : 0,
          unique_techniques: uniqueTechs.size,
        };
      }
      qualityAnalysis = qualityMetrics;
    }

    // Generate overall recommendations with reasoning
    const recommendations: Array<{
      recommendation: string;
      reasoning: string;
      priority: 'high' | 'medium' | 'low';
    }> = [];

    // Find best overall source
    const sortedByTotal = Object.entries(sourceStats)
      .sort((a, b) => b[1].total - a[1].total);
    
    recommendations.push({
      recommendation: `Use ${sortedByTotal[0][0]} as primary source for broad coverage`,
      reasoning: `${sortedByTotal[0][0]} has ${sortedByTotal[0][1].total} detections, ` +
        `${sortedByTotal.slice(1).map(([s, d]) => `vs ${s}(${d.total})`).join(', ')}`,
      priority: 'high',
    });

    // Find gaps to fill
    const techniqueGaps = techniqueComparisons.filter(tc => tc.coverage_gap_sources.length > 0);
    if (techniqueGaps.length > 0) {
      recommendations.push({
        recommendation: `Address ${techniqueGaps.length} technique gaps across sources`,
        reasoning: `${techniqueGaps.slice(0, 3).map(g => `${g.technique} missing from ${g.coverage_gap_sources.join(',')}`).join('; ')}`,
        priority: 'high',
      });
    }

    // Source-specific recommendations
    const noDetectionSources = sources.filter(s => sourceStats[s].total === 0);
    if (noDetectionSources.length > 0) {
      recommendations.push({
        recommendation: `Import detections from ${noDetectionSources.join(', ')} to expand coverage`,
        reasoning: `These sources have 0 detections indexed`,
        priority: 'medium',
      });
    }

    // Log decision
    logDecision(
      'source_comparison',
      'Comparing detection sources for coverage analysis',
      `Completed comparison of ${sources.length} sources across ${techniquesToCompare.length} techniques`,
      `Source totals: ${sortedByTotal.map(([s, d]) => `${s}(${d.total})`).join(', ')}. ` +
      `Found ${techniqueGaps.length} techniques with source gaps. ` +
      `Recommendations: ${recommendations.slice(0, 2).map(r => r.recommendation).join('; ')}`,
      ['source_comparison', ...techniquesToCompare.slice(0, 5)],
      `Generated ${recommendations.length} recommendations`,
      sessionId
    );

    // Store comparison result
    const comparisonId = randomUUID();
    insertDynamicRow('source_comparisons', {
      id: comparisonId,
      techniques_compared: JSON.stringify(techniquesToCompare),
      focus_tactic: focusTactic || null,
      source_totals: JSON.stringify(Object.fromEntries(
        Object.entries(sourceStats).map(([s, d]) => [s, d.total])
      )),
      technique_results: JSON.stringify(techniqueComparisons),
      recommendations: JSON.stringify(recommendations),
      created_at: now(),
    });

    return {
      status: 'completed',
      comparison_id: comparisonId,
      summary: {
        sources_compared: sources.length,
        techniques_analyzed: techniquesToCompare.length,
        source_totals: Object.fromEntries(
          Object.entries(sourceStats).map(([s, d]) => [s, d.total])
        ),
        techniques_with_gaps: techniqueGaps.length,
      },
      source_rankings: sortedByTotal.map(([source, data], index) => ({
        rank: index + 1,
        source,
        total_detections: data.total,
        unique_techniques: data.coverage.summary.total_techniques,
      })),
      technique_comparison: techniqueComparisons,
      tactic_analysis: tacticAnalysis,
      quality_analysis: qualityAnalysis,
      recommendations,
      next_actions: [
        `Review ${techniqueGaps.length} techniques with source-specific gaps`,
        `Consider ${sortedByTotal[0][0]} as primary source (${sortedByTotal[0][1].total} detections)`,
        focusTactic ? `Deep-dive into ${focusTactic} tactic coverage` : 'Analyze specific tactics with focus_tactic parameter',
        'Use log_decision() to record your source selection reasoning',
      ],
      note: 'Comparison stored in source_comparisons table. Use technique_comparison for detailed source-by-source breakdown.',
    };
  },
});

// ============================================================================
// Tool 4: llm_enhanced_analysis (Sampling-powered)
// ============================================================================

export const llmEnhancedAnalysis = defineTool({
  name: 'llm_enhanced_analysis',
  description: `Request LLM-enhanced analysis of security detection data using MCP sampling.

This tool leverages MCP sampling to request the client's LLM to analyze security data with expert reasoning. Unlike the auto_* tools that perform direct analysis, this tool asks the LLM to provide contextual insights.

Note: Requires client to support MCP sampling capability. If not supported, falls back to structured data output.

Use cases:
- Get expert reasoning about coverage gaps
- Generate detection recommendations with context
- Compare sources with nuanced analysis
- Understand threat profile implications`,
  inputSchema: {
    type: 'object',
    properties: {
      analysis_type: {
        type: 'string',
        enum: ['coverage', 'gaps', 'comparison', 'recommendation'],
        description: 'Type of analysis to request',
      },
      threat_profile: {
        type: 'string',
        description: 'Threat profile context (e.g., ransomware, apt)',
      },
      techniques: {
        type: 'array',
        items: { type: 'string' },
        description: 'Specific techniques to analyze (optional)',
      },
      custom_context: {
        type: 'string',
        description: 'Additional context for the analysis',
      },
    },
    required: ['analysis_type'],
  },
  handler: async (args) => {
    const analysisType = args.analysis_type as 'coverage' | 'gaps' | 'comparison' | 'recommendation';
    const threatProfile = args.threat_profile as string | undefined;
    const techniques = args.techniques as string[] | undefined;
    const customContext = args.custom_context as string | undefined;

    // Check sampling status first
    const samplingStatus = getSamplingStatus();
    
    // Gather relevant data based on analysis type
    let analysisData: Record<string, unknown> = {};
    
    switch (analysisType) {
      case 'coverage':
        // analyzeCoverage expects a source type, not threat profile
        // Pass undefined to get overall coverage
        analysisData = {
          coverage: analyzeCoverage(),
          stats: getStats(),
          threat_profile: threatProfile,
        };
        break;
        
      case 'gaps':
        analysisData = {
          gaps: identifyGaps(threatProfile || 'ransomware'),
          threat_profile: threatProfile || 'ransomware',
        };
        break;
        
      case 'comparison':
        const comparisonTechniques = techniques || ['T1059.001', 'T1003.001', 'T1547.001'];
        analysisData = {
          techniques: comparisonTechniques,
          comparisons: comparisonTechniques.map(t => ({
            technique: t,
            ...compareDetectionsBySource(t).summary,
          })),
          source_totals: {
            sigma: listBySource('sigma', 9999).length,
            splunk_escu: listBySource('splunk_escu', 9999).length,
            elastic: listBySource('elastic', 9999).length,
            kql: listBySource('kql', 9999).length,
          },
        };
        break;
        
      case 'recommendation':
        const gaps = identifyGaps(threatProfile || 'ransomware') as GapAnalysis;
        analysisData = {
          critical_gaps: gaps.critical_gaps.slice(0, 10),
          threat_profile: threatProfile || 'ransomware',
          existing_recommendations: gaps.recommendations,
        };
        break;
    }

    // Attempt LLM-enhanced analysis via sampling
    const llmAnalysis = await requestAnalysis(
      analysisType,
      analysisData,
      customContext
    );

    if (llmAnalysis) {
      // Sampling succeeded - log the decision with LLM reasoning
      logDecision(
        'llm_analysis',
        `LLM-enhanced ${analysisType} analysis`,
        `Generated ${analysisType} analysis with LLM reasoning`,
        llmAnalysis.reasoning,
        [analysisType, threatProfile || 'general'].filter(Boolean),
        'Analysis complete with LLM enhancement'
      );

      return {
        status: 'completed',
        sampling_used: true,
        analysis_type: analysisType,
        llm_analysis: llmAnalysis.analysis,
        reasoning_source: llmAnalysis.reasoning,
        raw_data: analysisData,
        note: 'Analysis enhanced with LLM reasoning via MCP sampling',
      };
    } else {
      // Sampling not available - return structured data
      logDecision(
        'fallback_analysis',
        `Direct ${analysisType} analysis (sampling unavailable)`,
        `Generated ${analysisType} analysis without LLM enhancement`,
        `Sampling status: ${samplingStatus.reason}`,
        [analysisType, threatProfile || 'general'].filter(Boolean),
        'Analysis complete without LLM enhancement'
      );

      return {
        status: 'completed',
        sampling_used: false,
        sampling_status: samplingStatus,
        analysis_type: analysisType,
        data: analysisData,
        note: 'LLM sampling not available. Use the auto_* tools for detailed direct analysis, or try again when client supports sampling.',
        recommendations: [
          'Review the raw data for insights',
          'Use auto_analyze_coverage for comprehensive coverage analysis',
          'Use auto_gap_report for prioritized gap recommendations',
        ],
      };
    }
  },
});

// ============================================================================
// Tool 5: check_sampling_status
// ============================================================================

export const checkSamplingStatus = defineTool({
  name: 'check_sampling_status',
  description: `Check if MCP sampling is available for LLM-enhanced analysis.

Sampling allows the server to request LLM completions from the client, enabling richer autonomous analysis. Not all MCP clients support this feature.

Use this tool to check capability before using llm_enhanced_analysis.`,
  inputSchema: {
    type: 'object',
    properties: {},
  },
  handler: async () => {
    const status = getSamplingStatus();
    
    return {
      ...status,
      feature_description: 'MCP Sampling allows the server to request LLM analysis from the client',
      dependent_tools: [
        'llm_enhanced_analysis - Full LLM-powered analysis',
      ],
      fallback_tools: [
        'auto_analyze_coverage - Direct coverage analysis',
        'auto_gap_report - Direct gap analysis',
        'auto_compare_sources - Direct source comparison',
      ],
    };
  },
});

// ============================================================================
// Exports
// ============================================================================

export const autonomousTools = [
  autoAnalyzeCoverage,
  autoGapReport,
  autoCompareSources,
  llmEnhancedAnalysis,
  checkSamplingStatus,
];

export const autonomousToolCount = autonomousTools.length;
