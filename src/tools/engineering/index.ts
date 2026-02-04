/**
 * Detection Engineering Intelligence Tools
 * 
 * Tools that help generate production-quality detections based on
 * patterns learned from indexed content. These tools enable:
 * - Query pattern retrieval by technique
 * - Field reference lookup by data model
 * - Template generation based on learned conventions
 * - User preference learning for continuous improvement
 */

import { defineTool } from '../registry.js';
import {
  getPatternsByTechnique,
  getFieldReference,
  getStyleConventions,
  getMacroReference,
  extractAllPatterns,
  getPatternStats,
  storeStyleConvention,
  type TechniquePatterns,
} from '../../db/patterns.js';
import {
  listByMitre,
  searchDetections,
  getDetectionById,
  getRawYaml,
} from '../../db/detections.js';
import { addLearning, logDecision } from '../../db/knowledge.js';

// =============================================================================
// PATTERN RETRIEVAL TOOLS
// =============================================================================

const getQueryPatternsTool = defineTool({
  name: 'get_query_patterns',
  description: 'Get common query patterns for a MITRE technique based on existing detections. Returns SPL structure, common fields, macros used, and example queries. Use this before writing a detection to learn the conventions.',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: {
        type: 'string',
        description: 'MITRE technique ID (e.g., T1059.001, T1003.001)',
      },
      source_type: {
        type: 'string',
        enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
        description: 'Filter patterns by source type (optional)',
      },
    },
    required: ['technique_id'],
  },
  handler: async (args) => {
    const techniqueId = args.technique_id as string;
    const sourceType = args.source_type as string | undefined;
    
    const patterns = getPatternsByTechnique(techniqueId, sourceType);
    const examples = listByMitre(techniqueId, 5);
    
    if (patterns.count === 0 && examples.length === 0) {
      return {
        technique: techniqueId,
        found: false,
        message: `No existing patterns found for ${techniqueId}. This is a coverage gap - you'll need to create a new detection pattern.`,
        suggestions: [
          'Check parent technique (e.g., T1059 instead of T1059.001)',
          'Search for similar techniques in the same tactic',
          'Use get_field_reference to understand available fields',
        ],
      };
    }
    
    return {
      technique: techniqueId,
      found: true,
      patterns: {
        count: patterns.count,
        data_models_used: patterns.data_models,
        common_macros: patterns.macros.slice(0, 10),
        common_fields: patterns.fields.slice(0, 15),
        most_common_data_model: patterns.most_common_data_model,
        query_structures: patterns.spl_structure.slice(0, 3).map(p => ({
          uses_tstats: p.uses_tstats,
          data_model: p.uses_datamodel,
          aggregations: p.aggregations,
          where_patterns: p.where_patterns,
        })),
      },
      examples: examples.map(e => ({
        name: e.name,
        id: e.id,
        severity: e.severity,
        query_preview: (e.query || '').substring(0, 300) + (e.query && e.query.length > 300 ? '...' : ''),
        data_sources: e.data_sources?.slice(0, 3),
      })),
      recommendation: `Based on ${patterns.count} existing detections. Most use ${patterns.most_common_data_model || 'direct event queries'}.`,
    };
  },
});

const getFieldReferenceTool = defineTool({
  name: 'get_field_reference',
  description: 'Get available fields for a Splunk data model with usage examples. Use this to understand what fields are available when writing a detection query.',
  inputSchema: {
    type: 'object',
    properties: {
      data_model: {
        type: 'string',
        description: 'Data model name (e.g., Endpoint.Processes, Endpoint.Filesystem, Network_Traffic.All_Traffic)',
      },
    },
    required: ['data_model'],
  },
  handler: async (args) => {
    const dataModel = args.data_model as string;
    const fields = getFieldReference(dataModel);
    
    if (fields.length === 0) {
      // Return common fields for known data models
      const commonFields = getCommonFieldsForDataModel(dataModel);
      return {
        data_model: dataModel,
        found: false,
        message: `No extracted field usage for ${dataModel}. Here are the standard fields:`,
        standard_fields: commonFields,
        suggestion: 'Run extract_patterns to populate field references from indexed detections.',
      };
    }
    
    return {
      data_model: dataModel,
      found: true,
      field_count: fields.length,
      fields: fields.map(f => ({
        name: f.field_name,
        type: f.field_type,
        usage_count: f.usage_count,
        examples: f.usage_examples.slice(0, 2),
      })),
      most_used: fields.slice(0, 10).map(f => f.field_name),
    };
  },
});

const getMacroReferenceTool = defineTool({
  name: 'get_macro_reference',
  description: 'Get common Splunk macros and their usage patterns. Essential for writing detections that follow repository conventions.',
  inputSchema: {
    type: 'object',
    properties: {
      filter: {
        type: 'string',
        description: 'Filter macros by name (optional, e.g., "security_content")',
      },
    },
  },
  handler: async (args) => {
    const filter = args.filter as string | undefined;
    const macroMap = getMacroReference();
    
    let macros = Array.from(macroMap.entries()).map(([name, data]) => ({
      name,
      usage_count: data.count,
    }));
    
    if (filter) {
      macros = macros.filter(m => m.name.toLowerCase().includes(filter.toLowerCase()));
    }
    
    // Sort by usage count
    macros.sort((a, b) => b.usage_count - a.usage_count);
    
    // Get top macros with descriptions
    const essentialMacros = [
      { name: 'security_content_summariesonly', purpose: 'Use with tstats for accelerated data model queries' },
      { name: 'drop_dm_object_name(Processes)', purpose: 'Remove Processes. prefix from field names' },
      { name: 'drop_dm_object_name(Filesystem)', purpose: 'Remove Filesystem. prefix from field names' },
      { name: 'security_content_ctime(firstTime)', purpose: 'Format firstTime field for display' },
      { name: 'security_content_ctime(lastTime)', purpose: 'Format lastTime field for display' },
      { name: 'detection_name_filter', purpose: 'Custom filter macro for tuning (replace detection_name with actual name)' },
    ];
    
    return {
      total_macros: macros.length,
      essential_macros: essentialMacros,
      top_used: macros.slice(0, 20),
      usage_tip: 'Always include `security_content_summariesonly` with tstats and end with `detection_name_filter`',
    };
  },
});

const findSimilarDetectionsTool = defineTool({
  name: 'find_similar_detections',
  description: 'Find existing detections similar to what you want to create. Use this to learn from existing detection logic and structure.',
  inputSchema: {
    type: 'object',
    properties: {
      description: {
        type: 'string',
        description: 'Describe the behavior you want to detect (e.g., "PowerShell downloading files", "process injection via CreateRemoteThread")',
      },
      technique_id: {
        type: 'string',
        description: 'MITRE technique ID to narrow search (optional)',
      },
      source_type: {
        type: 'string',
        enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
        description: 'Filter by source type (optional)',
      },
      limit: {
        type: 'number',
        description: 'Maximum results (default 5)',
      },
    },
    required: ['description'],
  },
  handler: async (args) => {
    const description = args.description as string;
    const techniqueId = args.technique_id as string | undefined;
    const limit = (args.limit as number) || 5;
    
    // Search for similar detections
    let results = searchDetections(description, limit * 2);
    
    // If technique provided, prioritize those
    if (techniqueId) {
      const techniqueMatches = listByMitre(techniqueId, limit);
      // Merge and dedupe
      const ids = new Set(results.map(r => r.id));
      for (const tm of techniqueMatches) {
        if (!ids.has(tm.id)) {
          results.push(tm);
        }
      }
    }
    
    // Limit results
    results = results.slice(0, limit);
    
    if (results.length === 0) {
      return {
        found: false,
        message: `No similar detections found for: "${description}"`,
        suggestions: [
          'Try broader search terms',
          'Search by MITRE technique ID instead',
          'Check if the detection type exists in the repository',
        ],
      };
    }
    
    return {
      found: true,
      count: results.length,
      similar_detections: results.map(d => ({
        name: d.name,
        id: d.id,
        description: d.description?.substring(0, 200),
        mitre_ids: d.mitre_ids,
        severity: d.severity,
        detection_type: d.detection_type,
        data_sources: d.data_sources?.slice(0, 3),
        query_structure: {
          uses_tstats: d.query?.includes('tstats') || false,
          data_model: d.query?.match(/from datamodel=(\S+)/)?.[1] || null,
          length: d.query?.length || 0,
        },
      })),
      recommendation: 'Use get_raw_yaml(id) to see the full detection YAML for any of these.',
    };
  },
});

// =============================================================================
// GENERATION TOOLS
// =============================================================================

const suggestDetectionTemplateTool = defineTool({
  name: 'suggest_detection_template',
  description: 'Generate a detection template based on technique, learned patterns, and conventions. Returns YAML structure ready for customization.',
  inputSchema: {
    type: 'object',
    properties: {
      technique_id: {
        type: 'string',
        description: 'MITRE technique ID (e.g., T1059.001)',
      },
      description: {
        type: 'string',
        description: 'What behavior to detect (e.g., "PowerShell executing encoded commands")',
      },
      data_model: {
        type: 'string',
        description: 'Data model (e.g., Endpoint.Processes). If not specified, will use most common for technique.',
      },
      detection_type: {
        type: 'string',
        enum: ['TTP', 'Anomaly', 'Hunting'],
        description: 'Detection type (default: TTP)',
      },
      platform: {
        type: 'string',
        enum: ['Windows', 'Linux', 'macOS', 'AWS', 'Azure', 'GCP'],
        description: 'Target platform (default: Windows)',
      },
    },
    required: ['technique_id', 'description'],
  },
  handler: async (args) => {
    const techniqueId = args.technique_id as string;
    const description = args.description as string;
    const platform = (args.platform as string) || 'Windows';
    const detectionType = (args.detection_type as string) || 'TTP';
    
    // Get patterns for this technique
    const patterns = getPatternsByTechnique(techniqueId, 'splunk_escu');
    const conventions = getStyleConventions();
    
    // Determine data model
    let dataModel = args.data_model as string;
    if (!dataModel) {
      dataModel = patterns.most_common_data_model || 'Endpoint.Processes';
    }
    
    // Get field reference
    const fields = getFieldReference(dataModel);
    const commonFields = fields.length > 0 
      ? fields.slice(0, 10).map(f => f.field_name)
      : getCommonFieldsForDataModel(dataModel);
    
    // Generate detection name
    const detectionName = generateDetectionName(platform, techniqueId, description);
    
    // Generate SPL query based on patterns
    const spl = generateSPLTemplate(dataModel, commonFields, patterns);
    
    // Generate RBA structure
    const rba = generateRBATemplate(platform, detectionType);
    
    // Build the template
    const template = {
      name: detectionName,
      id: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
      version: 1,
      date: new Date().toISOString().split('T')[0],
      author: 'Your Name, Splunk',
      status: 'production',
      type: detectionType,
      description: description,
      data_source: inferDataSources(dataModel),
      search: spl,
      how_to_implement: `Requires data from ${dataModel.split('.')[0]} data model. Ensure proper CIM mapping.`,
      known_false_positives: 'Legitimate administrative activity may trigger this detection. Tune using the filter macro.',
      references: [
        `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`,
      ],
      drilldown_searches: generateDrilldownSearches(detectionName),
      rba: rba,
      tags: {
        analytic_story: ['Your Story Name'],
        asset_type: platform === 'Windows' || platform === 'Linux' || platform === 'macOS' ? 'Endpoint' : 'Cloud Instance',
        mitre_attack_id: [techniqueId],
        product: ['Splunk Enterprise', 'Splunk Enterprise Security', 'Splunk Cloud'],
        security_domain: inferSecurityDomain(dataModel),
        cve: [],
      },
      tests: [{
        name: 'True Positive Test',
        attack_data: [{
          data: 'https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/...',
          sourcetype: inferSourcetype(dataModel),
          source: inferSourcetype(dataModel),
        }],
      }],
    };
    
    // Log this decision for tribal knowledge
    logDecision(
      'detection_generated',
      `Generated detection template for ${techniqueId}`,
      `Used ${dataModel} with ${patterns.count} existing patterns as reference`,
      `Most common data model for ${techniqueId} is ${patterns.most_common_data_model || 'unknown'}. Applied standard ESCU conventions.`,
      [techniqueId, dataModel]
    );
    
    return {
      template: template,
      yaml_preview: generateYAMLPreview(template),
      based_on: {
        similar_detections: patterns.count,
        data_model: dataModel,
        macros_included: ['security_content_summariesonly', 'drop_dm_object_name', 'security_content_ctime', `${detectionName.toLowerCase().replace(/\s+/g, '_')}_filter`],
        fields_available: commonFields,
      },
      notes: [
        'Replace the placeholder ID with a real UUID',
        'Customize the WHERE clause for specific behavior patterns',
        'Adjust RBA scores based on severity and confidence',
        'Add specific false positive tuning based on your environment',
        'Update the test data URL with actual attack simulation data',
      ],
    };
  },
});

const generateRBAStructureTool = defineTool({
  name: 'generate_rba_structure',
  description: 'Generate RBA (Risk-Based Alerting) structure for a detection based on learned patterns and best practices.',
  inputSchema: {
    type: 'object',
    properties: {
      detection_type: {
        type: 'string',
        enum: ['TTP', 'Anomaly', 'Hunting', 'Correlation'],
        description: 'Type of detection',
      },
      severity: {
        type: 'string',
        enum: ['low', 'medium', 'high', 'critical'],
        description: 'Detection severity',
      },
      description: {
        type: 'string',
        description: 'What the detection identifies (for message generation)',
      },
      fields_available: {
        type: 'array',
        items: { type: 'string' },
        description: 'Fields available in the detection (e.g., ["dest", "user", "process_name"])',
      },
    },
    required: ['detection_type', 'severity', 'description'],
  },
  handler: async (args) => {
    const detectionType = args.detection_type as string;
    const severity = args.severity as string;
    const description = args.description as string;
    const fieldsAvailable = (args.fields_available as string[]) || ['dest', 'user', 'process_name'];
    
    // Calculate base score based on type and severity
    const baseScores: Record<string, Record<string, number>> = {
      TTP: { low: 40, medium: 56, high: 72, critical: 90 },
      Anomaly: { low: 16, medium: 32, high: 48, critical: 64 },
      Hunting: { low: 8, medium: 16, high: 24, critical: 32 },
      Correlation: { low: 48, medium: 64, high: 80, critical: 96 },
    };
    
    const score = baseScores[detectionType]?.[severity] || 50;
    
    // Build risk objects based on available fields
    const riskObjects: Array<{ field: string; type: string; score: number }> = [];
    
    if (fieldsAvailable.includes('dest')) {
      riskObjects.push({ field: 'dest', type: 'system', score: Math.round(score * 0.6) });
    }
    if (fieldsAvailable.includes('user')) {
      riskObjects.push({ field: 'user', type: 'user', score: Math.round(score * 0.4) });
    }
    if (riskObjects.length === 0) {
      // Default to dest if no standard fields
      riskObjects.push({ field: 'dest', type: 'system', score: score });
    }
    
    // Build threat objects
    const threatObjects: Array<{ field: string; type: string }> = [];
    const threatFields = ['process_name', 'parent_process_name', 'file_name', 'file_path', 'registry_path'];
    for (const field of threatFields) {
      if (fieldsAvailable.includes(field)) {
        threatObjects.push({ field, type: field });
      }
    }
    
    // Generate message
    const message = generateRBAMessage(description, fieldsAvailable);
    
    return {
      rba: {
        message: message,
        risk_objects: riskObjects,
        threat_objects: threatObjects.length > 0 ? threatObjects : [],
      },
      explanation: {
        base_score: score,
        score_rationale: `${detectionType} detection with ${severity} severity. Score distributed across ${riskObjects.length} risk object(s).`,
        message_variables: fieldsAvailable.filter(f => message.includes(`$${f}$`)),
      },
    };
  },
});

// =============================================================================
// LEARNING TOOLS
// =============================================================================

const extractPatternsTool = defineTool({
  name: 'extract_patterns',
  description: 'Extract and store patterns from all indexed detections. Run this to populate the pattern database for template generation.',
  inputSchema: {
    type: 'object',
    properties: {
      force: {
        type: 'boolean',
        description: 'Force re-extraction even if patterns exist (default: false)',
      },
    },
  },
  handler: async (args) => {
    const force = args.force as boolean;
    
    // Check if patterns already exist
    const stats = getPatternStats();
    if (stats.total_patterns > 0 && !force) {
      return {
        already_extracted: true,
        current_stats: stats,
        message: 'Patterns already extracted. Use force=true to re-extract.',
      };
    }
    
    // Run extraction
    const result = extractAllPatterns();
    
    return {
      success: true,
      extraction_result: result,
      message: `Extracted ${result.total_patterns} patterns from indexed detections`,
    };
  },
});

const learnFromFeedbackTool = defineTool({
  name: 'learn_from_feedback',
  description: 'Store user preference or correction to improve future suggestions. Call this when user modifies generated content to build tribal knowledge.',
  inputSchema: {
    type: 'object',
    properties: {
      feedback_type: {
        type: 'string',
        enum: ['naming', 'query_structure', 'rba_score', 'field_usage', 'style', 'macro_usage'],
        description: 'Type of feedback',
      },
      original: {
        type: 'string',
        description: 'What was originally suggested',
      },
      corrected: {
        type: 'string',
        description: 'What the user changed it to',
      },
      context: {
        type: 'string',
        description: 'Additional context (technique, detection type, etc.)',
      },
    },
    required: ['feedback_type', 'original', 'corrected'],
  },
  handler: async (args) => {
    const feedbackType = args.feedback_type as string;
    const original = args.original as string;
    const corrected = args.corrected as string;
    const context = args.context as string;
    
    // Store as a learning in knowledge graph
    const learningId = addLearning(
      'user_preference',
      `${feedbackType} preference`,
      `User prefers "${corrected}" over "${original}"`,
      context || 'No additional context provided',
      feedbackType
    );
    
    // Also store as style convention for quick lookup
    storeStyleConvention(feedbackType, original, corrected, 'user_preference', 1.0);
    
    // Log the decision
    logDecision(
      'preference_learned',
      `User corrected ${feedbackType}`,
      `Updated from "${original}" to "${corrected}"`,
      context || 'User preference',
      [feedbackType]
    );
    
    return {
      learned: true,
      learning_id: learningId,
      feedback_type: feedbackType,
      message: `Stored preference for ${feedbackType}. Will apply to future suggestions.`,
    };
  },
});

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

function getCommonFieldsForDataModel(dataModel: string): string[] {
  const fieldMaps: Record<string, string[]> = {
    'Endpoint.Processes': [
      'dest', 'user', 'process_name', 'process_path', 'process', 'process_id',
      'process_guid', 'parent_process_name', 'parent_process_path', 'parent_process',
      'parent_process_id', 'parent_process_guid', 'original_file_name', 'process_hash',
      'process_integrity_level', 'action', 'vendor_product',
    ],
    'Endpoint.Filesystem': [
      'dest', 'user', 'file_name', 'file_path', 'file_hash', 'file_size',
      'action', 'process_name', 'process_guid',
    ],
    'Endpoint.Registry': [
      'dest', 'user', 'registry_path', 'registry_key_name', 'registry_value_name',
      'registry_value_data', 'registry_value_type', 'action', 'process_name',
    ],
    'Network_Traffic.All_Traffic': [
      'src', 'src_ip', 'src_port', 'dest', 'dest_ip', 'dest_port',
      'transport', 'protocol', 'bytes_in', 'bytes_out', 'action',
    ],
    'Authentication.Authentication': [
      'dest', 'user', 'src', 'action', 'app', 'authentication_method',
      'signature', 'signature_id',
    ],
  };
  
  return fieldMaps[dataModel] || ['dest', 'user'];
}

function generateDetectionName(platform: string, techniqueId: string, description: string): string {
  // Extract key action words from description
  const words = description.split(' ').filter(w => w.length > 3);
  const action = words.slice(0, 3).map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ');
  
  return `${platform} ${action}`;
}

function generateSPLTemplate(dataModel: string, fields: string[], patterns: TechniquePatterns): string {
  const modelParts = dataModel.split('.');
  const objectName = modelParts[1] || 'Processes';
  
  // Get the most common fields for grouping
  const groupByFields = fields.slice(0, 8).map(f => `${objectName}.${f}`).join(' ');
  
  return `| tstats \`security_content_summariesonly\` count min(_time) as firstTime max(_time) as lastTime 
  from datamodel=${dataModel} 
  where ${objectName}.process_name="*"
  by ${groupByFields}
| \`drop_dm_object_name(${objectName})\` 
| \`security_content_ctime(firstTime)\` 
| \`security_content_ctime(lastTime)\`
| \`DETECTION_NAME_filter\``;
}

function generateRBATemplate(platform: string, detectionType: string): object {
  const baseScore = detectionType === 'TTP' ? 64 : detectionType === 'Anomaly' ? 32 : 16;
  
  return {
    message: `Suspicious activity detected on $dest$ by $user$. Review process $process_name$ for potential malicious behavior.`,
    risk_objects: [
      { field: 'dest', type: 'system', score: Math.round(baseScore * 0.6) },
      { field: 'user', type: 'user', score: Math.round(baseScore * 0.4) },
    ],
    threat_objects: [
      { field: 'process_name', type: 'process_name' },
    ],
  };
}

function inferDataSources(dataModel: string): string[] {
  const dataSourceMaps: Record<string, string[]> = {
    'Endpoint.Processes': ['Sysmon EventID 1', 'Windows Event Log Security 4688'],
    'Endpoint.Filesystem': ['Sysmon EventID 11', 'Sysmon EventID 23'],
    'Endpoint.Registry': ['Sysmon EventID 12', 'Sysmon EventID 13', 'Sysmon EventID 14'],
    'Network_Traffic.All_Traffic': ['Zeek', 'Palo Alto Networks Firewall'],
  };
  
  return dataSourceMaps[dataModel] || ['Windows Event Log'];
}

function inferSecurityDomain(dataModel: string): string {
  if (dataModel.startsWith('Endpoint')) return 'endpoint';
  if (dataModel.startsWith('Network')) return 'network';
  if (dataModel.startsWith('Authentication')) return 'access';
  return 'endpoint';
}

function inferSourcetype(dataModel: string): string {
  if (dataModel.includes('Processes') || dataModel.includes('Filesystem') || dataModel.includes('Registry')) {
    return 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational';
  }
  return 'WinEventLog:Security';
}

function generateDrilldownSearches(detectionName: string): Array<{ name: string; search: string; earliest_offset: string; latest_offset: string }> {
  return [
    {
      name: 'View the detection results for - "$dest$" and "$user$"',
      search: '%original_detection_search% | search dest="$dest$" user="$user$"',
      earliest_offset: '$info_min_time$',
      latest_offset: '$info_max_time$',
    },
    {
      name: 'View risk events for the last 7 days for - "$dest$" and "$user$"',
      search: '| from datamodel Risk.All_Risk | search normalized_risk_object IN ("$dest$", "$user$") starthoursago=168 | stats count min(_time) as firstTime max(_time) as lastTime values(search_name) as "Search Name" values(risk_message) as "Risk Message" values(analyticstories) as "Analytic Stories" values(annotations._all) as "Annotations" values(annotations.mitre_attack.mitre_tactic) as "ATT&CK Tactics" by normalized_risk_object | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`',
      earliest_offset: '$info_min_time$',
      latest_offset: '$info_max_time$',
    },
  ];
}

function generateRBAMessage(description: string, fields: string[]): string {
  const fieldVars = fields.slice(0, 3).map(f => `$${f}$`).join(', ');
  return `${description} detected on ${fields.includes('dest') ? '$dest$' : 'system'}${fields.includes('user') ? ' by user $user$' : ''}. Review ${fieldVars} for investigation.`;
}

function generateYAMLPreview(template: object): string {
  // Simple YAML-like preview (not full YAML serialization)
  return `name: ${(template as any).name}
id: ${(template as any).id}
version: ${(template as any).version}
date: '${(template as any).date}'
author: ${(template as any).author}
status: ${(template as any).status}
type: ${(template as any).type}
description: ${(template as any).description}
search: |
${(template as any).search.split('\n').map((l: string) => '  ' + l).join('\n')}
# ... (truncated for preview)`;
}

// =============================================================================
// EXPORTS
// =============================================================================

export const engineeringTools = [
  getQueryPatternsTool,
  getFieldReferenceTool,
  getMacroReferenceTool,
  findSimilarDetectionsTool,
  suggestDetectionTemplateTool,
  generateRBAStructureTool,
  extractPatternsTool,
  learnFromFeedbackTool,
];

export const engineeringToolCount = engineeringTools.length;
